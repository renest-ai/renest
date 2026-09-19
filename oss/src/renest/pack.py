"""Nest packing + upload.

Four phases: P1 walks the target and stream-hashes every asset; P2 places blobs
into the content-addressed tree and assembles the manifest; P3 hands the tree to
an uploader (injected, default none); P4 reconciles sizes against what landed --
all-match or loudly fail, never a false success. ``dry_run`` stops after P2 and
returns the inventory preview without placing or uploading anything.

Boundaries that must not be relaxed: an unknown licence defaults to gated; wheel
pinning (``--pin-wheels``) is opt-in because it needs network and pack's default
is zero-network, and a failed pin is a hard failure (skipping it ships a nest
that passes sha256 and can never be installed); compiled ``.so`` files are
stripped only when the node has a build path, since a vendored one that cannot
be rebuilt verifies green and then crashes on startup.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import errno
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

import httpx

from .capture import _parse_extra_model_paths, capture
from .envlock import (
    COMPILE_REQUIRED_VERDICT,
    LOCK_FROM_ENV_HEADER,
    LOCK_FROM_INSTALLED_HEADER,
    compile_required_evidence,
    conda_owned_evidence,
    env_dir_of,
    env_python_matches_run_record,
    find_env_python,
    find_launchers,
    find_site_packages,
    dists_built_from_a_directory,
    lock_lines_for,
    unreinstallable_manager_parts,
    split_out_package_manager,
    image_build_evidence,
    is_conda_build_url,
    distro_owned_packages,
    vendor_only_locals,
    freeze_environment,
    is_system_interpreter,
    freeze_from_installed,
    interpreter_kernel,
    interpreter_python_series,
    launcher_interpreter_dir,
    local_path_evidence,
    local_version_sources,
    venv_python_candidates,
)
from .errors import NestFailure, ErrorClass, ExitCode
from .events import EventEmitter
from .doctor import LEVEL_PASS, check_lock_cuda_family
from .fingerprint import CRITICAL_PACKAGES, collect, collect_gpu, collect_wheel_env
from .syslibs import (
    collect_native_libs_with_layers,
    contested_winners,
    interpreter_site_packages,
    node_declared_machine_libs,
    read_run_record,
    record_search_roots,
)
from .vram_watch import observed_use_from_record
from .integrity import (
    cache_stated_sha256,
    declared_base_model,
    dirty_gap,
    looks_like_lfs_pointer,
    probe_model_bytes,
    serialization_of,
    upstream_match,
)
from .licensing import (
    licence_text_path,
    lookup as _licence_lookup,
    lookup_code_dep as _lookup_code_dep,
    stricter_of,
)
from .roots import (
    ENV_ROOT_TOKEN,
    bad_root_entry as _bad_root_entry,
    resolve_file_root,
    tokenise_env_root,
    unsafe_relpath,
)
from .wheels import (
    WheelPinError,
    add_hashes,
    audit_lock_urls,
    lock_hosts,
    pin_lock_text,
    python_tag_of,
    wheel_os_family,
    wheel_platform_tags,
)

__all__ = [
    "CROCKFORD",
    "FAT_ARCHIVE",
    "HOSTED_MEMORY_REL",
    "LOCK_CANDIDATES",
    "PackError",
    "PackReport",
    "hosted_memory_read",
    "hosted_memory_write",
    "ulid",
    "infer_spec",
    "infer_spec_current_state",
    "pack",
    "run_from_args",
]

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
FAT_ARCHIVE = 512 << 20  # a code archive above this = suspicious (models packed into the tar?)

#: python lock filenames capture looks for in the env root (target-only inference).
#: A lock is a real artifact of the env (not workflow-referenced, so not "guessing")
#: — first hit wins; none found → python_lock omitted (honest, human fills it in).
LOCK_CANDIDATES = ("requirements.lock", "uv.lock", "requirements.txt")



#: Does this dependency list contain renest itself? Matches the shapes ``uv pip
#: freeze`` actually emits — ``renest==0.1.0``, ``renest @ file:///…`` for an
#: editable install, and the ``-e``/``#egg=`` spellings — while leaving names that
#: merely start with the same letters (``renest-something``) alone.
_RENEST_IN_LOCK = re.compile(
    r"(?im)^\s*(?:-e\s+)?renest(?:\[[^\]]*\])?\s*(?:==|@|>=|<=|~=|===|\s*$)"
    r"|^\s*-e\s+\S*#egg=renest\s*$"
)


def lock_carries_renest(lock_text: str) -> str | None:
    """The line naming renest itself, or ``None``. Used for a notice, never to drop it.

    **Why we do not remove it.** The promise is that a rebuild gives you back the
    environment you had; quietly deleting ourselves from the list would make the
    rebuild unfaithful, and if anything in there imports renest, the restored
    environment would be broken. So it is captured like everything else.

    What the notice is for: `pip install renest` installs into whatever environment
    is active, and that is often the very environment being packed — resolving our
    dependencies there can move versions that were already working. By the time we
    see the lock the damage, if any, is already done, so all we can do is say it.
    """
    match = _RENEST_IN_LOCK.search(lock_text or "")
    return match.group(0).strip() if match else None


def _own_package_dir() -> Path:
    """The directory this running copy of renest is loaded from.

    A hard fact of this process — the import system already resolved it — never
    a guess from ``PATH``, an executable name, or what a symlink points at.
    """
    return Path(__file__).resolve().parent


def self_installed_in_env(env_root: Path | None) -> Path | None:
    """Where this running copy of renest lives, **when that place is inside
    ``env_root``** (the environment being packed); ``None`` otherwise.

    Why it matters: ``uv pip install renest`` in a shell with that environment
    active lands us right there, and uv resolves our dependencies against the
    virtualenv layer alone — it does not count a ``--system-site-packages``
    layer as satisfied. Measured 2026-09-06 on a real ComfyUI environment: all
    seven libraries the app was importing got displaced by newer versions, and
    the dependency list read afterwards records the displaced versions — a list
    describing an environment the workflow never actually ran on.

    Judged on install paths, deliberately: the tool run as ``uv tool install``
    or from anywhere outside the environment compares unrelated and stays
    silent. The complementary guard in :mod:`renest.envlock`
    (``drop_ourselves``) keeps our own line out of the list; this one exists
    because that line is not the damage — the displaced versions are, and only
    a word at pack time can still reach the user about them.
    """
    if env_root is None:
        return None
    own = _own_package_dir()
    try:
        target = Path(env_root).resolve()
    except OSError:
        return None
    return own if own.is_relative_to(target) else None


#: uploader: (blobs_dir, manifest) -> dict of verify info {sha256: size}
Uploader = Callable[[Path, dict], dict]


class PackError(Exception):
    """A pack problem carrying an exit code (pre-gate config/usage). Distinct
    from the byte-level P-stage failures which raise :class:`NestFailure`.

    ``failure`` optionally carries a contract-1.3 error object (the shape
    :meth:`NestFailure.to_error_object` produces) for the machine-readable
    report. Without it, ``--json`` ends on ``ok:false`` with ``failure: null``
    and an automated caller learns nothing about what happened — exactly how
    the still-verifying timeout got buried on 2026-09-06."""

    def __init__(
        self,
        human: str,
        *,
        exit_code: int = int(ExitCode.USAGE),
        failure: dict | None = None,
    ) -> None:
        self.human = human
        self.exit_code = exit_code
        self.failure = failure
        super().__init__(human)


def ulid() -> str:
    """48-bit ms timestamp + 80-bit random, Crockford base32, 26 chars."""
    ms = int(datetime.datetime.now(datetime.UTC).timestamp() * 1000)
    val = (ms << 80) | secrets.randbits(80)  # 128 bit
    out = []
    for _ in range(26):
        out.append(CROCKFORD[val & 0x1F])
        val >>= 5
    return "".join(reversed(out))


#: Where the "already read this file, here is its fingerprint" record sits,
#: relative to the target folder (same state area as the nest memory below).
HASH_CACHE_REL = ".renest/state/hash-cache.json"

#: Names that never travel inside a user's code archive. **One list, read by both
#: the archiver and the `.so` scan** -- they used to be two hand-written copies that
#: said they mirrored each other, and a test could pass against one while the other
#: still let the file through (found 2026-08-23, by a falsification that refused to
#: go red).
ARCHIVE_JUNK = (".git", "__pycache__", ".venv", "venv", "node_modules", ".renest")
_HASH_CACHE_FORMAT = 1


class HashCache:
    """Lets a repeat pack of the same folder skip re-reading files that did not
    change, so a 100 GB folder does not cost a full disk read every time.

    An entry is believed only while size, modification time and inode all still
    match; any one of them moving means the file is read again. That is a
    heuristic — a rewrite that puts all three back exactly as they were would
    slip through, which is what ``--full-rehash`` is for. It is an optimisation
    and nothing else: an unreadable, stale or wrong-shaped record costs a
    re-read, never a wrong fingerprint. sha256 stays sha256; what is saved is
    reading bytes that nobody touched.
    """

    def __init__(self, path: Path | None = None, *, trust: bool = True) -> None:
        self.path = Path(path) if path is not None else None
        self.trust = trust
        self.hits = 0
        self.misses = 0
        self._entries: dict[str, list] = {}
        self._lock = threading.Lock()
        if self.path is not None:
            self._load()

    def attach(self, path: Path) -> None:
        """Point an in-memory record at its file and take in what is already
        recorded there; entries read this session win. Lets the caller hold one
        record across capture and pack **before** knowing where it lives — a dry
        run writes nothing, so a shared file cannot carry hashes between the two
        and every weight got read twice (measured 2026-08-30: 2.00x)."""
        if self.path is not None:
            return
        self.path = Path(path)
        mine = dict(self._entries)
        self._entries = {}
        self._load()
        self._entries.update(mine)

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return
        if not isinstance(data, dict) or data.get("cache_format") != _HASH_CACHE_FORMAT:
            return
        entries = data.get("entries")
        if not isinstance(entries, dict):
            return
        for key, val in entries.items():
            if (
                isinstance(key, str)
                and isinstance(val, list)
                and len(val) == 4
                and all(isinstance(v, int) and not isinstance(v, bool) for v in val[:3])
                and isinstance(val[3], str)
                and len(val[3]) == 64
            ):
                self._entries[key] = list(val)

    @staticmethod
    def _key(path: str | os.PathLike[str]) -> str:
        # One file, one entry, whichever spelling reached us. Capture keys a model by
        # the path written in the folder; pack dereferences a symlink before hashing
        # (a HuggingFace cache is all symlinks). Two spellings of one file meant two
        # entries, and the first pack read a symlinked weight twice.
        return os.path.realpath(os.fspath(path))

    def lookup(self, path: str | os.PathLike[str], st: os.stat_result) -> str | None:
        """The recorded sha256 for ``path``, or None when it has to be read."""
        if not self.trust:
            return None
        key = self._key(path)
        with self._lock:
            ent = self._entries.get(key)
            if ent is not None and tuple(ent[:3]) == (st.st_size, st.st_mtime_ns, st.st_ino):
                self.hits += 1
                return ent[3]
            self.misses += 1
        return None

    def remember(self, path: str | os.PathLike[str], st: os.stat_result, sha256: str) -> None:
        with self._lock:
            self._entries[self._key(path)] = [st.st_size, st.st_mtime_ns, st.st_ino, sha256]

    def save(self) -> None:
        """Atomic write; failing to write is never an error. Entries whose file
        is gone drop out here, so the record cannot grow without bound."""
        if self.path is None:
            return
        with self._lock:
            keep = {k: v for k, v in self._entries.items() if os.path.exists(k)}
        payload = {"cache_format": _HASH_CACHE_FORMAT, "entries": keep}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            return


def _sha256_stream(path: Path, cache: HashCache | None = None) -> tuple[str, int]:
    # If the source is written while we read it (ComfyUI or a downloader still
    # running), the fingerprint is void and the restore side would only ever see
    # "corrupt download" — fail loudly here rather than ship a poisoned nest.
    # Covers the read window. The window between hashing and upload -- the blob is
    # hard-linked, so whatever writes the original writes the blob -- is closed on the
    # upload side (see hosted.py, one stat before each send).
    before = path.stat()
    if cache is not None:
        # Unchanged size, time and inode since the last pack of this folder also
        # means nothing is writing to it now, so the guard above loses nothing.
        known = cache.lookup(path, before)
        if known is not None:
            return known, before.st_size
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise PackError(
            f"This file changed while we were reading it to pack: {path} "
            f"(size {before.st_size} → {after.st_size} bytes). "
            "Something is still writing to it — most likely ComfyUI itself, or a "
            "download that hasn't finished. Stop it, then pack again. Pack it now "
            "and the byte check will fail on restore, looking like a broken transfer.",
            exit_code=int(ExitCode.S2_HASH_MISMATCH),
        )
    digest = h.hexdigest()
    if cache is not None:
        cache.remember(path, after, digest)
    return digest, after.st_size


def _copy(src: Path, dest: Path) -> None:
    """Content-addressed placement. **The temp name must be unique per call**:
    packing is multi-threaded, and content addressing means two files at
    different paths may well hash to the same value. Sharing one `<hash>.part`
    lets two threads stomp on each other — one `os.replace` wins, the other's
    part file is already gone → `FileNotFoundError`, pointing nowhere near the
    real cause."""
    tmp = dest.with_suffix(dest.suffix + f".{os.getpid()}.{threading.get_ident()}.part")
    try:
        with src.open("rb") as r, tmp.open("wb") as w:
            for chunk in iter(lambda: r.read(1 << 22), b""):
                w.write(chunk)
        os.replace(tmp, dest)
    finally:
        # Leave no litter even when we fail midway (a pile of stale .part files
        # makes the next run's tree unreadable).
        with contextlib.suppress(OSError):
            tmp.unlink()


def _place_blob(
    src: Path, out_blobs: Path, hardlink: bool = True, cache: HashCache | None = None,
    on_copy_fallback: Callable[[Path, OSError], None] | None = None,
) -> dict:
    """Place ``src`` content-addressed into ``out_blobs/<first 2 chars>/<hash>``.

    The same hash being placed twice concurrently is **normal** (under content
    addressing, different paths may hold identical content), so every step here
    must tolerate "someone already placed it": EEXIST from `os.link` is not an
    error."""
    # **Dereference first, then place**: inside an HF cache everything under
    # snapshots/ is a **relative** symlink into blobs/. os.link would store the
    # link itself, whose relative target no longer resolves once it lands in
    # blobs/sha256/xx/ — so the blob never lands while the hash is already
    # correct, giving a manifest that looks complete with the bytes missing.
    real = src.resolve() if src.is_symlink() else src
    h, size = _sha256_stream(real, cache)
    dest = out_blobs / h[:2] / h
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        if hardlink:
            try:
                os.link(real, dest)
            except FileExistsError:
                pass                      # another thread just placed it — exactly what we want
            except OSError as e:
                # Cross-device, or a quota that refuses hard links: fall back to a
                # real copy. **Say so** -- copying is the one path that needs a
                # second full-size disk, and it used to be silent: a 20 GB volume
                # ran out mid-pack packing 6.9 GB of models and the error named
                # the disk, not the reason (measured 2026-07-13).
                if on_copy_fallback is not None:
                    on_copy_fallback(real, e)
                _copy(real, dest)
        else:
            _copy(real, dest)
    # Prove the placement right here: whether the bytes landed must be answered
    # now, not discovered at P4 as "a few are missing".
    if not dest.is_file() or dest.stat().st_size != size:
        raise PackError(
            f"Could not put {src} into the nest: expected {size} bytes at {dest}, "
            f"found {'nothing' if not dest.exists() else str(dest.stat().st_size) + ' bytes'}.",
            exit_code=int(ExitCode.USAGE),
        )
    return {"sha256": h, "size_bytes": size}


def hardlinks_refused(src_dir: Path, dest_dir: Path) -> OSError | None:
    """Ask the disk **before** P1 whether it will hard-link into the nest.

    Returns the refusal (an ``OSError``) when it will not, ``None`` when links
    work. Comparing device numbers is a different, weaker question: the pack
    that ran a 20 GB volume dry on 2026-07-13 was writing to the very
    filesystem it was reading from, and the links were refused by a **quota**.
    So this tries one real link and believes the answer.

    A read-only source folder cannot hold a probe file; that is not a refusal,
    so the device numbers decide (different disks can never be linked across).
    """
    try:
        fd, probe_name = tempfile.mkstemp(dir=src_dir, prefix=".renest-link-probe-")
    except OSError:
        try:
            same = os.stat(src_dir).st_dev == os.stat(dest_dir).st_dev
        except OSError:
            return None
        if same:
            return None
        return OSError(errno.EXDEV, "the output folder is on a different disk")
    os.close(fd)
    probe = Path(probe_name)
    link = Path(dest_dir) / (probe.name + ".link")
    try:
        os.link(probe, link)
    except OSError as e:
        return e
    finally:
        with contextlib.suppress(OSError):
            link.unlink()
        with contextlib.suppress(OSError):
            probe.unlink()
    return None


def _declared_file_bytes(root: Path, spec: dict) -> int:
    """Lower bound on what a copying pack has to write a second time.

    Only the files the spec names: they are the bulk (model weights), and every
    byte counted here is one we can point at on disk. Under-counting only costs
    a warning that could have been a refusal; over-counting would refuse a pack
    that would have fitted, so this leans low on purpose.
    """
    total = 0
    seen: set[tuple[int, int]] = set()
    for f in spec.get("files") or []:
        if not isinstance(f, dict) or not f.get("path"):
            continue
        try:
            if f.get("source_path"):
                src = _spec_source(root, f, f["path"])
            elif (f.get("root") or "env") == "env":
                src = root / f["path"]
            else:
                src = resolve_file_root(f["root"], root) / f["path"]
            st = src.stat()
        except (OSError, ValueError):
            continue
        key = (st.st_dev, st.st_ino)
        if key in seen:
            continue
        seen.add(key)
        total += st.st_size
    return total


def _gb(n: int) -> str:
    """Sizes a person can act on: a "0.0 GB" reading tells them nothing."""
    return f"{n / 2**30:.1f} GB" if n >= 2**30 else f"{n / 2**20:.0f} MB"


def second_copy_notice(
    root: Path, out_blobs: Path, spec: dict, no_hardlink: bool
) -> tuple[str, bool] | None:
    """What to tell the user *before* any bytes move, when this pack will need
    a second full-size copy of everything on disk.

    Returns ``(message, fits)`` — ``fits`` is False when the copy provably does
    not fit in the space left where the nest is being written. ``None`` means
    hard links work and the nest costs no extra room.

    Placing a file into the nest normally hard-links it, which costs nothing.
    When linking is refused (a different disk, or a quota) every file is copied
    instead, so packing a 64 GB run needs 128 GB free. That used to be said
    only *after* P1 had finished copying — i.e. after the disk it warned about
    had already filled up.
    """
    refusal = None if no_hardlink else hardlinks_refused(root, out_blobs)
    if not no_hardlink and refusal is None:
        return None
    why = (
        "--no-hardlink was asked for"
        if no_hardlink
        else f"this disk would not let us hard-link files into the nest ({refusal.strerror or refusal})"
    )
    needed = _declared_file_bytes(root, spec)
    try:
        free = shutil.disk_usage(out_blobs).free
    except OSError:
        free = -1
    fits = free < 0 or needed <= free
    if no_hardlink and fits:
        # Asking for copies and getting copies is not news. Saying it every time
        # trains people to skip the line that matters (test_pack.py:
        # ``test_no_hardlink_on_purpose_says_nothing_about_copying``). What is
        # still news — it will not fit — falls through below.
        return None
    room = (
        f"This pack needs about {_gb(needed)} of it, and {_gb(free)} is free there."
        if free >= 0
        else f"This pack needs about {_gb(needed)} of it."
    )
    return (
        f"Every file will be copied into the nest, because {why}. That means a "
        f"second full-size copy of everything sits on disk before any of it is "
        f"sent — plan for twice the space. {room} Put the output folder (--out) "
        f"on the same disk as the files being packed to keep the copy, and the "
        f"wait, out of it.",
        fits,
    )


def _spec_source(root: Path, entry: dict, fallback: str) -> Path:
    """Where packing reads this entry from (pack-spec 1.3 ``source_path``).

    ``install_path``/``path`` say where a **rebuild** writes; ``source_path`` says
    where the bytes are **right now**. The two differ when an application keeps
    its program in one tree and its nodes, models and workflows in another (the
    ComfyUI desktop build does). Relative is taken from the environment root,
    absolute as given. Absent = the old behaviour, ``root / fallback``.
    """
    sp = str(entry.get("source_path") or "").strip()
    if not sp:
        return root / fallback
    p = Path(sp).expanduser()
    return p if p.is_absolute() else root / p


def _run_record_roots(root: Path, spec: dict, program_dir: Path | None = None) -> list[Path]:
    """Every tree the extension may have left its run record in, in search order.

    It writes beside ComfyUI's own source, because that is where ``folder_paths``
    lives. On an installation that keeps the program in a separate tree from the
    nodes and models (the ComfyUI desktop build), that is **not** under the folder
    a pack is rooted at, so looking only there finds nothing and the nest quietly
    carries the guessed-at library list instead of the measured one.

    The program tree comes from ``--program-dir`` or, for a spec that already
    names it, the host entry's ``source_path`` -- both routes, one answer.
    """
    extra: list[Path] = []
    if program_dir is not None:
        extra.append(Path(program_dir))
    for dep in spec.get("code_deps") or []:
        if isinstance(dep, dict) and dep.get("role") == "host" and dep.get("source_path"):
            extra.append(_spec_source(root, dep, dep.get("install_path", "")))
    # Program tree first when there is one: on a two-tree install the data tree
    # holds no record at all, and anything it does hold is left over from an
    # earlier single-tree layout.
    return record_search_roots(root, [*extra, _locate_comfyui_dir(root, None)])


def _tar_code_dep(root: Path, install_path: str, work: Path, extra_excludes=(), raw_excludes=(),
                  source_dir: Path | None = None) -> Path:
    """Tar the code dep into a ``--strip-components=1``-compatible tar.gz
    (single top-level component = the source directory's basename; the rebuild
    strips it and lands the contents at ``install_path``, so the two names are
    free to differ when ``source_path`` points at another tree).

    Generic junk is excluded by name; scene-specific excludes come from the
    spec's ``code_deps[].exclude`` so the tool stays scene-neutral. Spec excludes
    must stay anchored to the archive root: a bare ``--exclude=models`` also
    strips source dirs like ``comfy/ldm/models/``, producing a nest that passes
    sha256 and crashes on startup.

    ``raw_excludes`` go to ``tar`` unanchored — the auto-detected
    ``*.so``/``build`` patterns are compiler artifacts that sit at any depth, and
    GNU tar matches unanchored patterns by basename at any depth."""
    src_dir = source_dir if source_dir is not None else root / Path(install_path)
    if not src_dir.is_dir():
        raise PackError(f"Can't find the code folder to pack: {src_dir}", exit_code=int(ExitCode.USAGE))
    if src_dir.is_symlink():
        # Symlink trap: when the whole directory is a symlink, tar stores **the
        # link itself**, not the tree it points at — the archive shrinks to a
        # few hundred bytes, sha256 verifies green, and the recipient unpacks
        # nothing. We **hard-refuse** rather than warn: a symlink preserves a
        # path guaranteed not to exist on someone else's machine, and shipping a
        # nest doomed to break is worse than not shipping one.
        raise PackError(
            f"{install_path} is a symlink, so packing it would store the link and not the "
            f"files it points at — the nest would verify fine and rebuild to nothing.\n"
            f"  It points at: {os.readlink(src_dir)}\n"
            f"  Replace the link with the real folder (or copy the files in) and pack again.",
            exit_code=int(ExitCode.USAGE),
        )
    _refuse_undownloaded_code(src_dir, install_path, extra_excludes)
    parent = src_dir.parent
    base = src_dir.name
    out_tar = work / f"{base}.tar.gz"
    # `.renest` is **our own** state area inside the user's environment (hash cache,
    # restore state, evidence, the extension's run record). It never travels: it holds
    # this machine's absolute paths -- a home directory carries the user's name -- and
    # it is one machine's measurement, so a nest packed after restoring it elsewhere
    # would carry the first machine's reading as its own.
    # End-to-end guard: tests/consistency/test_nest_carries_no_machine_paths.py
    junk = [*ARCHIVE_JUNK, "*.pyc"]
    anchored = [f"{base}/{e.strip('/')}" for e in extra_excludes]
    excludes = junk + anchored + list(raw_excludes)
    subprocess.run(  # noqa: S603
        ["tar", *[f"--exclude={e}" for e in excludes], "-czf", str(out_tar), "-C", str(parent), base],
        check=True,
        # COPYFILE_DISABLE stops macOS tar writing an `._name` sidecar next to every file
        # carrying an extended attribute. Those sidecars are not on disk -- tar invents
        # them -- and on a Linux pod they unpack as real files. A `._node.py` beside a
        # node's `node.py` is binary junk that anything scanning the folder may try to
        # read; this project already lost a deploy to exactly that (alembic read a
        # `._auth.py` and died on "source code string cannot contain null bytes").
        # Measured 2026-08-14: packing the same fixture with and without it, the archive
        # goes from 6 members to 3. Ignored by GNU tar on Linux, so it is safe everywhere.
        env={**os.environ, "COPYFILE_DISABLE": "1"},
    )
    _zero_gzip_mtime(out_tar)
    return out_tar


def _zero_gzip_mtime(path: Path) -> None:
    """Zero the gzip header's timestamp (RFC 1952 bytes 4-7) so packing the same
    tree twice produces the same bytes. Found 2026-08-13 repacking a real nest
    with two unrelated manifest fields changed: the whole 11.2 MB code archive
    still got re-sent, because `tar -z` stamps wall-clock time into the gzip
    header even when every file inside is byte-identical — that alone defeats
    content-addressed dedup on every repack. Does not touch file order, so a
    from-scratch clone on a different filesystem can still differ."""
    with path.open("r+b") as f:
        head = f.read(4)
        if head == b"\x1f\x8b\x08\x00" or head[:3] == b"\x1f\x8b\x08":
            f.seek(4)
            f.write(b"\x00\x00\x00\x00")


#: dirs never scanned for `.so` / never treated as a node's own build signal
#: (mirrors _tar_code_dep's junk list — a vendored dep's own .venv shouldn't
#: count as "this node has a build path").
_JUNK_DIRS = frozenset(ARCHIVE_JUNK)


def _packed_entries(src_dir: Path, exclude=()):
    """Every path of a code dep that survives the archive's filters — files,
    folders and symlinks alike (junk dirs and the spec's own excludes come off
    first)."""
    ex_prefixes = [e.strip("/") for e in exclude]
    for p in src_dir.rglob("*"):
        parts = p.relative_to(src_dir).parts
        if _JUNK_DIRS & set(parts) or any(part.endswith(".pyc") for part in parts):
            continue
        rel = "/".join(parts)
        if any(rel == e or rel.startswith(e + "/") for e in ex_prefixes):
            continue
        yield rel, p


def _packed_files(src_dir: Path, exclude=()):
    """Iterate the files of a code dep that really end up in its archive."""
    for rel, p in _packed_entries(src_dir, exclude):
        if p.is_file():
            yield rel, p


def _symlinks_leaving_the_archive(src_dir: Path, exclude=()) -> list[tuple[str, str]]:
    """Symlinks inside a code dep that point out of it, as (path, where it points).

    tar stores such a link, never the bytes behind it, so the archive verifies by
    sha256 and the restored tree holds a link to a path nobody else has."""
    base = src_dir.resolve()
    out: list[tuple[str, str]] = []
    for rel, p in _packed_entries(src_dir, exclude):
        if not p.is_symlink():
            continue
        with contextlib.suppress(OSError):
            if not p.resolve().is_relative_to(base):
                out.append((rel, os.readlink(p)))
    return sorted(out)


def _lfs_pointer_files(src_dir: Path, exclude=()) -> list[str]:
    """Files that are Git LFS pointer text instead of the real content — a clone
    where `git lfs pull` never ran holds a few hundred bytes of text per file."""
    return sorted(rel for rel, p in _packed_files(src_dir, exclude) if looks_like_lfs_pointer(p))


def _empty_submodule_dirs(src_dir: Path) -> list[str]:
    """Submodule folders this repo declares that hold nothing: `git clone` without
    `--recursive` leaves the folder there and empty.

    Only empty folders count, never missing ones — a submodule someone deleted can
    leave a stale entry behind, and refusing on that would block a pack that nobody
    could then fix.
    """
    try:
        text = (src_dir / ".gitmodules").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out = []
    for m in re.finditer(r"(?m)^[ \t]*path[ \t]*=[ \t]*(\S.*?)[ \t]*$", text):
        rel = m.group(1)
        with contextlib.suppress(OSError):
            d = src_dir / rel
            if d.is_dir() and not any(d.iterdir()):
                out.append(rel)
    return sorted(out)


def _refuse_undownloaded_code(src_dir: Path, install_path: str, exclude=()) -> None:
    """Refuse to pack code whose bytes were never downloaded onto this machine.

    Same trap as the symlinked directory above, one level down: tar happily
    archives LFS pointer text and empty submodule folders, sha256 matches on
    restore, and the rebuilt environment is missing the code. **Hard-refuse
    rather than warn** — a nest that passes every check and crashes on startup
    is worse than no nest.

    The judgment itself is invariant I-2 and lives in :mod:`renest.invariants`
    (2026-09-06): one source, so no second consumer can drift from what counts
    as "never downloaded". This raise, its message and its exit code are
    unchanged — the invariant sweep did not make pack stricter or looser here.
    """
    from .invariants import ArchiveDir, i2_code_bytes_never_downloaded

    for v in i2_code_bytes_never_downloaded(
        {}, "", [ArchiveDir(install_path, src_dir, tuple(exclude))]
    ):
        raise PackError(v.message, exit_code=int(ExitCode.USAGE))


def _dir_size_as_packed(src_dir: Path, exclude=()) -> int:
    """How big is the part of this directory that **actually gets packed** — the
    number shown in the dry run must match what really comes out.

    Both the name-excluded things (``.venv`` / ``.git`` / ``__pycache__``) and
    the spec's own excludes must come off. Summing the whole tree instead counts
    a multi-GiB virtual environment the nest will never contain, and this is the
    number the user reads to decide whether to store it at all.
    """
    if not src_dir.is_dir():
        return 0
    total = 0
    for _rel, p in _packed_files(src_dir, exclude):
        with contextlib.suppress(OSError):
            total += p.stat().st_size
    return total


def _declared_assets_inside(spec: dict, install_path: str, already=()) -> list[str]:
    """Assets named in ``files[]`` that physically sit inside this code directory.

    Returned relative to the archive root, so a caller can anchor them like any
    other exclude. Each of these already travels as its own blob, so a copy in
    the archive is the same bytes packed a second time — a real run doubled the
    nest that way. Worse for a restricted file: it must not travel, yet the
    archive would carry it anyway. Entries the spec already excludes are left
    out, so a spec that got this right stays silent.
    """
    ip = str(install_path).strip("/")
    if not ip:
        return []
    covered = [str(e).strip("/") for e in already]
    out: set[str] = set()
    for f in spec.get("files") or []:
        # Files rooted in a model cache live outside the environment root, so
        # they can never be inside a code directory.
        if not isinstance(f, dict) or (f.get("root") or "env") != "env":
            continue
        rel = str(f.get("path") or "").strip("/")
        if not rel or not rel.startswith(ip + "/"):
            continue
        inner = rel[len(ip) + 1:]
        if any(inner == c or inner.startswith(c + "/") for c in covered):
            continue
        out.add(inner)
    return sorted(out)


def _find_so_files(src_dir: Path, exclude=()) -> list[Path]:
    """`.so` files anywhere under ``src_dir``, excluding junk dirs and any
    subtree already covered by ``exclude`` — a nested dir that is its own
    ``code_dep`` is tarred separately, so scanning it here too would
    double-count and double-warn the same bytes under two dep names."""
    ex_prefixes = [e.strip("/") for e in exclude]

    def _excluded(relpath: str) -> bool:
        return any(relpath == e or relpath.startswith(e + "/") for e in ex_prefixes)

    out = []
    for p in src_dir.rglob("*.so"):
        if not p.is_file():
            continue
        parts = p.relative_to(src_dir).parts
        if _JUNK_DIRS & set(parts):
            continue
        if _excluded("/".join(parts)):
            continue
        out.append(p)
    return out


def _has_build_path(src_dir: Path) -> bool:
    """Does this node have a source build path: ``setup.py``, or a
    ``pyproject.toml`` declaring ``[build-system]``, or ``requirements.txt`` —
    any one of them means "reinstallable/recompilable", so its ``.so`` files can
    safely be stripped from the archive. If ``pyproject.toml`` fails to parse we
    conservatively answer "no" (better to keep bytes we did not need than to
    delete bytes that cannot be rebuilt)."""
    if (src_dir / "setup.py").is_file():
        return True
    if (src_dir / "requirements.txt").is_file():
        return True
    pyproject = src_dir / "pyproject.toml"
    if pyproject.is_file():
        import tomllib

        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError):
            return False
        if "build-system" in data:
            return True
    return False


#: Where a CUDA install puts the binary reader when it is not on PATH. The machine
#: this was measured on (2026-07-26) had it only here, and looking on PATH alone
#: would have recorded nothing at all for an environment full of CUDA extensions.
_CUOBJDUMP_FALLBACK = "/usr/local/cuda/bin/cuobjdump"


def _cuobjdump() -> str | None:
    """The CUDA binary reader, or ``None`` when this machine has none."""
    found = shutil.which("cuobjdump")
    if found:
        return found
    return _CUOBJDUMP_FALLBACK if Path(_CUOBJDUMP_FALLBACK).is_file() else None


def _probe_so_arch(so_path: Path) -> list[str] | None:
    """Best effort at detecting which GPU architectures a kept vendored ``.so``
    was compiled for (``cuobjdump --list-elf``, parsing ``sm_NN``). No
    ``cuobjdump`` / not a CUDA binary / nothing parseable → honestly return
    ``None`` (skip, never invent — the same discipline manifest.gpu follows)."""
    tool = _cuobjdump()
    if tool is None:
        return None
    try:
        result = subprocess.run(  # noqa: S603
            [tool, "--list-elf", str(so_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    archs = sorted({f"sm_{m}" for m in re.findall(r"sm_(\d+)", result.stdout)})
    return archs or None


#: Ceilings on reading installed binaries. One environment can hold hundreds of
#: them and each is opened on its own, so without a ceiling this one step could
#: outlast the packing of the bytes themselves. Order decides what fits: the
#: packages a rebuild is known to fail on go first, the rest alphabetically.
_ARCH_SCAN_MAX_FILES = 200
_ARCH_SCAN_BUDGET_S = 180.0


def _package_so_files(site: Path) -> list[Path]:
    """Compiled binaries installed under ``site``, most decisive first.

    Fixed order, so two packs of one environment record the same thing. A file
    sitting straight in ``site`` with no package folder above it is left out --
    there is no owner name to put beside it, and inventing one is worse than
    recording nothing.
    """
    seen: dict[Path, None] = {}
    for pattern in ("*.so", "*.so.*"):
        for p in site.rglob(pattern):
            rel = p.relative_to(site)
            if len(rel.parts) < 2 or _JUNK_DIRS & set(rel.parts) or not p.is_file():
                continue
            seen.setdefault(p, None)
    critical = set(CRITICAL_PACKAGES)
    return sorted(
        seen,
        key=lambda p: (
            0 if p.relative_to(site).parts[0] in critical else 1,
            p.relative_to(site).as_posix(),
        ),
    )[:_ARCH_SCAN_MAX_FILES]


def _target_site_packages(python_path: str | None) -> Path | None:
    """Where the environment being packed keeps its installed packages.

    Asked of that interpreter itself, never assumed from the folder layout: a pack
    can be pointed at another environment's Python with ``--env-python``. With no
    interpreter named, the one running pack **is** the environment's -- the same
    fallback the rest of the fingerprint takes. ``None`` when neither can answer.
    """
    if python_path:
        return interpreter_site_packages(python_path)
    import sysconfig

    here = sysconfig.get_paths().get("purelib")
    return Path(here) if here else None


def _collect_package_native_archs(site: Path) -> list[dict]:
    """Which card generations each installed compiled package was built for.

    Reading PyTorch's own list alone is wrong in both directions (measured
    2026-07-26 on an RTX 3060): one attention library's main binary covered
    sm_60/70/75/80/90 and omitted sm_86 -- the packing machine's own card --
    while a quantisation library shipped binaries covering more than PyTorch
    did. Recorded per binary, because binaries inside one package differ.

    Yielding nothing is the normal outcome, not an error: 18 of 29 binaries in
    that measurement gave nothing (pure-CPU libraries, non-NVIDIA variants, C++
    glue). Those are left out entirely -- never written down as "no targets",
    which a reader would take for a positive finding.
    """
    if _cuobjdump() is None:
        return []
    deadline = time.monotonic() + _ARCH_SCAN_BUDGET_S
    out: list[dict] = []
    for so in _package_so_files(site):
        if time.monotonic() > deadline:
            break
        archs = _probe_so_arch(so)
        if not archs:
            continue
        rel = so.relative_to(site)
        out.append({"package": rel.parts[0], "path": rel.as_posix(), "sm_list": archs})
    return out


def _declare_mine(fspec: dict, mine: set[str] | None, warnings: list[str]) -> dict:
    """The user explicitly declares "I made this file myself" ⇒ licence tier
    private (own asset).

    An unknown licence defaults to gated, and that direction is right — but a
    model the user trained themselves is in no public registry either, so it
    lands as gated with no download address to point at, and the recipient hits
    a dead end. The private tier describes exactly this: the sharer's own assets
    (a self-trained LoRA, own material), supplied to authorised recipients.

    **Only an explicit declaration counts; never infer one** — guessing wrong
    here ships a genuinely gated model as if it were the user's own work. The
    declaration also **does not override a lookup**: ``_license_of`` keeps
    whichever of the two tiers is stricter, so claiming a real gated model is
    yours still leaves it gated whenever the lookup succeeds.
    """
    path = fspec.get("path")
    if not mine or not isinstance(path, str) or path not in mine:
        return fspec
    out = dict(fspec)
    out["license"] = {
        "shareable": True,
        "serving_scope": "private",
        "tag": "unknown",
        "note": "You declared this file your own work (--mine), so it travels with a hand-off "
                "to the people you give a code to. If it isn't yours, pack again without --mine.",
    }
    warnings.append(
        f"{path}: you declared this your own work, so its bytes DO travel to anyone you "
        f"hand this nest to. Only do that for files you made (a LoRA you trained, your own "
        f"images) — not for models you downloaded."
    )
    return out


def _license_of(fspec: dict, warnings: list[str], license_lookup=None) -> dict:
    """Three-tier supply routing: an unknown license defaults to gated
    (default deny, never default allow).

    A **completely missing** ``license`` block takes the same default-deny route
    — hand-written specs leave it out all the time. Defaulting to gated is the
    safe side: these bytes only ever serve your own restores, and are never
    supplied across users.
    """
    # Look it up first, then keep whichever is stricter, the lookup or what the
    # user wrote. A failed lookup is normal, not an error — **packing must never
    # fail because of it**.
    verdict = license_lookup(fspec) if license_lookup is not None else None
    raw = fspec.get("license")
    if verdict is not None and not isinstance(raw, dict):
        return stricter_of(None, verdict)
    if verdict is not None:
        return stricter_of(raw, verdict)
    if isinstance(raw, dict) and license_lookup is not None:
        # We looked it up and found nothing — **this tier must be marked as
        # "the user's own claim"**. Without that mark, an unchecked claim looks
        # exactly like a checked conclusion, which is the old failure mode.
        merged = stricter_of(raw, None)
        if "serving_scope" not in raw:
            # The warning still goes out: the packer needs to know this tier came
            # from the default-deny rule, not from a lookup.
            warnings.append(
                f"{fspec['path']} says nothing about serving_scope, so we're defaulting to gated "
                f"(restricted: this copy only serves your own restores)"
            )
        return merged
    if not isinstance(raw, dict):
        warnings.append(
            f"{fspec.get('path', '(a file)')} doesn't say anything about its licence, so "
            f"we're treating it as restricted: this copy only ever serves your own "
            f"restores, and it never travels with a nest you hand to someone else. "
            f"Add a \"license\" block to the spec if that isn't what you want."
        )
        raw = {}
        # When the whole block is missing, the serving_scope warning below would
        # say the same thing a second time — once is enough; duplicate warnings
        # teach people to ignore warnings, which is worse than none.
        return {"serving_scope": "gated", "shareable": False}
    lic = dict(raw)
    if "serving_scope" not in lic:
        lic["serving_scope"] = "gated"
        warnings.append(
            f"{fspec['path']} says nothing about serving_scope, so we're defaulting to gated "
            f"(restricted: this copy only serves your own restores)"
        )
    if lic["serving_scope"] == "gated":
        lic["shareable"] = False  # gated bytes never travel with the nest
    return lic


@dataclass
class PackReport:
    ok: bool = False
    exit_code: int = int(ExitCode.OK)
    dry_run: bool = False
    nest_id: str = ""
    manifest_path: str | None = None
    manifest: dict | None = None
    total_bytes: int = 0
    blob_count: int = 0
    inventory: list[dict] = field(default_factory=list)  # reverse-inferred preview
    findings: list[str] = field(default_factory=list)
    failure: dict | None = None
    capture_report: dict | None = None  # present iff spec was reverse-inferred
    #: ``--i-know`` was used to step past the credential-shape gate. **The
    #: hand-off surface asks again on the strength of this** — the escape valve
    #: only lets you pack, it does not let you hand off.
    i_know_used: bool = False
    #: renest itself was found installed **inside the environment being packed**
    #: (see :func:`self_installed_in_env`). Installing it there can displace
    #: library versions the app in that environment was already using, so the
    #: dependency list captured here may describe an environment the workflow
    #: never actually ran on. Advisory: the pack goes through; this flag lives
    #: in the report only, never in the manifest.
    renest_in_packed_env: bool = False
    #: Whether this nest, as packed, can be rebuilt on another machine. False when
    #: the shipped lock keeps a vendor-only pin with no download address (an
    #: offline pack of a torch==…+cuXXX environment): archived faithfully, but a
    #: rebuild against the public index can never install it, and the restore
    #: side's pre-check refuses it up front. **Report layer only, never in the
    #: manifest** (same rule as renest_in_packed_env: a manifest field goes
    #: through the format process). Meaningful for a pack that succeeded; a
    #: failed pack produced nothing to judge and keeps the default.
    restorable: bool = True
    #: Plain-language reasons behind ``restorable=False``, one per cause, each
    #: carrying its own way out. Kept apart from ``findings``: warnings scroll,
    #: this is the fact a hand-off or a restore decision hangs on.
    unrestorable_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("manifest", None)  # keep report light; manifest lives on disk
        return d


def offline_effects(
    offline: bool, pin_wheels: bool, no_licence_lookup: bool
) -> tuple[bool, bool]:
    """What ``--offline`` means for the two online pack steps, as
    ``(pin_wheels, no_licence_lookup)`` — one definition, so the CLI and its
    tests cannot disagree.

    ``--offline`` = pin nothing and look up no licences. The fine-grained flags
    stay individual overrides: an explicit ``--pin-wheels`` wins over the
    pinning half even under ``--offline`` (the user asked for that one online
    step by name), and ``--no-licence-lookup`` simply folds in.
    """
    return (pin_wheels or not offline, no_licence_lookup or offline)


def sealed_summary(report: PackReport) -> str:
    """The one-line pack completion message (wording is fixed).

    Health facts only — what was sealed, whether the dependency lock made it
    in, whether lint had anything to say. NEVER a price, a plan name or an
    upsell: at this moment the user's rented machine is burning money, and a
    sales pitch priced against that clock is a shakedown, not information.
    """
    manifest = report.manifest or {}
    lock = manifest.get("python_lock") or {}
    if lock.get("lockfile") or lock.get("lockfile_path") or lock.get("from_environment"):
        lock_note = "dependency lock complete"
    else:
        lock_note = "no dependency lock captured"
    if report.findings:
        lint_note = f"lint: {len(report.findings)} warning(s), listed above"
    else:
        lint_note = "lint: no warnings"
    return (
        f"Sealed ✓ nest {report.nest_id} · {report.blob_count} files / "
        f"{report.total_bytes} bytes · {lock_note} · {lint_note}"
    )


#: Format 2.3 convention: where the escape-hatch script sits inside a nest
#: (relative to the restore target directory). This string is **part of the
#: specification**, not an implementation detail — it is how someone two years
#: from now knows where to look.
ESCAPE_HATCH_REL = ".renest/escape/restore.sh"


def escape_hatch_source() -> Path | None:
    """Find the authoritative copy of the escape-hatch script
    (``scripts/restore.sh``) on this machine.

    Returns ``None`` when it cannot be found — **never substitute something
    else**. Two places, tried in order:
    (1) once installed as a package, it lives at ``renest/escape/restore.sh``;
    (2) when running straight from the source tree, at ``scripts/restore.sh``.
    """
    packaged = Path(__file__).resolve().parent / "escape" / "restore.sh"
    if packaged.is_file():
        return packaged
    repo = Path(__file__).resolve().parents[3] / "scripts" / "restore.sh"
    if repo.is_file():
        return repo
    return None


def _attach_escape_hatch(manifest: dict, place, dry_run: bool, warnings: list[str]) -> None:
    """Put the escape-hatch script itself inside the nest (at the format 2.3
    conventional path ``.renest/escape/restore.sh``).

    The escape hatch promises "even if this company is gone, you can still get
    your things back", which only holds if the script travels **inside** the
    nest instead of having to be fetched from us. It costs a few tens of KB,
    stored by content fingerprint, so one version is stored once for everybody.

    The copy inside a nest is **frozen**, so later fixes never reach old nests:
    it is the floor, and a newer copy from us reads more format generations.

    It is an ordinary ``files[]`` entry, so fingerprint, size and byte-for-byte
    verification come for free and a recipient can tell whether anyone tampered
    with it — never run a script out of someone else's nest with your eyes shut.
    """
    src = escape_hatch_source()
    if src is None:
        warnings.append(
            "Couldn't find the emergency restore script (scripts/restore.sh) on this "
            "machine, so it is not travelling inside this nest. The nest itself is fine — "
            "you would just need a copy of Renest to unpack it later."
        )
        return
    if any(f.get("path") == ESCAPE_HATCH_REL for f in manifest.get("files", [])):
        return  # someone already placed one explicitly: don't overwrite, don't duplicate
    if dry_run:
        h, size = _sha256_stream(src)
        blob = {"sha256": h, "size_bytes": size}
    else:
        blob = place(src, hardlink=False)
    manifest.setdefault("files", []).append({
        "path": ESCAPE_HATCH_REL,
        "blob": blob,
        "kind": "other",
        # Our own script, Apache-2.0, anyone may take it — escaping is its job.
        "license": {"shareable": True, "serving_scope": "open", "spdx": "Apache-2.0"},
    })


def _attach_licence_texts(manifest: dict, place, dry_run: bool, root: Path) -> None:
    """Put the **standard text** of every licence used in this nest into the
    nest, and point each asset at it (format 2.2).

    **The text must travel with the bytes**: the OpenRAIL family requires use
    restrictions to be delivered along with the model, and shipping the licence
    text itself is the hardest-to-get-wrong way to do that. `cc-by-4.0`
    attribution works the same way — carry the text next to the provenance.

    The text is an ordinary file, so content addressing, dedup and verification
    come for free and one licence text is stored once across the whole drive.
    """
    wanted: dict[str, Path] = {}
    for f in manifest.get("files", []):
        spdx = (f.get("license") or {}).get("spdx") or ""
        src = licence_text_path(spdx)
        if src is not None:
            wanted[spdx.strip().lower()] = src
    # The upstream's **own** licence file, when it sits right next to the asset,
    # comes along too — the author may have added their own words (extra terms,
    # attribution requirements, contact details) that the standard text does not
    # carry. **The two do not conflict, take both**: one says what this licence
    # is, the other says what this author said.
    for f in manifest.get("files", []):
        rel = f.get("path") or ""
        base = resolve_file_root(f.get("root", "env"), root) / rel
        for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE",
                     "COPYING", "NOTICE"):
            cand = base.parent / name
            if cand.is_file() and cand.stat().st_size <= (1 << 20):
                wanted[f"as-shipped/{Path(rel).parent.name or 'model'}/{name}"] = cand
                break
    if not wanted:
        return
    for spdx, src in sorted(wanted.items()):
        # as-shipped/… is the upstream's own copy, not the standard text of a
        # named licence — so nothing points back at it.
        _is_standard = "/" not in spdx
        if dry_run:
            h, size = _sha256_stream(src)
            blob = {"sha256": h, "size_bytes": size}
        else:
            blob = place(src, hardlink=False)
        manifest["files"].append({
            "path": f"LICENSES/{spdx}.txt",
            "blob": blob,
            "kind": "license_text",
            # A licence text may of course travel with the nest — it is the very
            # thing that is meant to be delivered alongside.
            "license": {"shareable": True, "serving_scope": "open", "spdx": spdx},
        })
        if not _is_standard:
            continue
        for f in manifest["files"]:
            if (f.get("license") or {}).get("spdx", "").strip().lower() == spdx and \
                    f.get("kind") != "license_text":
                f["license"]["text"] = dict(blob)


def _attach_recipes(manifest: dict, place, dry_run: bool, work: Path, recipes: list[dict]) -> None:
    """Carry every recipe found besides the one already driving the check —
    never make the caller pick a favorite among several past runs.

    Deduped by content: the same recipe often sits behind several pictures.
    Each is a few KB, so a few dozen still cost nowhere near the models this
    nest also carries.
    """
    seen: set[str] = set()
    for content in recipes:
        text = json.dumps(content, ensure_ascii=False, sort_keys=True, indent=2)
        h = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        tmp = work / f"recipe-{h[:16]}.json"
        tmp.write_text(text, encoding="utf-8")
        if dry_run:
            hh, size = _sha256_stream(tmp)
            blob = {"sha256": hh, "size_bytes": size}
        else:
            blob = place(tmp, hardlink=False)
        manifest["files"].append({
            "path": f"RECIPES/{h[:12]}.json",
            "blob": blob,
            "kind": "other",
            "license": {"shareable": True, "serving_scope": "private", "tag": "permissive",
                        "note": "A workflow recipe recovered from this environment — "
                                "treated as yours."},
        })


def _scan_spec_for_secrets(root: Path, spec: dict) -> tuple[list, list[str]]:
    """[SECURITY-REVIEW] Scan every **code directory** that is about to be packed.

    What gets scanned are the ``code_deps[]`` trees **as they sit on this machine**
    (``source_path`` when given, else ``install_path``) — because those are the
    places where a whole directory is packed as-is. ``files[]`` holds individually
    named assets (models, material) and is not in scope here.

    Each tree skips nested subdirectories that are their own ``code_dep``, so the
    same bytes are not reported twice (same handling as :func:`_find_so_files`).
    """
    from .secrets import scan_tree

    # Recipe files (the YAML/TOML a training run uses) get scanned too — they
    # hide secrets more often than code directories do, and they are named one
    # by one into the nest rather than living in a code_deps tree, so the
    # per-directory loop below would never reach them.
    from .secrets import scan_file, scan_recipe_json
    cfg_hits: list = []
    named: set[str] = set()
    for ad in (spec.get("adapters") or {}).values():
        if isinstance(ad, dict):
            named.update(str(x) for x in (ad.get("config_files") or []))
    for rel in sorted(named):
        cfg_hits += scan_file(root / rel, label=rel)

    # [SECURITY-REVIEW] The image-gen recipe, scanned on its own path. ``config_files``
    # above is filled by the training side only, so the recipe was reaching the nest
    # unscanned -- and a node that calls a hosted service keeps that service's key in a
    # plain input. A nest is **handed to other people**, so a key left in one leaks to
    # the recipient, not merely to us. Found 2026-08-12; this was the only credential
    # gate in the project, so a miss here was a miss everywhere.
    wf_rel = ((spec.get("adapters") or {}).get("comfyui") or {}).get("workflow_path") or ""
    if wf_rel:
        cfg_hits += scan_recipe_json(root / str(wf_rel), label=str(wf_rel))

    deps = [d for d in (spec.get("code_deps") or []) if isinstance(d, dict)]
    paths = [str(d.get("install_path") or "").strip("/") for d in deps]
    hits: list = []
    suspicious: list[str] = []
    for d, ip in zip(deps, paths, strict=True):
        if not ip:
            continue
        # [SECURITY-REVIEW] Read where the bytes actually are. A dep packed out of a
        # second tree (``source_path``) would otherwise be scanned at a path holding
        # nothing, and an empty scan is indistinguishable from a clean one.
        src = _spec_source(root, d, ip)
        # Other code_deps nested inside (e.g. each custom node under ComfyUI)
        # are scanned on their own pass, so they come out of this one.
        # [SECURITY-REVIEW] The exclusion is the nested dep's **whole path**. It used
        # to be only its first path component, which meant one node folder having an
        # entry of its own took all of ``custom_nodes/`` out of the host's scan --
        # and node folders the workflow never named have no entry, so their bytes
        # rode into the host archive having never been looked at. The scan report
        # said "no credentials found" without having opened them. Found 2026-08-30.
        nested = frozenset(
            Path(o).relative_to(ip).as_posix()
            for o in paths
            if o and o != ip and (o + "/").startswith(ip + "/")
        )
        # [SECURITY-REVIEW] The dep's own ``exclude`` comes off too: those bytes never
        # enter the archive, yet a hit there is a **hard stop** (exit USAGE, nothing
        # written). ComfyUI excludes ``user/``, and a key typed into its settings screen
        # lands in ``user/default/comfy.settings.json`` -- that alone made packing
        # impossible without ``--i-know``. Found 2026-08-30. Only the spec's own list:
        # ``_declared_assets_inside`` entries leave the code archive merely because each
        # travels as its own blob, so their bytes DO ship and must stay in scope.
        own = frozenset(
            e for e in (str(x).strip("/") for x in (d.get("exclude") or [])) if e
        )
        h, s = scan_tree(src, exclude=nested | own)
        prefix = d.get("name") or ip
        hits += [type(x)(f"{prefix}/{x.path}", x.line, x.what, x.sample) for x in h]
        suspicious += [f"{prefix}/{x}" for x in s]
    return cfg_hits + hits, suspicious


def _resolve_via_extra_model_paths(root: Path, relpath: str) -> Path | None:
    """Capture normalises models found through extra_model_paths into their
    standard path ("follow the pointer to find it, record it in the standard
    place"), but the physical bytes still live in the external directory — so
    when packing actually reads the file we must map the standard path back to
    its real location on disk. Only applies to the
    ``<ComfyUI>/models/<category>/<file>`` shape (input_asset and friends are not
    governed by extra_model_paths). Returns None when nothing matches (or when
    the spec was not inferred by capture and there is no matching ComfyUI
    directory at all), and the caller reports the file as missing as usual."""
    parts = Path(relpath).parts
    if len(parts) < 3 or parts[-3] != "models":
        return None
    comfyui_dir = root / parts[0]
    category, filename = parts[-2], parts[-1]
    emp = _parse_extra_model_paths(comfyui_dir)
    for d in emp.get(category, []):
        cand = d / filename
        if cand.is_file():
            return cand
    return None


class _ProgressTracker:
    """Progress announcer for packing: measure how many bytes are to be moved
    first, then report once after each item is moved.

    The denominator comes from file sizes: stat only, never reading content, so
    it costs a fraction of a second against minutes of moving bytes. Anything we
    cannot measure (missing path, no permission) counts as 0, so progress errs
    low — better to look slow than to show 120%; a 0 denominator reports no
    percentage rather than an invented one. The asset phase runs on several
    threads, so the counter is under a lock.
    """

    def __init__(self, emitter: EventEmitter, root: Path, spec: dict) -> None:
        self.emitter = emitter
        self.lock = threading.Lock()
        self.done = 0
        self.started = time.monotonic()
        self.total = self._plan(root, spec)

    @staticmethod
    def _plan(root: Path, spec: dict) -> int:
        total = 0
        for dep in spec.get("code_deps", []):
            d = _spec_source(root, dep, dep.get("install_path", ""))
            with contextlib.suppress(OSError):
                if d.is_dir():
                    # **Only what really gets packed** — same function the dry run uses.
                    # Summing the whole tree instead counted the models living under it
                    # (they travel one by one through ``files[]``, not in this archive),
                    # and the venv and .git as well: a real 20 GB run reported a
                    # 797 GB denominator, so the bar stopped at 2.6% and looked stuck.
                    ex = list(dep.get("exclude", [])) + _declared_assets_inside(
                        spec, dep.get("install_path", ""), dep.get("exclude", []))
                    total += _dir_size_as_packed(d, ex)
        lock_path = spec.get("python_lock", {}).get("lockfile_path")
        if lock_path:
            with contextlib.suppress(OSError):
                total += (root / lock_path).stat().st_size
        for fspec in spec.get("files", []):
            with contextlib.suppress(OSError, KeyError):
                total += _spec_source(root, fspec, fspec["path"]).stat().st_size
        return total

    def advance(self, stage: str, n_bytes: int, source: str) -> None:
        with self.lock:
            self.done += max(0, int(n_bytes))
            done = self.done
        elapsed = max(1e-6, time.monotonic() - self.started)
        self.emitter.progress(
            stage,
            percent=round(min(100.0, done * 100.0 / self.total), 1) if self.total else 0.0,
            bytes_done=done,
            bytes_total=self.total,
            speed_mbps=round(done * 8 / 1e6 / elapsed, 2),
            active_sources=[source],
        )


def _has_placeholder(node: object) -> bool:
    """Does this node still contain a "fill me in" blank? (The blanks in the
    pack skeleton look like ``<fill in …>``.)

    **Anything we cannot obtain is omitted wholesale; never write placeholder
    text** — it fails the schema's own format check (an image fingerprint must
    be ``sha256:`` plus 64 hex characters), producing an archive that looks
    successful and is invalid. A ``<`` anywhere means it was never filled in.
    """
    if isinstance(node, str):
        return "<" in node
    if isinstance(node, dict):
        return any(_has_placeholder(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_placeholder(v) for v in node)
    return False


#: What the manifest schema accepts as an image fingerprint. Same string in both
#: schemas; kept here so the check below reads as the rule it enforces.
_DIGEST_SHAPE = re.compile(r"^sha256:[a-f0-9]{64}$")


def _base_image_for_manifest(spec_img: object, warnings: list[str]) -> dict | None:
    """The image block to write into the manifest, or None to leave it out.

    A pack-spec may carry a ``ref`` with no ``digest`` (its schema allows that),
    while the manifest requires both -- so copying the block through produced an
    archive that fails our own ``renest lint``, silently. The fingerprint is
    lookup-able from the name, so look it up; if the registry cannot answer,
    drop the whole block, because half an image record is worse than none.

    **A blank fingerprint beside a real name is the normal case, not an unfilled
    one**: the pack skeleton asks the human for the name only, leaving the digest
    out of its ``needs_manual`` list precisely because it can be looked up. So
    only an absent or still-blank *name* means the block cannot be written.
    """
    if not isinstance(spec_img, dict) or not spec_img:
        return None
    ref = str(spec_img.get("ref") or "").strip()
    if not ref or _has_placeholder(ref):
        return None
    digest = str(spec_img.get("digest") or "").strip()
    # Anything still carrying a blank is dropped; ref and digest are re-added below
    # from the values this function actually established.
    out = {k: v for k, v in spec_img.items() if not _has_placeholder(v)}
    out["ref"] = ref
    if _DIGEST_SHAPE.match(digest):
        out["digest"] = digest
        return out
    from .capture import resolve_image_digest

    found = resolve_image_digest(ref, timeout=10.0)
    if not found:
        warnings.append(
            f"This pack-spec names the image {ref} but carries no usable fingerprint for "
            f"it, and the registry could not be asked for one. The image line is left out "
            f"of the manifest rather than written half-filled — a nest carrying a name "
            f"without a fingerprint fails our own `renest lint`. To keep it, put the "
            f"fingerprint (sha256: plus 64 hex characters) into base_image.digest."
        )
        return None
    # **Say which layer it is.** The lookup only ever asks for the index media types
    # (see resolve_image_digest), so what comes back is always the index digest, never
    # the per-architecture one -- and the schema treats those as different things, with
    # the per-architecture one being the useful one. Writing the digest without saying
    # which layer leaves a consumer unable to tell, and the schema says not to guess.
    # A digest the spec supplied stays unlabelled: we do not know where it came from.
    out["digest"] = found
    out["digest_kind"] = "index"
    return out


def _site_packages_for(
    root: Path, env_python: str | None, program_dir: Path | None = None
) -> Path | None:
    """The installed-packages folder of the environment being packed: asked of its
    interpreter when one can run here, found by layout when not.

    ``program_dir`` covers the split program/data layout: when the program tree
    lives apart from the data root, its environment lives with the program, and
    a scan of the root alone reads empty there."""
    cand = root / ".venv" / "bin" / "python"
    py = env_python or (str(cand) if cand.exists() else None)
    sp = interpreter_site_packages(py) if py else None
    return sp if sp is not None else find_site_packages(root, program_dir)


def _env_python_for(root: Path, env_python: str | None) -> str | None:
    """The interpreter of the environment being packed, found by layout when the
    caller does not name one.

    ``<root>/.venv`` is only the common case. kohya keeps its environment inside
    the checkout it packs (``<root>/sd-scripts/.venv``), and looking only at the
    root found nothing there: the manifest then carried no torch facts, so the
    GPU-generation gate had nothing to compare and downgraded itself to
    "unverified". Measured 2026-08-18 on three Blackwell machines — all three
    passed the pre-flight and then died on ``no kernel image is available``.
    """
    if env_python:
        return env_python
    cands = list(venv_python_candidates(root))
    sp = find_site_packages(root)
    if sp is not None:
        # ``env_dir_of`` already returns the environment root, so the interpreter
        # hangs directly off it — feeding it back through ``venv_python_candidates``
        # would ask for ``.venv/.venv/bin/python``.
        env = env_dir_of(sp)
        cands += [env / "bin" / "python", env / "bin" / "python3", env / "Scripts" / "python.exe"]
    found = find_env_python(cands)
    return str(found) if found else None


def _foreign_env_kernel(root: Path, env_python: str | None) -> str | None:
    """The other machine's name when the environment being packed was built for one.

    Everything the fingerprint block records -- python version, OS, wheel platform
    tag, driver, C library -- describes **the machine running pack**. The format says
    so, and it is right whenever packing happens inside the environment that ran the
    workflow. A shared all-in-one bundle breaks that assumption without saying a word.
    """
    if env_python:
        return None                 # the caller named the environment's own interpreter
    sp = find_site_packages(root)
    if sp is None:
        return None
    kernel = interpreter_kernel(env_dir_of(sp))
    here = "windows" if os.name == "nt" else "posix"
    return kernel if kernel and kernel != here else None


def _should_record_upstream_match(um: dict | None, entry: dict) -> bool:
    """Record upstream_match only when it does not contradict the entry itself.

    An archive-installed host (e.g. ComfyUI dropped in by comfy-cli) is not a
    git repository, so upstream_match() honestly answers ``no_upstream`` — but
    the entry still carries the repo_url/commit identity it was installed
    from. Writing "no repository at all" next to a named repo/commit is the
    upstream-contradiction lint error; per the docstring we never guess, so in
    that case the block is left out entirely.
    """
    if not um:
        return False
    if um.get("state") == "no_upstream" and (entry.get("repo_url") or entry.get("commit")):
        return False
    return True


def _utc_now() -> datetime.datetime:
    """The wall clock as an aware UTC datetime.

    A single seam for "now", so the instant a nest stamps as its creation time can
    be reasoned about against the files pack writes while assembling it.
    """
    return datetime.datetime.now(datetime.UTC)


def _created_at_ts(created_at: str) -> float | None:
    """A manifest ``created_at`` parsed back to a POSIX timestamp (None if unreadable).

    Mirrors how the upload-time tamper guard reads the same field, so the two agree
    on what "the moment this nest was created" means.
    """
    try:
        return datetime.datetime.fromisoformat(created_at.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _build_manifest(
    root: Path,
    spec: dict,
    *,
    place: Callable[..., dict],
    work: Path,
    env_python: str | None,
    no_fingerprint: bool,
    warnings: list[str],
    dry_run: bool,
    # Online pinning is the default since 0.1.13 (decided 2026-09-06): a bare
    # vendor pin shipped as-is killed the first real 64 GB restore after the
    # downloads. ``pack()`` owns the public default; this one only mirrors it.
    pin_wheels: bool = True,
    # Collects the reasons this nest, as packed, cannot be rebuilt elsewhere
    # (mutated in place, same convention as ``warnings``). The caller folds it
    # into PackReport.restorable / unrestorable_reasons — report layer only.
    unrestorable: list[str] | None = None,
    client: httpx.Client | None = None,
    no_licence_lookup: bool = False,
    mine: set[str] | None = None,
    emitter: EventEmitter | None = None,
    cache: HashCache | None = None,
    program_dir: Path | None = None,
) -> tuple[dict, list[dict]]:
    """P1 + P2: scan/hash + assemble the v1 manifest. Returns (manifest, inventory).

    ``program_dir`` only says where to also look for the extension's run record
    when the program lives in a tree of its own; every byte still comes from the
    spec.
    """
    nest_id = spec.get("id") or ulid()
    # A real pack takes tens of minutes, so without progress events a UI watching
    # through the API can only show a frozen 0% bar: no way to tell "working"
    # from "hung".
    tracker = _ProgressTracker(emitter, root, spec) if (emitter and not dry_run) else None
    manifest: dict = {
        "format_version": "2.12",
        "id": nest_id,
        "created_at": _utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "runtime": spec["runtime"],
        "code_deps": [],
        "python_lock": {"tool": "uv"},
        "files": [],
    }
    # `base_image` (which container image this environment runs on) is optional
    # from format 2.3 on. **Write it if we have it, omit the block if we don't,
    # never write placeholder text** — a placeholder fails the schema's format
    # check (sha256: plus 64 hex characters) and invalidates the whole archive.
    _said = len(warnings)
    _img = _base_image_for_manifest(spec.get("base_image"), warnings)
    if _img is not None:
        manifest["base_image"] = _img
    elif len(warnings) > _said:
        pass  # it already said the precise thing; the blanket line below would muddy it
    else:
        warnings.append(
            "We can't tell which container image this environment runs on, so that line is "
            "left out of the manifest rather than filled with a placeholder. Rebuilding does "
            "not need it — it is a record of where this ran, not a rebuild instruction."
        )
    for k in ("name", "post_install", "api_deps", "creation", "entrypoint"):
        if k in spec:
            manifest[k] = spec[k]

    # -- fingerprint Layer 1 --
    # Skipped outright when the environment was built for another machine: a manifest
    # saying macOS/arm64/python 3.11 over a Windows bundle is confident and wrong, and
    # the restore side reads exactly these fields to judge "will this install here".
    # Both blocks are optional in the format, so leaving them out costs nothing.
    foreign_kernel = _foreign_env_kernel(root, env_python)
    if foreign_kernel:
        warnings.append(
            f"This environment was built for {foreign_kernel}, and pack is running "
            f"somewhere else. Everything we normally record about the machine — its "
            f"Python, operating system, GPU driver and which pre-built packages fit — "
            f"would have described this computer, not the one that ran the workflow, so "
            f"all of it is left out. The files themselves are packed exactly as they are. "
            f"To record those details, pack on the machine this environment runs on, or "
            f"point --env-python at its own Python."
        )
    if not no_fingerprint and not foreign_kernel:
        py = _env_python_for(root, env_python)
        fp = collect(py)
        manifest["fingerprint"] = fp.to_manifest_dict()
        # The CUDA version we just detected also belongs in ``runtime``: that is the block
        # the drive page and the recipe view read, and until now nothing ever wrote it, so
        # every nest showed "cuda ?" while the number sat in the fingerprint all along.
        # Detected only -- never invent one when torch is absent.
        # A fresh dict, not setdefault on the spec's own: ``runtime`` above is the caller's
        # object, and quietly growing their spec is how surprises get built.
        if fp.torch and fp.torch.cuda_version:
            rt = dict(manifest.get("runtime") or {})
            rt.setdefault("cuda_version", fp.torch.cuda_version)
            manifest["runtime"] = rt
        # -- torch side of the gpu block: captured_on + torch_cuda_arch_list.
        # Nothing collected → omit the whole block. The node .so side
        # (node_native_archs) is not governed by this gate; it is merged into the
        # same gpu block with setdefault after the code_deps loop.
        gpu = collect_gpu(py)
        if gpu:
            manifest["gpu"] = gpu
            # Same story as the CUDA line above: the card's name was collected all along,
            # into ``gpu.captured_on``, while the drive page reads ``runtime.gpu_model``
            # — so every nest showed no card at all. One value, written where it is read.
            name = (gpu.get("captured_on") or {}).get("name")
            if name:
                rt = dict(manifest.get("runtime") or {})
                rt.setdefault("gpu_model", name)
                manifest["runtime"] = rt
        # Which card generations each installed compiled package was built for.
        # PyTorch's own list answers for PyTorch and nothing else -- measured, one
        # library was built for every card except the packing machine's own. The
        # field and the machine check that reads it have both existed since 2.0;
        # nothing ever filled it in. setdefault because the node side lands in the
        # same block after the code_deps loop below.
        _site = _target_site_packages(py)
        if _site is not None and _site.is_dir():
            _pkg_archs = _collect_package_native_archs(_site)
            if _pkg_archs:
                manifest.setdefault("gpu", {})["package_native_archs"] = _pkg_archs
        # Two facts that decide whether a pre-built wheel can install on the target
        # (format 2.4). The platform tag is the authority; the C library is one of
        # the things that shapes it. Measured: one machine accepted 690 tags.
        env = collect_wheel_env(py)
        if env:
            rt = dict(manifest.get("runtime") or {})
            for key, value in env.items():
                rt.setdefault(key, value)
            manifest["runtime"] = rt
        # The GPU driver this ran on. Two places read it and both read an empty value
        # on every nest ever packed — the collector sat in doctor.py all along, just
        # never called from here. Imported inside the function: doctor pulls in the
        # rules layer, and packing should not pay for that on every import.
        from .doctor import collect_driver_version, collect_system_memory

        _drv = collect_driver_version()
        if _drv:
            rt = dict(manifest.get("runtime") or {})
            rt.setdefault("driver_version", _drv)
            manifest["runtime"] = rt
        # How much system memory this machine could use (format 2.10): the cgroup
        # cap of a container, or the physical total. It is the second half of the
        # "restores byte for byte, still not usable" story the machine-library
        # list opened — a nest packed where memory was plentiful can restore into
        # a memory-capped pod and be killed the instant it loads the models.
        # Read nothing → write nothing: absence must never read as "needs little".
        _sysmem = collect_system_memory()
        if _sysmem:
            rt = dict(manifest.get("runtime") or {})
            rt.setdefault("system_memory", _sysmem)
            manifest["runtime"] = rt
        # Which operating-system libraries this run needed the machine to provide
        # (format 2.6). They cannot be packed, so a machine missing one restores every
        # byte and still loses whole plugins. Collected nothing → write nothing: an
        # empty list would read as "this run needed none".
        # Where the extension may have left its run record is a fact about how the
        # application is installed, not about this stage -- `_run_record_roots` answers
        # it, and the video-memory reading further down reads the same record.
        _rec_roots = _run_record_roots(root, spec, program_dir)
        libs, _own = collect_native_libs_with_layers(root, py, record_roots=_rec_roots)
        if _own:
            # Left off the list on purpose, and said out loud rather than dropped: a
            # rebuild creates its own interpreter, so a machine without these is short
            # of nothing. Listing them made a machine that worked perfectly report
            # three missing libraries (measured 2026-08-30, nest 01M186XFJ9Y9WBJN3H66CY8F5A).
            _where = sorted({str(Path(p).parent) for p in _own.values()})
            warnings.append(
                f"{len(_own)} librar{'y' if len(_own) == 1 else 'ies'} this run loaded "
                f"came from the Python installation that packed it ({', '.join(_where[:2])}), "
                f"not from the machine: {', '.join(sorted(_own)[:5])}"
                f"{'…' if len(_own) > 5 else ''}. They are not recorded as machine "
                f"requirements, because a rebuild builds its own Python and never uses "
                f"that one."
            )
        if libs:
            rt = dict(manifest.get("runtime") or {})
            rt.setdefault("native_libs", libs)
            manifest["runtime"] = rt
            # Which of the two lists this is decides whether a rebuild stops **before**
            # downloading anything. Asking a running app what it loaded is exact; reading
            # the installed packages is a guess that names libraries never used and misses
            # ones that are, so the restore side only mentions it and never stops on it.
            # The user is the only one who can turn the weaker list into the stronger one,
            # and until now nothing told them the difference existed.
            if libs.get("method") == "declared":
                warnings.append(
                    "The machine-library list in this nest is the weaker of the two: it was "
                    "read off the installed packages, because the application was not "
                    "running while we packed. A rebuild on a machine short of one of these "
                    "will only get a mild note, not the stop that happens before any bytes "
                    "are downloaded. To get the stronger list, start the application, let it "
                    "load once, and pack again with it still running -- then we ask it what "
                    "it actually loaded."
                )

        # What each custom node's own compiled files declare they need from the
        # machine (format 2.12). The list above says what the working run loaded; a
        # workflow that never touches a node's compiled parts never loads theirs, so
        # `native_libs` cannot cover them -- measured 2026-09-12, a plugin whose
        # `import cv2` died on `libxcb.so.1` on the rebuild machine passed the machine
        # check green. This list is read off the bytes being packed, so it covers nodes
        # the run never touched. Declared-level all the way down: the restore side may
        # only warn on it, never stop. Names the Python environment carries (torch/lib,
        # the `*.libs` convention) are not machine requirements -- the rebuild
        # reinstalls them from the lock. Node with no compiled files or no gaps → no
        # entry: an empty object would read as "all nodes checked, none needed".
        _sp = interpreter_site_packages(py) if py else None
        _node_libs: dict[str, list[str]] = {}
        for _d in (spec.get("code_deps") or []):
            if not isinstance(_d, dict):
                continue
            _ip = str(_d.get("install_path") or "").strip("/")
            if not _ip or "custom_nodes" not in _ip:
                continue
            _names = node_declared_machine_libs(
                _spec_source(root, _d, _ip),
                carried_dirs=(_sp,) if _sp else (),
            )
            if _names:
                _node_libs[str(_d.get("name") or _ip)] = _names
        if _node_libs:
            rt = dict(manifest.get("runtime") or {})
            rt.setdefault("node_native_libs", _node_libs)
            manifest["runtime"] = rt

        # How much video memory the working run was seen using, out of that same
        # record. Only something inside the application can read it while the run is
        # alive, and by packing time the process is usually gone. Nothing read → write
        # nothing: a nest without the figure means nobody measured, and the check that
        # reads it says exactly that instead of quietly passing.
        for candidate in _rec_roots:
            seen_vram = observed_use_from_record(read_run_record(candidate))
            if seen_vram:
                manifest.setdefault("gpu", {})["observed_use"] = seen_vram
                break

    inventory: list[dict] = []
    node_arch_entries: list[dict] = []  # kept-vendored .so target archs -> manifest.gpu

    # -- code deps: tar -> blob --
    for dep in spec.get("code_deps", []):
        # role is required (host / extension / the user's own code); repo_url and
        # commit are optional — a kohya user's config and launch scripts often
        # live in no git repository at all.
        role = dep.get("role")
        if role not in ("host", "extension", "user_code"):
            raise PackError(
                f"code_deps entry {dep.get('name')!r} does not say what it is. Add "
                '"role": "host" (the app itself), "extension" (something installed into '
                'it) or "user_code" (your own scripts and config).',
                exit_code=int(ExitCode.USAGE),
            )
        entry = {"name": dep["name"], "role": role}
        for k in ("repo_url", "commit"):
            if dep.get(k):
                entry[k] = dep[k]
        entry["install_path"] = dep["install_path"]
        # install_path is the destination recorded in the nest; source_path (when
        # given) is the only thing that changes -- where we read from.
        src_dir = _spec_source(root, dep, dep["install_path"])

        # Models sitting under the code folder used to need a hand-written exclude to
        # stay out of its archive; without one the same bytes were packed twice and the
        # nest doubled. Take them out here instead, and use one exclude list for every
        # step below so the dry run's size, the scans and the archive agree.
        auto_ex = _declared_assets_inside(spec, dep["install_path"], dep.get("exclude", []))
        dep_ex = list(dep.get("exclude", [])) + auto_ex
        if auto_ex:
            shown = ", ".join(auto_ex[:3]) + (f" and {len(auto_ex) - 3} more"
                                              if len(auto_ex) > 3 else "")
            warnings.append(
                f"{dep['name']}: {len(auto_ex)} file(s) listed under files[] sit inside this "
                f"code folder ({shown}). They are left out of its archive — each one travels "
                f"on its own, and packing them twice would make the nest twice the size."
            )

        # -- "strip by default, tell the user to recompile": node .so routing --
        raw_excludes: list[str] = []
        if src_dir.is_dir():
            # Dirty git working tree: the manifest only records repo_url+commit,
            # so a rebuild git-clones the clean version and any hand edits in the
            # tree silently evaporate. Report it truthfully at pack time; do not
            # block.
            dg = dirty_gap(dep["name"], src_dir)
            if dg:
                warnings.append(dg)
            # Symlinks reaching out of the tree. We warn instead of following them:
            # a link into a shared model cache would drag that whole cache into the
            # code archive, and the manifest's files[] paths say nothing about links.
            escaping = _symlinks_leaving_the_archive(src_dir, dep_ex)
            if escaping:
                shown = "; ".join(f"{rel} -> {target}" for rel, target in escaping[:3])
                warnings.append(
                    f"{dep['name']}: {len(escaping)} symlink(s) point outside the code "
                    f"archive, so they travel as links and come back as dead links after a "
                    f"restore — the nest still passes its byte check ({shown}). Replace them "
                    f"with the real files, or list them in code_deps[].exclude if the "
                    f"rebuild does not need them."
                )
            so_files = _find_so_files(src_dir, dep_ex)
            if so_files:
                if _has_build_path(src_dir):
                    raw_excludes = ["*.so", "build"]
                    post_hint = (
                        "post_install is already set"
                        if dep.get("post_install")
                        else "no post_install set yet — add a rebuild command yourself, "
                             "e.g. pip install -e ."
                    )
                    warnings.append(
                        f"{dep['name']}: {len(so_files)} compiled .so file(s) left out of the "
                        f"code archive (this node can rebuild them — it has setup.py / "
                        f"pyproject build-system / requirements.txt). On a different GPU they "
                        f"get rebuilt during restore, so {post_hint}"
                    )
                else:
                    warnings.append(
                        f"⚠ {dep['name']}: {len(so_files)} compiled .so file(s) with no way to "
                        f"rebuild them (no setup.py, no pyproject build-system, no "
                        f"requirements.txt). They ship as-is — dropping them would give you a "
                        f"nest that passes the byte check but crashes the moment it starts. "
                        f"On a GPU of another architecture they may not load; see "
                        f"manifest.gpu.node_native_archs if we could read what they were built for"
                    )
                    for so in so_files:
                        archs = _probe_so_arch(so)
                        if archs:
                            node_arch_entries.append(
                                {
                                    "code_dep": dep["name"],
                                    "path": so.relative_to(root).as_posix(),
                                    "sm_list": archs,
                                }
                            )

        # An inventory entry must say for itself what it is and where it lives:
        # without dep_role and path a consumer sees only a bare name and ends up
        # counting the host app itself among the "custom nodes".
        dep_ident = {"dep_role": role, "path": dep["install_path"]}
        if dry_run:
            size = _dir_size_as_packed(src_dir, dep_ex)
            inventory.append(
                {"role": "code_dep", "name": dep["name"], **dep_ident, "approx_bytes": size}
            )
        else:
            tar = _tar_code_dep(root, dep["install_path"], work, dep_ex, raw_excludes,
                                source_dir=src_dir)
            blob = place(tar, hardlink=False)
            if blob["size_bytes"] > FAT_ARCHIVE:
                warnings.append(
                    f"{dep['name']} code archive is {blob['size_bytes'] / (1 << 20):.0f} MiB — "
                    f"code should never be this big. Models or finished images most likely got "
                    f"swept in. Add them to code_deps[].exclude and pack again"
                )
            entry["archive"] = blob
            inventory.append({"role": "code_dep", "name": dep["name"], **dep_ident, **blob})
            if tracker:
                tracker.advance("P1", blob["size_bytes"], dep["name"])
        if dep.get("post_install"):
            entry["post_install"] = dep["post_install"]
        # What was deliberately left out of this archive (format 2.6). Both halves
        # belong in it: the spec's own list and what we dropped by ourselves above
        # (compiled .so files we expect to be rebuilt, build/, and assets that travel
        # on their own). Without this a recipient cannot tell a complete source tree
        # from a trimmed one — same repository, same commit, one directory missing,
        # manifest looks healthy. Disclosure only; nothing on the reading side replays it.
        _left_out = [str(x) for x in dep_ex] + list(raw_excludes)
        if _left_out:
            entry["exclude"] = _left_out
        # What licence this code is under. The host app is usually copyleft ("use
        # me and you must open source too") and extensions are all over the map,
        # so a team receiving a nest needs to know what is inside it. If we
        # cannot look it up we leave the field out; we never guess.
        if not no_licence_lookup:
            cv = _lookup_code_dep(dep, client=client)
            if cv is not None:
                entry["license"] = cv.as_license_block()
        # Whether this code matches the upstream it claims to be. It has to land
        # in the manifest, not just in a hint to the packer: "this extension has
        # been modified" is how a recipient spots a poisoned supply chain.
        um = upstream_match(src_dir)
        if _should_record_upstream_match(um, entry):
            entry["upstream_match"] = um
        manifest["code_deps"].append(entry)

    if node_arch_entries:
        manifest.setdefault("gpu", {})["node_native_archs"] = node_arch_entries

    # A shared bundle is started by a script sitting beside the application, and that
    # script is usually the only place its layout is written down -- which folder holds
    # the Python, which extra folders must be on the search path. Measured 2026-08-13:
    # the very file the owner double-clicks sat one level above everything we archive,
    # so the recipient would get the application without the thing that starts it.
    # We say so rather than quietly widening what gets packed.
    packed_dirs = [str(d.get("install_path") or "").strip("/") for d in manifest["code_deps"]]
    stray = []
    for script in find_launchers(root):
        try:
            rel = script.relative_to(root).as_posix()
        except ValueError:  # pragma: no cover - find_launchers only walks below root
            continue
        if not any(p and (rel == p or rel.startswith(p + "/")) for p in packed_dirs):
            stray.append(rel)
    if stray:
        warnings.append(
            f"{', '.join(stray)} looks like the script that starts this setup, and it "
            f"sits outside everything the nest carries — so it won't come back with it. "
            f"Move it inside the application folder, or list it under files[] in a "
            f"pack-spec, if whoever restores this should get it too."
        )

    # -- python_lock: four tiers, in order (the format spec carries the full table) --
    #   1. a lock file in the environment → pack it as-is;
    #   2. no lock file but its Python runs here → ask it what is installed;
    #   3. that Python will not run here (built for another operating system) →
    #      read the installed packages' own metadata off disk;
    #   4. not even that → leave the field out and warn.
    # Tiers 2-3 must fire for **every** entry point: a nest with no dependency list
    # makes the restore side type in hundreds of versions by hand.
    pl = spec.get("python_lock")
    if pl is None:
        _exe = env_python or find_env_python(venv_python_candidates(root))
        _sp = None if _exe else find_site_packages(root)
        if _exe is None and _sp is None:
            # The layout scan is bounded, so an interpreter parked somewhere unusual
            # slips past it. The start script names that folder outright — read it.
            for script in find_launchers(root):
                hinted = launcher_interpreter_dir(script)
                _sp = find_site_packages(hinted) if hinted else None
                if _sp is not None:
                    break
        if _exe:
            pl = {"tool": "uv", "from_environment": {"python": str(_exe)}}
        elif _sp is not None:
            # Tier 2.5: the interpreter is there but cannot be run here (a Windows
            # bundle packed from a Mac, an interpreter folder not named .venv). Its
            # installed packages each left a metadata file, so the list is readable
            # off disk. Weaker than asking the interpreter, so it goes after it.
            pl = {"tool": "uv", "from_installed": {"site_packages": str(_sp)}}
        else:
            warnings.append(
                "No python lock file in this environment (requirements.lock / uv.lock / "
                "requirements.txt) and no interpreter we could ask either, so python_lock is "
                "left out — the dependencies have to be filled in by hand before a restore "
                "can work (see report.gaps). Point --env-python at the Python this "
                "environment starts with and pack again if you want that list captured."
            )
    system_python: bool | None = None
    if pl is not None:
        from_env = pl.get("from_environment")
        if from_env:
            system_python = is_system_interpreter(from_env["python"])
            # No lock file, so ask the running interpreter instead. The generated
            # file goes only into the temporary work directory — not a byte of
            # the user's environment is touched, dry run or not.
            frozen = freeze_environment(from_env["python"])
            if frozen is None:
                raise PackError(
                    f"Couldn't read the installed packages from {from_env['python']} — "
                    "that interpreter didn't answer. Point --env-python at the Python that "
                    "runs this environment, or write a lock file and pack again",
                    exit_code=int(ExitCode.USAGE),
                )
            lock_src = work / "requirements.lock"
            lock_src.write_text(frozen, encoding="utf-8")
            lock_rel_hint = "requirements.lock (read from the running environment)"
            # No original path exists on this branch: the list was read out of the
            # interpreter, not copied from a file. Leave lockfile_path out rather than
            # naming a path that was never there.
            lock_orig_rel = None
            warnings.append(
                f"This environment had no lock file, so the dependency list was read from the "
                f"Python that runs it ({from_env['python']}): "
                f"{len(frozen.splitlines()) - LOCK_FROM_ENV_HEADER.count(chr(10))} packages, "
                f"versions pinned as installed. Package hashes and the original index URLs were "
                f"not recorded — a restore installs those versions from the public index"
            )
            # Jupyter kernel != shell env (diagnostic, never a block). The list was read
            # from one interpreter; the run may have happened in another (a kernel whose
            # packages differ from the shell). Say so when the run record disagrees; a
            # false stop here would misfire on every ordinary pack, so unknown stays quiet.
            _mismatch = env_python_matches_run_record(from_env["python"], read_run_record(root))
            if _mismatch:
                warnings.append(_mismatch)
        elif pl.get("from_installed"):
            sp = Path(pl["from_installed"]["site_packages"])
            frozen = freeze_from_installed(sp)
            if frozen is None:
                raise PackError(
                    f"Found an installed-packages folder at {sp} but could not read a single "
                    "package out of it. Point --env-python at the Python that runs this "
                    "environment, or write a lock file and pack again",
                    exit_code=int(ExitCode.USAGE),
                )
            lock_src = work / "requirements.lock"
            lock_src.write_text(frozen, encoding="utf-8")
            lock_rel_hint = "requirements.lock (worked out from the installed packages)"
            lock_orig_rel = None
            n_pkgs = len(frozen.splitlines()) - LOCK_FROM_INSTALLED_HEADER.count("\n")
            series = interpreter_python_series(env_dir_of(sp))
            warnings.append(
                f"This environment has no lock file and its Python was not found, or could "
                f"not be run here, so the dependency list was worked out from the {n_pkgs} "
                f"packages installed in {sp.name}, by reading their own metadata. Versions "
                f"are what is installed; package hashes and original index URLs were not "
                f"recorded, and anything installed from a source folder cannot be expressed "
                f"this way and is missing. **If that interpreter does run on this machine, "
                f"point --env-python at it and pack again** -- asking it directly carries "
                f"everything this route drops."
                + (f" That Python is {series}.x — the exact third number isn't written "
                   f"anywhere in this layout, so the version field is left empty rather "
                   f"than half-filled." if series else "")
            )
        else:
            lock_src = root / pl["lockfile_path"]
            lock_rel_hint = lock_orig_rel = str(pl["lockfile_path"])
            if not lock_src.is_file():
                raise PackError(f"Lock file is missing: {lock_src}", exit_code=int(ExitCode.USAGE))
        lock_text = lock_src.read_text()
        self_line = lock_carries_renest(lock_text)
        if self_line:
            warnings.append(
                f"This environment has renest itself installed ({self_line}), so it is in the "
                "dependency list. That is on purpose — a rebuild gives you back the "
                "environment you had, ours included. Worth knowing for next time: installing "
                "it here with pip can move versions of packages this environment already had "
                "(renest pulls in httpx, cryptography and a few more). `uv tool install "
                "renest` keeps it out of the environment you are capturing."
            )
        # The operating system's own packages and a vendor build like torch==2.4.1+cu124
        # both carry a local version, and the old code warned about them as one thing while
        # advising --pin-wheels. That advice is wrong for the first group: no index ever
        # published a wheel for python-apt, so pinning cannot reach it. Split them, because
        # only one of the two has a fix that works.
        distro_ver = distro_owned_packages(lock_text)
        # A local build baked into the image (torch==2.1.0a0+gitc263bd4) is a third
        # dead end: unlike a vendor +cuNNN build it is on no index and --pin-wheels
        # cannot reach it, so it gets its own warning and is taken out of local_ver
        # below -- the generic "--pin-wheels fixes this" advice is wrong for it.
        image_ver = image_build_evidence(lock_text)
        # One definition, shared with `renest lint`'s artifact-side gate — two copies
        # of "which pins are vendor-only" is exactly how a gate and its ledger drift.
        local_ver = vendor_only_locals(lock_text)
        if distro_ver:
            names = ", ".join(ln.split("==")[0].strip() for ln in distro_ver[:6])
            more = f" and {len(distro_ver) - 6} more" if len(distro_ver) > 6 else ""
            warnings.append(
                f"{len(distro_ver)} package(s) in this dependency list belong to the operating "
                f"system, not to a package index ({names}{more})"
                + (", because this environment runs on the Python that came with the image "
                   "rather than in a virtual environment" if system_python else "")
                + ". No machine can install them: the install stops on the first one and the "
                "rebuild fails there, after the model files have already been downloaded and "
                "paid for. Build this environment in a virtual environment (`uv venv`, then "
                "reinstall what it needs) and pack again, or pass --env-python at the Python "
                "inside one — that list is installable anywhere. Packing continues: the "
                "archive is still a faithful record of this machine."
            )
        # A conda-built environment is the same dead end from a different source, so it
        # gets the same treatment as the OS-package case above: warn now, at PACK time
        # and near the cause, instead of letting a restore blow up far from it. renest
        # rebuilds with uv/PyPI; conda-only packages (conda/libmambapy/mkl-service and
        # friends) have no wheel on any index, and a conda build-tree URL
        # (file:///croot/...) names a path that exists on no machine. Said here with the
        # one fix that works — not the un-followable "--trust-host file://" the URL audit
        # below would otherwise suggest for each such line.
        # **Take the package manager's own parts out before anything else looks at the
        # list.** This is a reading, not a judgement: it asks only "which distributions
        # make up conda itself", off conda's own METADATA headers, and never "does the
        # app need this". Measured on a real fine-tune run: the packed environment was
        # conda's base environment, so `libmambapy` and `menuinst` rode along in a
        # 121-line lock. Neither is on any index; the restore stopped on the first of
        # them **after 2.1 GB had been downloaded and paid for**. They are the package
        # manager, not the work -- a nest is a record of the app, and shipping a lock
        # that cannot install is not a more faithful record, it is a broken one.
        # Which environment to read this off is whatever the lock itself came from --
        # `_sp` / `_exe` above only exist on one of the branches that lead here.
        _pl_inst = (pl or {}).get("from_installed") or {}
        _pl_env = (pl or {}).get("from_environment") or {}
        _plumbing_py = _pl_env.get("python") or (str(env_python) if env_python else None)
        _plumbing_sp = (
            Path(_pl_inst["site_packages"]) if _pl_inst.get("site_packages")
            else (interpreter_site_packages(_plumbing_py) if _plumbing_py else None)
        )
        if _plumbing_sp is None:
            # A lock the spec pointed at names no environment, but one is usually
            # sitting right here -- and the conda parts ride in through that lock
            # exactly the same way. Without this the filter never fired on the
            # commonest route of all: `python_lock.lockfile_path`.
            _plumbing_sp = find_site_packages(root)
        if _plumbing_sp is not None:
            _owned = unreinstallable_manager_parts(Path(_plumbing_sp))
            lock_text, _dropped = split_out_package_manager(lock_text, _owned)
            if _dropped:
                lock_src = work / "requirements.lock"
                lock_src.write_text(lock_text)
                _names = ", ".join(ln.split("==")[0].strip() for ln in _dropped[:6])
                _more = f" and {len(_dropped) - 6} more" if len(_dropped) > 6 else ""
                warnings.append(
                    f"Left {len(_dropped)} package(s) out of the dependency list: they are "
                    f"conda's own installation ({_names}{_more}), read off conda's METADATA, "
                    "not something this environment's work depends on. They are on no package "
                    "index, so keeping them would stop the rebuild on the first one — after "
                    "the model files had been downloaded and paid for. Nothing the app "
                    "installed was touched, whichever tool installed it."
                )
        conda_ev = conda_owned_evidence(lock_text)
        if conda_ev:
            names = ", ".join(ln.split(" @ ")[0].split("==")[0].strip() for ln in conda_ev[:6])
            more = f" and {len(conda_ev) - 6} more" if len(conda_ev) > 6 else ""
            warnings.append(
                f"This looks like a conda-built environment ({names}{more}). renest rebuilds "
                "with uv/PyPI and cannot reproduce conda-only packages: they have no wheel on "
                "any package index, and a conda build path (file:///croot/...) exists on no "
                "other machine — so a restore would stop on the first of them. Build this "
                "environment in a virtual environment (`uv venv`, then reinstall what it "
                "needs) and pack again. Packing continues: the code and models in this "
                "archive are still a faithful record of this machine."
            )
        # **A lock that installs nowhere makes this nest unrestorable, and the report has
        # to say so.** Until now these three families only produced a warning, while
        # `PackReport.restorable` stayed True -- so a packer who scrolled past the warning
        # was told, in the one field a hand-off decision reads, that the archive was fine.
        # This is the same channel the offline/vendor-pin case already uses below, and it
        # changes no exit code and no format: packing still succeeds, because the archive
        # is still a faithful record of this machine. What it stops is the archive being
        # *described* as rebuildable when the dependency list provably is not.
        # The restore side does not depend on this mark -- it measures for itself at S0,
        # before any model bytes move (`restore.py::s0_lock_probe`). Measurement is the
        # stronger guard; this one exists for the person doing the packing, who otherwise
        # finds out only when someone else tries to rebuild.
        # **A distribution installed from a folder on this machine.** `pip install -e .`
        # -- the last line of kohya_ss's own requirements.txt, and what its README tells
        # you to run -- records the repository as an ordinary distribution, and a freeze
        # writes it out as a bare `library==0.0.0`. No index has that name at that
        # version, so a rebuild stops on it exactly as it does on a conda-only package;
        # measured on a real fine-tune archive, line 44 of its 121-line lock. Nothing in
        # the lock *text* can see this -- the line looks like any other -- so it is read
        # off the install record instead. Named, never removed: unlike conda's own
        # machinery this is the user's own work, and the app certainly needs it.
        _local_dirs = (
            dists_built_from_a_directory(Path(_plumbing_sp))
            if _plumbing_sp is not None else {}
        )
        _local_lines = lock_lines_for(lock_text, set(_local_dirs)) if _local_dirs else []
        if _local_lines:
            _n = ", ".join(ln.split("==")[0].strip() for ln in _local_lines[:6])
            _m = f" and {len(_local_lines) - 6} more" if len(_local_lines) > 6 else ""
            warnings.append(
                f"{len(_local_lines)} package(s) in this dependency list were installed "
                f"from a folder on this machine ({_n}{_m}; e.g. {_local_lines[0]}), which is "
                f"what `pip install -e .` records. The line reads like an ordinary package, "
                f"but no index carries that name at that version, so a rebuild stops on it. "
                f"The folder itself is in this archive if it was packed as code; the "
                f"dependency list is what cannot express it. Packing continues: the archive "
                f"is still a faithful record of this machine."
            )
        # Each family gets **its own way out**. They are not interchangeable: telling
        # someone to rebuild in a virtual environment fixes a conda base environment and
        # does nothing at all for `pip install -e .`, which records the same line inside
        # a venv too. Advice that does not work is worse than no advice -- it is followed.
        _VENV_FIX = ("build this environment in a virtual environment (`uv venv`, then "
                     "reinstall what it needs) and pack again")
        for _family, _lines, _fix in (
            ("conda", conda_ev, _VENV_FIX),
            ("the operating system", distro_ver, _VENV_FIX),
            ("a folder on the packing machine", _local_lines,
             "pack that folder as code and install it from there on the rebuild, or "
             "publish it somewhere a rebuild can fetch it from"),
        ):
            if _lines and unrestorable is not None:
                _n = ", ".join(ln.split(" @ ")[0].split("==")[0].strip() for ln in _lines[:6])
                _m = f" and {len(_lines) - 6} more" if len(_lines) > 6 else ""
                unrestorable.append(
                    f"Archived faithfully, but as recorded this dependency list cannot be "
                    f"installed on another machine: {len(_lines)} package(s) belong to "
                    f"{_family} rather than to any package index ({_n}{_m}). A rebuild looks "
                    f"them up on the public index, which never has them, and stops. To make "
                    f"this nest rebuildable elsewhere, {_fix}."
                )
        # An image-preinstalled torch build carries a local version no index serves
        # (torch==2.1.0a0+gitc263bd4, an NGC container build): the pin reads fine and
        # installs nowhere, and --pin-wheels cannot find it either. Same warn-not-block
        # line as the cases above; the fix is a venv rebuild, or a direct wheel URL if
        # one exists. Taken out of local_ver above so the two do not contradict.
        if image_ver:
            names = ", ".join(ln.split("==")[0].strip() for ln in image_ver[:6])
            more = f" and {len(image_ver) - 6} more" if len(image_ver) > 6 else ""
            warnings.append(
                f"{len(image_ver)} package(s) carry a local build that only ever existed on "
                f"this machine or in its image ({names}{more}) — a from-source or container "
                f"build like torch==2.1.0a0+git…, which no package index carries and "
                f"--pin-wheels cannot find. The pin reads as installable and a restore stops "
                f"on it, after the model files have already been downloaded and paid for. "
                f"Rebuild this environment in a virtual environment (`uv venv`, then reinstall "
                f"from an installable release) and pack again, or pin a direct wheel URL by "
                f"hand if you have one. Packing continues: the archive is still a faithful "
                f"record of this machine."
            )
        # Packages that are rebuilt from source against the exact torch/CUDA/GPU-arch of
        # whatever machine installs them (flash-attn and friends): a byte-for-byte carry
        # is impossible in principle, so this is not a "pack it better" warning -- it is a
        # verdict, stated at pack time, that the restore machine must recompile. We read
        # the arch this run was built for out of the gpu block already assembled above
        # (no new field, no format bump) so the note names the target it was built against.
        compile_ev = compile_required_evidence(lock_text)
        if compile_ev:
            names = ", ".join(ln.split("==")[0].split(" @ ")[0].strip() for ln in compile_ev[:6])
            more = f" and {len(compile_ev) - 6} more" if len(compile_ev) > 6 else ""
            _cap = (manifest.get("gpu") or {}).get("captured_on") or {}
            _built_for = _cap.get("name") or _cap.get("sm_arch")
            built = f" (built here for {_built_for})" if _built_for else ""
            warnings.append(
                f"{len(compile_ev)} package(s) in this dependency list must be built from "
                f"source for the card that runs them{built}: {names}{more}. For each, "
                f"{COMPILE_REQUIRED_VERDICT}. The nest does not try to install these back — a "
                f"restore recompiles them or fetches the official wheel for its own card. "
                f"Packing continues: the archive is still a faithful record of this machine."
            )
        pinned: list[tuple[str, str]] = []
        if pin_wheels and not dry_run:
            # Pinning: the one step in pack that touches the network — on by
            # default since 0.1.13 (decided 2026-09-06); --offline is the
            # explicit zero-network path.
            py_ver = (spec.get("runtime") or {}).get("python_version", "")
            # Both pinning and fingerprints need the environment's Python version
            # to pick the right package files. A spec may legitimately not carry
            # one, and with pinning now the default that must not crash the pack:
            # no vendor pins -> skip the online extras with a warning; vendor
            # pins present -> refuse with the way out, never ship a dead nest.
            try:
                py_tag: str | None = python_tag_of(py_ver)
            except WheelPinError:
                py_tag = None
            if local_ver and py_tag is None:
                raise PackError(
                    f"{len(local_ver)} package(s) here pin a vendor-only build "
                    f"(e.g. {local_ver[0]}) that needs a direct download address "
                    f"recorded, but this environment's Python version was not "
                    f"captured, and picking the right package file needs it. "
                    f"Point --env-python at the Python that runs this environment "
                    f"and pack again — or pass --offline to archive as-is, marked "
                    f"as not rebuildable on other machines.",
                    exit_code=int(ExitCode.USAGE),
                )
            # **Fingerprints are not conditional on there being a vendor build.**
            # This block used to also require local_ver, so an ordinary lock got no
            # fingerprints at all and --package-source then promised a check that
            # could not happen. Pinning needs local_ver; recording hashes does not.
            if local_ver:
                try:
                    new_text, pinned = pin_lock_text(
                        lock_text,
                        py_tag,
                        # **Wheels must be chosen for the chip doing the packing.**
                        # Omit this and the x86_64 default applies: packing on ARM
                        # pins Intel wheels, and the archive verifies green while
                        # installing nowhere.
                        wheel_platform_tags(),
                        client=client,
                    )
                except WheelPinError as e:
                    # Honest boundary: a failed pin is a hard failure. Skipping
                    # silently = shipping a nest that passes sha256 and can never be
                    # installed again. Pinning is the default now, so the machine
                    # with no network gets pointed at the deliberate way out.
                    raise PackError(
                        str(e)
                        + "\n  Packing with no network on purpose? Pass --offline: "
                          "the nest is archived exactly as this machine stands and "
                          "marked as not rebuildable on other machines (licence "
                          "lookups are skipped too).",
                        exit_code=int(ExitCode.USAGE),
                    ) from e
                if pinned:
                    lock_src = work / "requirements.lock"
                    lock_src.write_text(new_text)
                    warnings.append(
                        f"{len(pinned)} package(s) carry a vendor-only version PyPI doesn't "
                        f"have; they now point at direct wheel URLs: "
                        + ", ".join(name for name, _ in pinned)
                        + ". From here on this lock is betting that wheel host stays up. "
                        "(The wheels_archived switch that would bundle the wheel files into "
                        "the nest is designed but NOT built yet — setting it only records "
                        "your intent in the manifest, it does not archive anything.)"
                    )
                # Machine reconciliation, not memory: every vendor-only pin must now
                # be a direct address. Re-scan the text that actually ships — a
                # silent fall-back inside pinning would otherwise produce a nest
                # that verifies green and can never be rebuilt, which is how the
                # July fix (tools/lock_rewrite.py) degraded into an optional flag
                # with no gate and shipped bare pins for two months.
                still_bare = vendor_only_locals(lock_src.read_text())
                if still_bare or len(pinned) != len(local_ver):
                    raise PackError(
                        "--pin-wheels ran, and the lock that would ship still carries "
                        f"{len(still_bare)} vendor-only pin(s) with no direct address "
                        f"({', '.join(ln.split('==')[0].strip() for ln in still_bare[:4])})"
                        f" — pinned {len(pinned)} of {len(local_ver)}. Such a nest "
                        "verifies green and can never be rebuilt, so packing stops. "
                        "This is a bug on our side (a silent fall-back in the pinning "
                        "step); please report it.",
                        exit_code=int(ExitCode.USAGE),
                    )
            # While we are online, also record a content fingerprint for every
            # package. It can only come from the index: once a package is
            # installed the .whl is gone, so the question is unanswerable
            # locally. **All of them or none of them** — one hashed line puts the
            # installer into verify-every-package mode and every unhashed line
            # then fails the install, so half a job is worse than none.
            if py_tag is None:
                hashed_text, n_hashed, unhashable = "", 0, []
                warnings.append(
                    "No content fingerprints were recorded: this environment's Python "
                    "version was not captured, and matching a package to its file "
                    "needs it. Point --env-python at the Python that runs this "
                    "environment to get them recorded."
                )
            else:
                # **The operating system is read here, at the boundary, like the
                # architecture next to it** — a wheel built for another OS does not
                # install however well the architecture matches, and writing its
                # fingerprint into the lock is worse than writing none: without one the
                # lock installs, with a wrong one the rebuild stops after paying for the
                # model files (2026-09-09, RC=30 on `pyyaml`'s macOS build).
                hashed_text, n_hashed, unhashable = add_hashes(
                    lock_src.read_text(), py_tag, wheel_platform_tags(), client=client,
                    os_family=wheel_os_family(),
                )
            if n_hashed:
                lock_src = work / "requirements.lock"
                lock_src.write_text(hashed_text)
                warnings.append(
                    f"Recorded a content fingerprint for {n_hashed} package(s), so a rebuild "
                    f"checks every one of them on arrival. That is also what makes it safe to "
                    f"install from a faster mirror: wrong bytes stop the rebuild instead of "
                    f"silently landing."
                )
            elif unhashable:
                warnings.append(
                    f"No content fingerprints were recorded, because {len(unhashable)} "
                    f"package(s) could not be looked up ("
                    + ", ".join(unhashable[:3])
                    + (f" and {len(unhashable) - 3} more" if len(unhashable) > 3 else "")
                    + "). It is all or nothing on purpose: a half-hashed list makes the "
                    "rebuild fail outright, which is worse than today's no-hash list."
                )
        elif local_ver and pin_wheels:
            # A dry run of an online pack: the rehearsal never rewrites the lock
            # and never goes online; the real pack will pin — or fail loudly.
            warnings.append(
                f"{len(local_ver)} package(s) carry a vendor-only version PyPI doesn't have "
                f"(like torch==…+cu124): a restore can only install them from direct wheel URLs, "
                f"and a dry run never rewrites the lock file, so pinned_wheel_urls is left out. "
                f"The real pack will pin them."
            )
        elif local_ver:
            # An offline pack (decided 2026-09-06): archive the scene faithfully,
            # refuse nothing — and record, in the report, that this nest as packed
            # cannot be rebuilt on another machine. The stopping points for an
            # unrestorable nest are the restore side's pre-check and hand-off
            # issuance, not the packing machine.
            _names = ", ".join(ln.split("==")[0].strip() for ln in local_ver[:6])
            _more = f" and {len(local_ver) - 6} more" if len(local_ver) > 6 else ""
            reason = (
                f"Archived faithfully, but as recorded this lock cannot be installed on "
                f"another machine: {len(local_ver)} package(s) pin a build that only its "
                f"vendor's own package index carries ({_names}{_more}; e.g. {local_ver[0]}), "
                f"and this pack was offline, so no download address was recorded for them. "
                f"A rebuild looks such a build up on the public index, which never has it, "
                f"and stops. To make this nest rebuildable elsewhere, pack again while "
                f"online — pinning is on by default, or pass --pin-wheels explicitly — so "
                f"each such build gets its exact download address."
            )
            if unrestorable is not None:
                unrestorable.append(reason)
            warnings.append(reason)
        # Move the warning forward in time: the restore side blocks unknown hosts
        # against the dependency-source allowlist, and by then the original
        # machine is usually gone. Nothing is blocked here — packing preserves
        # the scene, it does not police it — we only say up front that a later
        # restore will need one extra flag, while the user can still act on it.
        lock_text_for_audit = lock_src.read_text()
        # The absolute paths an editable install leaves behind do not exist on
        # another machine, while that directory itself travels with the nest, so
        # they become a marker the restore side swaps for its own rebuild root.
        # **Only the segment pointing at this environment's root is touched.**
        tokenised, n_tok = tokenise_env_root(lock_text_for_audit, root)
        if n_tok:
            lock_src = work / "requirements.lock"
            lock_src.write_text(tokenised)
            lock_text_for_audit = tokenised
            warnings.append(
                f"{n_tok} place(s) in the lockfile pointed at this machine's own folders "
                f"(that is what an editable install leaves behind). They now travel as a "
                f"marker and get pointed at wherever this nest is rebuilt."
            )
        # Mixed CUDA families: nvidia-* packages from two different major CUDA
        # versions install fine and then do not run, and the error ("libcudart.so
        # not found") points nowhere near the cause. Pack time is when the user
        # can still fix it, so say it now; report only, never block.
        cuda_mix = check_lock_cuda_family(lock_text_for_audit)
        if cuda_mix.level != LEVEL_PASS:
            warnings.append(cuda_mix.reason)
        unknown_src = audit_lock_urls(lock_text_for_audit)
        # A conda build-tree URL is not a host anyone can trust in — it names conda's own
        # build farm. The conda warning above already gave the only fix that works, so drop
        # these here rather than tell the user to `--trust-host file://` once per line.
        if conda_ev:
            unknown_src = [u for u in unknown_src if not is_conda_build_url(u)]
        # An editable/local-path install (-e /opt/mylib, or a wheel pinned by file://)
        # points at a folder that does NOT travel inside the nest, so a restore cannot
        # reach it — but "--trust-host <domain>" is un-followable for it (there is no
        # host). Same move as the conda case: give the one fix that works instead of the
        # trust-host line. The environment root's own editable install is exempt: it
        # travels as a token and the audit line for it is a false alarm at pack time
        # (the token has no real path here, but restore swaps it back and lets it
        # through), so drop those from unknown_src too.
        local_refs = local_path_evidence(lock_text_for_audit)
        _local_urls = {u for u in unknown_src
                       if ENV_ROOT_TOKEN in u or any(u in ln for ln in local_refs)}
        unknown_src = [u for u in unknown_src if u not in _local_urls]
        if local_refs:
            names = ", ".join(ln[:80] for ln in local_refs[:3])
            more = f" and {len(local_refs) - 3} more" if len(local_refs) > 3 else ""
            warnings.append(
                f"{len(local_refs)} dependency line(s) install from a path on this machine "
                f"that does not travel inside the nest ({names}{more}) — an editable install "
                f"of a folder outside the environment, or a wheel pinned by file://. A restore "
                f"stops there: the path is not on the new machine and the nest did not carry "
                f"it. Move that code into code_deps[] so it is packed with the nest, or install "
                f"it from a published wheel or a git URL that pins a commit, and pack again. "
                f"(The environment's own editable install is fine — it travels with the nest.)"
            )
        if unknown_src:
            warnings.append(
                f"{len(unknown_src)} dependency source(s) we don't recognize: "
                + ", ".join(u[:100] for u in unknown_src[:3])
                + (f" and {len(unknown_src) - 3} more" if len(unknown_src) > 3 else "")
                + ". Packing goes ahead as normal — this changes nothing today. But a later "
                "restore will stop right here (installing dependencies means running code from "
                "those sources on that machine). Let them through by name when you restore: "
                "`renest restore … --trust-host <domain>` (escape hatch: "
                "RENEST_TRUSTED_HOSTS=<domain>), once per new machine; a private source you use "
                "every day is better baked into your own base image, once and for all. "
                "If this is in fact a well-known public source and we got it wrong, tell us — "
                "we update the rules and every client lets it through. "
                "⚠ This is for whoever receives the nest too: hand it off to someone else and "
                "they hit the same stop"
            )
        # path is where the dependency lock sits in the environment. Without it
        # the entry is a bare hash and size, and a consumer has nothing
        # human-readable to show.
        lock_rel = lock_rel_hint
        # Where the lock sat in the environment (format 2.6). Both restore paths used
        # to land it at a fixed spot in the environment root and said so in a comment;
        # the fine-tuning frameworks keep theirs in a sub-directory, so that convention
        # moved the file somewhere the framework does not look.
        if lock_orig_rel and not unsafe_relpath(lock_orig_rel):
            manifest["python_lock"]["lockfile_path"] = lock_orig_rel
        # A lock pack generated or rewrote this round lives in the work directory,
        # not in the environment, and was written *after* the manifest's created_at.
        # It is then hard-linked into the blob tree, so the upload-time tamper guard
        # — which refuses a blob whose still-shared file was written after the nest
        # was created — would flag our own freshly written lock and upload nothing
        # (any environment with no lock file would then always fail). That is not an
        # external change: we wrote the file as part of creating this nest, so pin
        # its timestamp back to the nest's creation time. Only the lock pack authored
        # here (the one in `work`) is touched; a user's own lock, packed as-is, keeps
        # its own mtime so a genuine mid-write is still caught.
        if not dry_run and lock_src.parent == work:
            made_ts = _created_at_ts(manifest["created_at"])
            if made_ts is not None:
                os.utime(lock_src, (made_ts, made_ts))
        if dry_run:
            h, size = _sha256_stream(lock_src)
            manifest["python_lock"]["lockfile"] = {"sha256": h, "size_bytes": size}
            inventory.append(
                {"role": "python_lock", "path": lock_rel, "sha256": h, "size_bytes": size}
            )
        else:
            blob = place(lock_src, hardlink=not pinned)
            manifest["python_lock"]["lockfile"] = blob
            if tracker:
                tracker.advance("P1", blob["size_bytes"], lock_rel)
            # The lock belongs in the inventory here too, or the preview and the
            # finished report disagree on both the item count and total_bytes.
            inventory.append({"role": "python_lock", "path": lock_rel, **blob})
        # Which hosts a rebuild will reach out to. Host names only, never full
        # URLs: the name answers "who will my machine talk to" while full URLs
        # would blow up the disclosure surface. Pairs with the hard refusal of
        # non-allowlisted hosts — that side blocks, this side warns in advance.
        # **Read from the text that ships, not the text that arrived**: --pin-wheels
        # rewrites vendor pins into download.pytorch.org addresses after lock_text
        # was read, and a disclosure computed from the stale copy would omit the
        # very host every pinned nest is guaranteed to contact (found 2026-09-06,
        # the day pinning stopped being optional for such locks).
        _hosts = lock_hosts(lock_text_for_audit)
        # Which index every still-bare vendor pin came from (format 2.11). Pinning
        # rewrites such a line into a direct wheel URL and that line needs nothing
        # here; what is left over is `torch==2.11.0+cu128` -- a name and a version no
        # public index serves, with no address anywhere in the nest until now. Read
        # off the installed package's own direct_url.json, or off this environment's
        # index config; **never worked back from the version suffix** (see
        # envlock.local_version_sources for why that route does not exist).
        _lvs_sp = _site_packages_for(root, env_python)
        # Two places a config file can sit: the environment root we were handed, and
        # the virtual environment the packages actually live in. Looked at in that
        # order -- a nest is packed from the tree the user points at, and that is where
        # a studio's own index setting is kept.
        _lvs_roots = [root] + ([env_dir_of(_lvs_sp)] if _lvs_sp is not None else [])
        _lvs = local_version_sources(lock_text_for_audit, _lvs_sp, *_lvs_roots)
        if _lvs:
            manifest["python_lock"]["local_version_sources"] = _lvs
            # Disclosure obligation of 2.11: these are hosts a rebuild will reach out
            # to, so they belong in the same list as the ones named inside the lock.
            # Recorded beside the lock rather than inside it, they would otherwise be
            # contacted without ever appearing on the disclosure surface -- and the
            # escape hatch's source gate reads the lock text, so an index only the
            # manifest knows about must be visible to the reader some other way.
            _hosts = sorted(set(_hosts) | set(lock_hosts(
                "\n".join(f"--index-url {v['index_url']}" for v in _lvs.values())
            )))
        if _hosts:
            manifest["python_lock"]["hosts"] = _hosts
        if pinned:
            # Write this field only when something was really rewritten.
            manifest["python_lock"]["pinned_wheel_urls"] = len(pinned)
        if pl.get("wheels_archived"):
            manifest["python_lock"]["wheels_archived"] = True
        # Contested modules (format 2.8): several packages in this lock write the
        # same folder, and the installer decides who writes last -- **not stably**
        # (measured 2026-08-17: one lock, one machine, a different survivor on
        # back-to-back installs). Only this machine knows which copy the working
        # run used, so record it: the file as installed and which package it
        # came from. Nothing found -> nothing written; the note says why.
        _sp = _site_packages_for(root, env_python)
        if _sp is not None:
            _won, _notes = contested_winners(_sp, lock_text_for_audit)
            if _won:
                rt = dict(manifest.get("runtime") or {})
                rt.setdefault("contested_modules", _won)
                manifest["runtime"] = rt
            warnings.extend(_notes)
        # Do not add convenience fields here. The manifest schema forbids any key
        # it does not define, so a new field is a format change: version bump
        # plus a human running the escape hatch end to end by hand. A CUDA tag,
        # for instance, is derivable from the dependency list the restore side
        # already holds — not worth a manual verification.

    # -- assets: parallel stream-hash + blob --
    files = spec.get("files", [])

    def do_file(fspec: dict) -> dict | None:
        # A file may live in one of two model-cache roots outside the environment
        # root. **This stays an allowlist and must never become a denylist**: a
        # training run writes the user's own datasets into the same caches, and
        # the two ways of being wrong cost very different amounts — a missing
        # allowlist entry loses one file from the rebuild, which the user
        # notices; a missing denylist entry uploads their dataset, which nobody
        # notices.
        froot = fspec.get("root", "env")
        why = _bad_root_entry(fspec)
        if why is not None:
            warnings.append(
                f"Left out of the nest — it names {why}. Only files under the environment "
                f"itself, plus the two known model-cache folders, can be packed."
            )
            return None
        if fspec.get("source_path"):
            # pack-spec 1.3: read the bytes from a second tree, land them at `path`.
            # `root`/`path` still decide where a rebuild writes, so the allowlist
            # check above keeps its full meaning.
            src = _spec_source(root, fspec, fspec["path"])
        elif froot == "env":
            src = root / fspec["path"]
            if not src.is_file():
                src = _resolve_via_extra_model_paths(root, fspec["path"]) or src
        else:
            src = resolve_file_root(froot, root) / fspec["path"]
        if not src.is_file():
            raise PackError(f"Asset file is missing: {src}", exit_code=int(ExitCode.USAGE))
        if dry_run:
            h, size = _sha256_stream(src, cache)
            blob = {"sha256": h, "size_bytes": size}
        else:
            blob = place(src, hardlink=True)
        # Cross-check against the hash capture measured. The window between
        # capture and pack is real (a download finishing, a model swapped by
        # hand), and without this the nest verifies green byte for byte while
        # holding a file the recipe was never proven against. Both now read
        # through one hash record, so what watches this window on a first pack
        # is the size/time/inode triple -- either event moves one of the three
        # and forces the re-read; `--full-rehash` forces it unconditionally.
        want = fspec.get("expected_sha256")
        if want and want != blob["sha256"]:
            raise PackError(
                f"This is not the file that was captured: {fspec['path']}. Captured "
                f"{want[:12]}…, on disk now {blob['sha256'][:12]}… — it was replaced or "
                "rewritten in between, so the run this nest is built from never used these "
                "bytes. Capture again to pack what is there now; if you swapped it on "
                "purpose, delete that file's expected_sha256 line from the spec.",
                exit_code=int(ExitCode.S2_HASH_MISMATCH),
            )
        # Bad-bytes health check: a hand-written spec bypasses capture entirely,
        # so this is the last gate asking "do these bytes look like complete
        # weights". Report only, never block — the user may genuinely want to
        # store a partial file.
        bad = probe_model_bytes(src, blob["size_bytes"], logical_name=fspec["path"])
        if bad:
            warnings.append(f"Doesn't look like a complete file: {bad}")
        # A model cache names its big files after their own sha256, so that name
        # is a free second opinion on the bytes we just hashed. It stays a second
        # opinion: the address recorded below is always the one we computed, never
        # a name read off the disk. Names of any other length in that folder are a
        # different digest and are ignored, not converted.
        claimed = cache_stated_sha256(src.resolve() if src.is_symlink() else src)
        if claimed and claimed != blob["sha256"]:
            warnings.append(
                f"{fspec['path']}: the model cache holds this file under the name "
                f"{claimed}, but its bytes are {blob['sha256']}. We store the bytes "
                f"that are here, so this nest is exact; the cached copy has changed "
                f"since it was downloaded, so download it again before your next run."
            )
        # Format 2.4: copy across what the file's own header says its base model
        # was. A transcription, not our judgement -- measured to match the fed
        # file's whole-file sha256 character for character. Same header read as
        # above, so it costs nothing extra. Read **before** the licence lookup:
        # that lookup names the base in what it tells the user, and the header is
        # often the only place the name exists.
        base = declared_base_model(src)
        entry = {
            "path": fspec["path"],
            "blob": blob,
            # **Actually do the lookup.** When it finds nothing the lookup
            # returns None and _license_of keeps what the user wrote, marked as
            # their claim — packing must never fail because a lookup failed.
            "license": _license_of(
                _declare_mine(
                    fspec | {"blob": blob, "declared_base_model": base}, mine, warnings
                ), warnings,
                license_lookup=None if no_licence_lookup else (
                    lambda fs: _licence_lookup(fs, client=client)
                ),
            ),
        }
        # Format 2.2: does loading this file execute code? Reading the file
        # header answers it at zero cost. If we cannot tell, we leave the field
        # out — skip honestly, never invent (same discipline as the .so
        # architecture probe).
        ser = serialization_of(src, logical_name=fspec["path"])
        if ser:
            entry["serialization"] = ser
        if base:
            entry["declared_base_model"] = base
        if froot != "env":
            entry["root"] = froot
        for k in ("origin_url", "kind", "sources"):
            if k in fspec:
                entry[k] = fspec[k]
        inventory.append(
            {"role": "asset", "path": fspec["path"], **blob, "kind": fspec.get("kind", "other")}
        )
        if tracker:
            tracker.advance("P1", blob["size_bytes"], fspec["path"])
        return entry

    if files:
        jobs = min(8, (os.cpu_count() or 4))
        with ThreadPoolExecutor(max_workers=jobs) as ex:
            manifest["files"] = [e for e in ex.map(do_file, files) if e is not None]
        _attach_licence_texts(manifest, place, dry_run, root)

    # The escape hatch travels with the nest (format 2.3). Doing it **after** the
    # licence-text step is deliberate: it is our own script, and it should not
    # drag a copy of the Apache text into the user's nest as a side effect.
    _attach_escape_hatch(manifest, place, dry_run, warnings)

    # Every recipe found while looking for evidence, not just the one driving
    # the check above: a few dozen run at a few KB each, so there is no reason
    # to make the caller pick one to keep.
    _attach_recipes(manifest, place, dry_run, work, spec.get("_extra_recipes") or [])

    # -- adapters.comfyui.workflow --
    _wf_json: dict | None = None  # the recipe's own JSON, for the invariant sweep below
    cui = spec.get("adapters", {}).get("comfyui")
    if cui and (cui.get("workflow_path") or "workflow_inline" in cui):
        if cui.get("workflow_path"):
            wf_src = root / cui["workflow_path"]
            if not wf_src.is_file():
                raise PackError(f"Workflow file is missing: {wf_src}", exit_code=int(ExitCode.USAGE))
        else:
            # Recovered from a picture's own text block — no standalone file to
            # hash, so write the bytes we already have and hash those instead.
            wf_src = work / "recipe-verified.json"
            wf_src.write_text(
                json.dumps(cui["workflow_inline"], ensure_ascii=False, indent=2), encoding="utf-8"
            )
        if dry_run:
            h, size = _sha256_stream(wf_src)
            wf_blob = {"sha256": h, "size_bytes": size}
        else:
            wf_blob = place(wf_src, hardlink=bool(cui.get("workflow_path")))
        # Record where the recipe lived (format 2.6). Until 2.6 this path was read,
        # used to find the bytes and then dropped, so restore had nowhere to put the
        # file back and parked it in a staging folder — which breaks "restore, change
        # one thing, pack again" at the first step. Writing it costs nothing here; the
        # obligations on the reading side are in the schema.
        comfy: dict = {"workflow": wf_blob}
        if cui.get("workflow_path"):
            comfy["workflow_path"] = str(cui["workflow_path"])
        for k in ("workflow_name", "verified_run"):
            if k in cui:
                comfy[k] = cui[k]
        manifest.setdefault("adapters", {})["comfyui"] = comfy
        # Keep the recipe's own JSON for the invariant sweep at the end (I-3
        # reads it). Unparseable or non-dict content is skipped honestly there.
        with contextlib.suppress(OSError, json.JSONDecodeError, UnicodeDecodeError):
            _parsed = json.loads(wf_src.read_text(encoding="utf-8"))
            if isinstance(_parsed, dict):
                _wf_json = _parsed

    # A training-side adapter is pure data (it names which files[] entries are
    # the recipe, plus the evidence of the run that worked); there is nothing to
    # place as a blob, so it passes through as-is. Unknown adapters pass through
    # too — format 2.0 is open under control: anything the core does not
    # recognise travels as an opaque object rather than being dropped here on the
    # user's behalf.
    for name, block in (spec.get("adapters") or {}).items():
        if name == "comfyui":
            continue
        manifest.setdefault("adapters", {})[name] = block

    # -- evidence: was this nest ever seen to work? (format 2.11) --------------
    # **Written only when somebody actually looked.** The two inference routes look --
    # that is their whole job -- and hand their verdict down here; a hand-written spec
    # (`--spec`) does not, and gets no block at all. That asymmetry is the field's whole
    # point: absent means "nobody looked", `none` means "looked, and there was nothing",
    # and a reader that collapses the two turns an unasked question into a clean answer.
    # So there is deliberately no `else` here filling in `none` for the quiet case --
    # that would be exactly the invention this field exists to prevent.
    _ev = spec.get("_evidence")
    if isinstance(_ev, dict) and _ev.get("source"):
        manifest["evidence"] = {
            k: v for k, v in _ev.items() if k in ("source", "note") and v
        }

    # -- invariant sweep, record layer (2026-09-06). One judgment, every
    # consumer: `renest lint` reads the same functions off renest.invariants, so
    # the two sides cannot drift on what counts as a violation. Pack is not the
    # police (packing preserves the scene): nothing here fails the pack.
    # Two invariants are deliberately not re-said here: I-2 already hard-refused
    # at archive time through the same module, and I-1 is voiced above by the
    # family-split lock warnings, which carry family-specific advice the generic
    # record cannot (--pin-wheels helps a vendor +cuNNN build and is exactly
    # wrong for a distro- or image-owned one).
    from .invariants import check_all as _check_invariants

    warnings.extend(
        v.message
        for v in _check_invariants(manifest, "", (), workflow=_wf_json)
        if v.code in ("workflow-ref-missing", "model-license-missing", "base-image-missing")
    )

    return manifest, inventory


def _locate_comfyui_dir(root: Path, comfyui_dir: str | os.PathLike[str] | None) -> Path:
    """Find the ComfyUI directory under (or at) ``root`` for capture. Common case:
    the env root holds ``ComfyUI/``. Falls back to ``root`` itself when it looks
    like a ComfyUI tree (has ``models/`` or ``custom_nodes/``), then to any such
    child. Never guesses beyond a directory-shape check."""
    if comfyui_dir:
        return Path(comfyui_dir).resolve()
    cand = root / "ComfyUI"
    if cand.is_dir():
        return cand.resolve()
    if (root / "models").is_dir() or (root / "custom_nodes").is_dir():
        return root  # root itself is the ComfyUI tree
    for child in sorted(p for p in root.iterdir() if p.is_dir()):
        if (child / "models").is_dir() or (child / "custom_nodes").is_dir():
            return child.resolve()
    return cand.resolve()  # default; capture will report the missing tree as a gap


def _fill_python_lock_and_version(spec: dict, env_root: Path, cdir: Path, env_python) -> None:
    """Wire in a real python lock/version when one can be found; drop the
    placeholder rather than invent one. Shared by both inference paths below
    so a fix to one covers the other.
    """
    lock = next((n for n in LOCK_CANDIDATES if (env_root / n).is_file()), None)
    if lock:
        spec["python_lock"] = {"tool": "uv", "lockfile_path": lock}
    else:
        # With no lock file, fall back to **asking the running Python itself**.
        # This invents nothing: what is installed in that interpreter is what the
        # successful run used. The ComfyUI desktop build ships no lock file at
        # all, so without this path its nests carry no dependency list.
        exe = env_python or find_env_python(venv_python_candidates(cdir, env_root))
        if exe:
            spec["python_lock"] = {"tool": "uv", "from_environment": {"python": str(exe)}}
        else:
            spec.pop("python_lock", None)  # genuinely no trace: skip honestly, never guess

    # Python version: if we can ask for it, don't leave it for a human to fill.
    # Left as the template placeholder, pack still exits 0 and produces a nest
    # that is guaranteed to die at the rebuild's dependency stage — a nest that
    # could never be restored. The interpreter was already located above.
    rt = spec.setdefault("runtime", {})
    if str(rt.get("python_version", "")).startswith("<"):
        exe2 = env_python or find_env_python(venv_python_candidates(cdir, env_root))
        ver = _python_version_of(exe2) if exe2 else None
        if ver:
            rt["python_version"] = ver
        else:
            rt.pop("python_version", None)


def _iso_utc(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_record(cache: HashCache | None, env_root: Path, full_rehash: bool) -> HashCache:
    """The one record capture and pack share, wherever it came from."""
    if cache is None:
        return HashCache(env_root / HASH_CACHE_REL, trust=not full_rehash)
    cache.attach(env_root / HASH_CACHE_REL)
    return cache


def infer_spec(
    target: str | os.PathLike[str],
    workflow: dict | str | os.PathLike[str],
    *,
    comfyui_dir: str | os.PathLike[str] | None = None,
    program_dir: str | os.PathLike[str] | None = None,
    env_python: str | os.PathLike[str] | None = None,
    full_rehash: bool = False,
    persist_hashes: bool = True,
    hash_cache: HashCache | None = None,
) -> tuple[Path, dict, dict]:
    """Reverse-infer a pack-spec (draft) from a ComfyUI ``target`` + a run-through
    ``workflow`` (inline API-format dict, or a path to one) via :func:`capture`.

    Capture and the pack that follows share one record of what has been hashed,
    so a weight is read once and not twice; ``full_rehash`` reads regardless, and
    ``persist_hashes=False`` keeps a dry run from writing anything. Pass
    ``hash_cache`` to hand that record in — a dry run persists nothing, so
    sharing the object is the only way the pack after it skips a second read.

    Returns ``(env_root, spec, capture_report)`` where ``env_root`` is the root
    the spec's paths are relative to (= the ComfyUI dir's parent). The workflow is
    linked into the spec only when it lives inside ``env_root``; a real python
    lock (``LOCK_CANDIDATES``) is wired in when present, else ``python_lock`` is
    dropped (honest — capture never invents it). This feeds pack's dry_run
    preview + the "unreferenced big file" hint; it is not a new pack mode.

    Named a workflow already? Use this. Nothing to name — several past runs, or
    none — is :func:`infer_spec_current_state` instead, which never asks which
    one.
    """
    root_in = Path(target).resolve()
    cdir = _locate_comfyui_dir(root_in, comfyui_dir)
    env_root = cdir.parent

    if isinstance(workflow, dict):
        wf_json, wf_rel = workflow, None
    else:
        wf_path = Path(workflow)
        wf_json = json.loads(wf_path.read_text(encoding="utf-8"))
        try:
            wf_rel = wf_path.resolve().relative_to(env_root).as_posix()
        except ValueError:
            wf_rel = None  # workflow outside the env → capture leaves a placeholder

    hashes = _hash_record(hash_cache, env_root, full_rehash)
    result = capture(wf_json, cdir, workflow_relpath=wf_rel, hash_cache=hashes,
                     program_dir=Path(program_dir).resolve() if program_dir else None)
    if persist_hashes:
        hashes.save()
    spec, report = result.pack_spec, result.report
    _fill_python_lock_and_version(spec, env_root, cdir, env_python)

    wf_in_spec = spec.get("adapters", {}).get("comfyui", {}).get("workflow_path", "")
    if wf_in_spec.startswith("<"):  # unresolved placeholder → drop, don't pack a non-file
        spec.pop("adapters", None)

    return env_root, spec, report


def infer_spec_current_state(
    target: str | os.PathLike[str],
    *,
    comfyui_dir: str | os.PathLike[str] | None = None,
    program_dir: str | os.PathLike[str] | None = None,
    env_python: str | os.PathLike[str] | None = None,
    full_rehash: bool = False,
    persist_hashes: bool = True,
    hash_cache: HashCache | None = None,
) -> tuple[Path, dict, dict]:
    """Pack the environment as it stands, without asking which run to trust.

    ``full_rehash`` / ``persist_hashes`` carry the same meaning as in
    :func:`infer_spec`: one shared record of what has been hashed, so the pack
    that follows does not read the same weights a second time.

    Verified evidence comes only from pictures ComfyUI itself wrote under
    ``output/`` — a run that actually finished. A workflow saved under
    ``user/*/workflows/`` but never run still drives the file-completeness
    check (so the disclosure is still useful) but is never treated as
    verified: a mid-debugging environment must still pack cleanly, it just
    carries no proof it ever produced anything. Every recipe found, run or
    not, travels with the nest (:mod:`renest.verified`); picking one to drive
    the check is internal, never a question put to the caller.
    """
    root_in = Path(target).resolve()
    cdir = _locate_comfyui_dir(root_in, comfyui_dir)
    env_root = cdir.parent

    from .verified import scan_comfyui_output, scan_saved_workflows

    evidence = scan_comfyui_output(cdir / "output")
    saved = scan_saved_workflows(cdir)
    # A file ComfyUI's UI saves is the *editor's* export ("nodes": [...] plus
    # canvas positions), not the API-format graph capture() reads — real
    # machine data confirmed every saved-workflow file is this shape. Only an
    # API-format one can drive the completeness check; a UI-format file still
    # travels with the nest (below), it just cannot be the driver.
    driving = evidence.most_recent or next(
        (r for r in saved if not isinstance(r.workflow.get("nodes"), list)), None
    )

    # No evidence at all: hand capture() a no-op node (a built-in with no file
    # reference) purely so it has something to walk — an empty workflow is
    # refused outright, and this contributes no refs, no unknown classes, and
    # so no per-plugin exclusion, i.e. exactly "whole folder, nothing singled
    # out" (COMFYUI_CORE_EXCLUDE only).
    wf_json = driving.workflow if driving else {"1": {"class_type": "KSampler", "inputs": {}}}
    wf_rel = None
    if driving is not None and driving.source_path is not None:
        try:
            wf_rel = driving.source_path.resolve().relative_to(env_root).as_posix()
        except ValueError:
            wf_rel = None

    hashes = _hash_record(hash_cache, env_root, full_rehash)
    result = capture(wf_json, cdir, workflow_relpath=wf_rel, hash_cache=hashes,
                     program_dir=Path(program_dir).resolve() if program_dir else None)
    if persist_hashes:
        hashes.save()
    spec, report = result.pack_spec, result.report
    _fill_python_lock_and_version(spec, env_root, cdir, env_python)

    cui = spec.get("adapters", {}).get("comfyui")
    if driving is None:
        spec.pop("adapters", None)
    elif cui is not None:
        if wf_rel is None:
            # No standalone file to point at (recovered from a picture's own
            # text block) — carry the recipe inline instead of a path nobody
            # can follow.
            cui.pop("workflow_path", None)
            cui["workflow_inline"] = driving.workflow
        if evidence.verified:
            cui["verified_run"] = {
                "queue_completed_at": _iso_utc(evidence.most_recent.mtime),
                # Format 2.11: the strongest claim in the format states its own rung
                # rather than leaving a reader to know the convention. A recipe read out
                # of a file the finished run wrote for itself is `observed_run` -- the
                # one rung a consumer is allowed to refuse on.
                "evidence_source": "observed_run",
            }

    # **Whether this nest carries proof it ever ran** (format 2.11). This route looked
    # -- that is the whole of what it does -- so it may say `none` when it found
    # nothing, and `none` is a different statement from saying nothing at all. Before
    # 2.11 both came out as an absent `verified_run` block, so a nest packed as it
    # stands (`--auto`) was indistinguishable downstream from one packed off a run
    # somebody watched finish. Written from the same `evidence` object the disclosure
    # line below is written from, so the manifest and the words on the screen cannot
    # disagree.
    spec["_evidence"] = (
        {"source": "observed_run"}
        if evidence.verified
        else {
            "source": "none",
            "note": "Packed as it stands: no finished run with its recipe attached was "
                    "found in this environment.",
        }
    )

    extra = [r.workflow for r in (*evidence.recipes, *saved) if r is not driving]
    if extra:
        spec["_extra_recipes"] = extra
    report["unreadable_images"] = [str(p) for p in evidence.unreadable]
    # **Say which run this nest will re-run, when there was more than one to choose from.**
    # Every recipe found travels with the nest either way, so nothing is lost -- but the
    # one picked here is the one a rebuild runs again and the one this nest claims worked,
    # and picking it silently is how someone ends up shipping a different run than they
    # meant. The default (the most recent finished run) stays; --workflow overrides it.
    if len(evidence.recipes) > 1 and driving is not None:
        import datetime as _dt
        when = _dt.datetime.fromtimestamp(driving.mtime, _dt.UTC).strftime("%Y-%m-%d %H:%M")
        where = str(driving.source_path) if driving.source_path else "a picture it produced"
        report["gaps"].append(
            f"This environment holds {len(evidence.recipes)} finished runs. The most recent "
            f"one ({when} UTC, from {where}) is the one recorded as having worked, and the "
            f"one a rebuild runs again. All of them travel with the nest either way. "
            f"To pick a different one, pass --workflow with that recipe."
        )

    # Tell the caller which of the two nests they are about to get -- said once,
    # up front, not left for them to notice missing on the other end.
    if evidence.verified:
        report["gaps"].append(
            "This environment has produced at least one picture with its recipe attached, "
            "so this nest carries a verified run: restoring it will re-run that recipe and "
            "require a picture to come out."
        )
    else:
        report["gaps"].append(
            "This environment carries no picture with a recipe attached, so this nest packs "
            "with no verified run. Everything still restores exactly, byte for byte -- "
            "restoring it just will not try to re-render anything, since nothing here is "
            "confirmed to have worked yet."
        )

    return env_root, spec, report




#: Fields that make the **whole nest worthless if left as a blank**
#: (``<fill in ...>``), so an unfilled one is refused rather than shipped.
_MUST_BE_FILLED = {
    "runtime.python_version": "uv builds the environment from it on restore; leave "
                              "the placeholder in and the dependency step is certain "
                              "to fail (exit code 34)",
    # Don't add the base_image fields here: the schema marks them required AND
    # format-restricted (`^sha256:[a-f0-9]{64}$`), while a container cannot see
    # its own image name while packing, so gating on them refuses every
    # environment-inferred pack. A rebuild does not need them.
}

#: ``code_deps[].commit`` is optional in the schema, but once written it must be
#: 40 hex characters — so when it is unknown, **omit it entirely**. A "please
#: fill this in" placeholder produces archives that fail our own checks.
_DROP_IF_UNFILLED_IN_DEPS = ("commit", "repo_url")

#: Optional top-level fields, same discipline: unfilled means not written.
#: Storing the ``<give it a name …>`` hint would show the recipient a hint
#: sentence as the nest name, and `renest lint` flags it as uncleaned
#: placeholder text. **Do not sweep ``entrypoint.redactions[].placeholder`` in
#: here** — holding a placeholder note for whoever rebuilds is that field's job.
_DROP_IF_UNFILLED_TOPLEVEL = ("name", "post_install")


def _refuse_unresolved_placeholders(manifest: dict) -> None:
    """One last gate before a nest goes out: refuse to ship while a critical
    field is still a fill-in-yourself blank.

    Without this, a nest with `runtime.python_version` left as
    ``<fill in python --version…>`` uploads, gets its hand-off code signed, and
    only dies at the dependency step on a new machine. **Refuse on the spot
    rather than produce something that looks successful and is worthless.**
    """
    def _unfilled(v: object) -> bool:
        """A blank comes in two shapes: the whole string starts with `<`, or it
        looks like `sha256:<…>`."""
        return isinstance(v, str) and ("<" in v)

    bad = []
    for dotted, why in _MUST_BE_FILLED.items():
        node: object = manifest
        for part in dotted.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        if _unfilled(node):
            bad.append(f"{dotted} is still a blank ({str(node).strip()[:60]}…) — {why}")
    # An optional field that was never filled in gets **removed** (keeping the
    # placeholder is what makes the archive invalid).
    for key in _DROP_IF_UNFILLED_TOPLEVEL:
        if _unfilled(manifest.get(key)):
            manifest.pop(key, None)
    for dep in manifest.get("code_deps") or []:
        if isinstance(dep, dict):
            for key in _DROP_IF_UNFILLED_IN_DEPS:
                if _unfilled(dep.get(key)):
                    dep.pop(key, None)
    if bad:
        raise NestFailure(
            "P2",
            ErrorClass.UNKNOWN,
            "This nest is not finished: some fields are still the fill-in-yourself "
            "placeholders, and a nest packed like that cannot be restored. "
            + "; ".join(bad)
            + ". Pass --spec with those filled in, or --env-python so we can read the "
              "version off the interpreter itself.",
            exit_code=int(ExitCode.USAGE),
        )


def _python_version_of(exe) -> str | None:
    """Ask the interpreter for its own version (shaped like ``3.11.9``). Returns
    None when it will not answer — **never guesses**."""
    import subprocess as _sp
    try:
        r = _sp.run([str(exe), "-c",
                     "import sys;print('.'.join(map(str,sys.version_info[:3])))"],
                    capture_output=True, text=True, timeout=30, check=False)
        v = (r.stdout or "").strip().splitlines()
        return v[-1] if r.returncode == 0 and v else None
    except (OSError, _sp.SubprocessError):
        return None


def pack(
    root: str | os.PathLike[str],
    spec: dict | None = None,
    out: str | os.PathLike[str] | None = None,
    *,
    dry_run: bool = False,
    no_hardlink: bool = False,
    env_python: str | None = None,
    no_fingerprint: bool = False,
    workflow: dict | str | os.PathLike[str] | None = None,
    comfyui_dir: str | os.PathLike[str] | None = None,
    program_dir: str | os.PathLike[str] | None = None,
    auto: bool = False,
    framework: str | None = None,
    run_record: dict | None = None,
    uploader: Uploader | None = None,
    emitter: EventEmitter | None = None,
    # On by default since 0.1.13 (decided 2026-09-06): the one online pack step.
    # A vendor-only pin (torch==…+cuXXX) shipped bare killed the first real 64 GB
    # restore after the downloads — so the exact download address is recorded by
    # default, and packing with no network is the explicit choice (--offline),
    # which archives faithfully and marks the nest as not rebuildable elsewhere.
    pin_wheels: bool = True,
    client: httpx.Client | None = None,
    i_know: bool = False,
    no_licence_lookup: bool = False,
    mine: set[str] | None = None,
    full_rehash: bool = False,
    hash_cache: HashCache | None = None,
    # Said while the user can still act on it. The report's findings are read
    # after the run is over, which is too late for "this needs twice the disk".
    notice: Callable[[str], None] | None = None,
) -> PackReport:
    """Pack a working environment into a nest. Never raises for a pack failure —
    the report's ``exit_code`` carries the verdict.

    Four inputs, one output form: a ready ``spec`` (pack-spec); ``spec=None``
    with a ``workflow`` — then :func:`infer_spec` reverse-infers the spec from
    ``root`` + workflow (the image-generation side, one named recipe); ``auto``
    with no ``workflow`` — then :func:`infer_spec_current_state` packs the
    environment as it stands, without asking which run to trust; or
    ``framework`` + ``run_record`` — then :func:`renest.training.capture_training`
    reverse-infers it from the record of the training run that worked (the
    fine-tuning side). The "unreferenced big file" hint and every capture gap
    land in ``report.findings`` (advisory, never blocks).

    ``hash_cache`` lets a caller hand in the record of what has already been
    read. The ComfyUI panel needs it: its confirm page runs a dry run first, and
    a dry run writes nothing to the user's folder, so without a shared object
    the pack behind the button reads every weight a second time (measured
    2026-08-30 through ``renest serve``: 2.00x)."""
    root = Path(root).resolve()
    # Kept for the manifest stage too, not just for capture: with a spec handed in
    # ready-made, capture never runs, and this is the only thing that says which
    # tree the extension wrote its run record in.
    _program_dir = Path(program_dir).resolve() if program_dir else None
    report = PackReport(dry_run=dry_run)
    warnings: list[str] = []
    # Reasons this nest, as packed, cannot be rebuilt elsewhere (report layer
    # only; folded into report.restorable below). Filled by the offline branch.
    unrestorable: list[str] = []
    # One record of what has been read, held across capture and the pack that
    # follows. It gets its file below, once the environment root is known.
    if hash_cache is None:
        hash_cache = HashCache(None, trust=not full_rehash)
    elif full_rehash:
        # A handed-in record must not quietly outrank "read everything again".
        hash_cache.trust = False

    if spec is None and framework is not None:
        # Fine-tuning side: reverse-infer the spec from the execution record of
        # the run that worked.
        from .training import capture_training

        try:
            res = capture_training(framework, run_record or {}, root)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            report.exit_code = int(ExitCode.USAGE)
            report.findings = [f"Couldn't work out what to pack from that run: {e}"]
            return report
        spec, cap_report = res.pack_spec, res.report
        report.capture_report = cap_report
        # Report truthfully whatever could not be collected; never skip silently.
        warnings.extend(cap_report.get("gaps", []))
    if spec is None and workflow is None and auto:
        try:
            root, spec, cap_report = infer_spec_current_state(
                root, comfyui_dir=comfyui_dir, program_dir=program_dir,
                env_python=env_python,
                full_rehash=full_rehash, persist_hashes=not dry_run,
                hash_cache=hash_cache,
            )
        except (OSError, ValueError, json.JSONDecodeError) as e:
            report.exit_code = int(ExitCode.USAGE)
            report.findings = [f"Couldn't work out what to pack from this folder: {e}"]
            return report
        report.capture_report = cap_report
        warnings.extend(cap_report.get("gaps", []))
    if spec is None:
        if workflow is None:
            report.exit_code = int(ExitCode.USAGE)
            report.findings = [
                "pack needs a pack-spec, a workflow so we can work out what to pack from your "
                "ComfyUI folder, --auto to pack it as it stands without naming one, or "
                "--framework + --run-record for a training setup"
            ]
            return report
        try:
            root, spec, cap_report = infer_spec(
                root, workflow, comfyui_dir=comfyui_dir, program_dir=program_dir,
                env_python=env_python,
                full_rehash=full_rehash, persist_hashes=not dry_run,
                hash_cache=hash_cache,
            )
        except (OSError, ValueError, json.JSONDecodeError) as e:
            report.exit_code = int(ExitCode.USAGE)
            report.findings = [f"Couldn't work out what to pack from this folder: {e}"]
            return report
        report.capture_report = cap_report
        # Pass on **everything** capture could not do, not just the "big files
        # installed but never used" hint: dropping "we can't tell where this
        # custom node came from, so it is not in the nest" hands the user an
        # inventory that looks complete and fails at rebuild time.
        warnings.extend(cap_report.get("gaps", []))

    # -- Are we ourselves installed in the environment being packed? -----------
    # The one wrong-but-natural move a newcomer makes: venv active, mental model
    # "back this app up", so `pip install renest` / `uv pip install renest` goes
    # straight into the environment about to be captured. By pack time any
    # displacement has already happened, so nothing here blocks — but it must be
    # said out loud, and the report must carry the fact as data, not prose only.
    _env_sp = _site_packages_for(root, env_python, program_dir=_program_dir)
    _self_at = self_installed_in_env(env_dir_of(_env_sp) if _env_sp is not None else None)
    if _self_at is not None:
        report.renest_in_packed_env = True
        warnings.append(
            f"renest itself is installed inside the environment being packed "
            f"({_self_at}). Installing it there can displace libraries this "
            f"environment's app was already using with the versions our own "
            f"dependencies want — `uv pip install` does this without a word — so "
            f"the dependency list going into this nest may describe an environment "
            f"your workflow never actually ran on. Packing continues: the archive "
            f"is still a faithful record of this machine as it stands. Next time, "
            f"install the tool with `uv tool install renest` — that gives it an "
            f"environment of its own, away from the ones it packs."
        )

    # -- Never quietly produce a nest that is doomed not to rebuild ------------
    # With no interpreter found (no .venv, no --env-python) the python version is
    # dropped, yet the nest is still produced and exit code 0 still says
    # "✓ Packed" — while the restore side refuses that manifest outright. The
    # user believes it is stored and finds out otherwise once the original
    # environment is gone, so say it here, and say what to do about it.
    rt_ver = str((spec or {}).get("runtime", {}).get("python_version", "") or "")
    if not rt_ver or rt_ver.startswith("<"):
        warnings.append(
            "We can't tell which Python version this setup runs on (no .venv found and no "
            "--env-python given), so the nest goes out without it. Rebuilding it will stop "
            "and ask for that version. To fill it in now, pack again with "
            "`--env-python /path/to/python` — the interpreter you start the app with. "
            "(In ComfyUI, the Renest panel sends this by itself.)"
        )

    # -- Hard stop on credential-shaped content. **Before a single byte is
    #    written.** ---------------------------------------------------------
    # Packing is the irreversible step: once the bytes are uploaded, withdrawing
    # only withdraws the index entry. So this gate must sit **before** the
    # dry_run branch — even a dry run has to tell the user "packing like this
    # would carry your keys out".
    secret_hits, suspicious = _scan_spec_for_secrets(root, spec or {})
    for s in suspicious:
        warnings.append(
            f"{s} is going into the nest. We did not find a credential in it, but files with "
            f"that name usually hold one — open it before you hand this nest to anyone"
        )
    if secret_hits and not i_know:
        report.exit_code = int(ExitCode.USAGE)
        report.ok = False
        report.findings = warnings + [
            "Stopped: this looks like it would pack your own credentials.",
            *[f"  {h.human()}" for h in secret_hits[:10]],
            *([f"  …and {len(secret_hits) - 10} more"] if len(secret_hits) > 10 else []),
            "A nest carries your code folder as-is, so whatever is in there travels with it — "
            "to anyone you hand it to. Remove them (or point them at an environment variable) "
            "and pack again.",
            "If you are certain these are not real credentials, pack again with --i-know. "
            "That gets you past this check only; handing the nest off will still ask once more.",
        ]
        return report
    if secret_hits and i_know:
        # The gate was stepped past, but **it must stay in the report** — the
        # hand-off surface asks once more, and this is what it goes on.
        report.i_know_used = True
        warnings.append(
            f"--i-know was used to pack past {len(secret_hits)} suspected credential(s). "
            f"You will be asked to confirm again before this nest can be handed to anyone"
        )

    out = Path(out).resolve() if out is not None else None
    if not dry_run and out is None:
        report.exit_code = int(ExitCode.USAGE)
        report.findings = warnings + ["A real pack needs an output folder (out)"]
        return report

    def log(msg: str, **extra: Any) -> None:
        if emitter is not None:
            emitter.log(msg, **extra)

    # Repeat packs of the same folder read only what moved. A dry run reads the
    # record but never writes it — a dry run changes nothing on disk. (A no-op
    # when capture already attached it: same object, same file.)
    hash_cache.attach(root / HASH_CACHE_REL)

    try:
        with tempfile.TemporaryDirectory() as _work:
            work = Path(_work)
            if dry_run:
                place: Callable[..., dict] = lambda src, hardlink=True: {}  # noqa: E731 (unused in dry_run)
                manifest, inventory = _build_manifest(
                    root, spec, place=place, work=work, env_python=env_python,
                    no_fingerprint=no_fingerprint, warnings=warnings, dry_run=True,
                    unrestorable=unrestorable,
                    pin_wheels=pin_wheels, client=client, no_licence_lookup=no_licence_lookup,
                    mine=mine, cache=hash_cache, program_dir=_program_dir,
                )
                # The same last gate as a real pack. A dry run that waves an
                # unresolved placeholder through lets "the dry run was green"
                # pass for a safety statement, while the real pack is certain to
                # refuse the very same manifest — one rented machine burned on
                # exactly that on 2026-09-06. A dry run must predict the real
                # pack, not flatter it.
                _refuse_unresolved_placeholders(manifest)
                report.nest_id = manifest["id"]
                report.manifest = manifest
                report.inventory = inventory
                report.blob_count = len(inventory)
                report.total_bytes = sum(i.get("size_bytes", i.get("approx_bytes", 0)) for i in inventory)
                report.findings = warnings
                report.restorable = not unrestorable
                report.unrestorable_reasons = list(unrestorable)
                report.ok = True
                report.exit_code = int(ExitCode.OK)
                log(f"Dry run: {report.blob_count} item(s), {report.total_bytes} bytes in total")
                return report

            out_blobs = out / "blobs" / "sha256"
            out_blobs.mkdir(parents=True, exist_ok=True)
            copied_instead: list[str] = []

            def _note_copy(path: Path, err: OSError) -> None:
                if not copied_instead:
                    copied_instead.append(f"{path} ({err.strerror or err})")

            place = lambda src, hardlink=True: _place_blob(  # noqa: E731
                src, out_blobs, hardlink and not no_hardlink, cache=hash_cache,
                on_copy_fallback=None if no_hardlink else _note_copy,
            )
            # Said before a single byte is copied: a pack that has to copy
            # needs the disk twice over, and the user has to hear that while
            # they can still act on it (point --out somewhere else), not from a
            # warning printed after P1 has already filled the disk up.
            notice_pair = second_copy_notice(root, out_blobs, spec, no_hardlink)
            if notice_pair is not None:
                msg, fits = notice_pair
                log(msg)
                if notice is not None:
                    notice(msg)
                if not fits:
                    # Refused, not attempted: the copy cannot fit, and finding
                    # that out at 90% costs the whole pack.
                    raise PackError(msg, exit_code=int(ExitCode.S0_DISK_INSUFFICIENT))
                warnings.append(msg)

            # Per-stage announcements: whoever is watching needs to know whether
            # we are moving bytes (P1), writing the manifest (P2), or
            # reconciling (P4).
            if emitter is not None:
                emitter.stage_start("P1", "Hashing and copying what the run used")
            manifest, inventory = _build_manifest(
                root, spec, place=place, work=work, env_python=env_python,
                no_fingerprint=no_fingerprint, warnings=warnings, dry_run=False,
                unrestorable=unrestorable,
                pin_wheels=pin_wheels, client=client, no_licence_lookup=no_licence_lookup,
                mine=mine, emitter=emitter, cache=hash_cache, program_dir=_program_dir,
            )
            # Saved as soon as the reading is done: what was read stays true even
            # if a later stage fails, and a retry should not pay for it twice.
            hash_cache.save()
            if copied_instead:
                warnings.append(
                    "This disk would not let us hard-link files into the nest, so they were "
                    f"copied instead — the nest now takes a second full-size copy of every "
                    f"file on it. First one: {copied_instead[0]}. If the disk runs out "
                    "part-way through, that is why: give the output folder (--out) a disk "
                    "with room for the whole thing a second time, or put it on the same "
                    "filesystem as the files being packed."
                )
            if emitter is not None:
                emitter.stage_start("P2", "Writing the manifest")
            _refuse_unresolved_placeholders(manifest)
            nest_id = manifest["id"]
            out_nest = out / "nests" / nest_id
            out_nest.mkdir(parents=True, exist_ok=True)
            manifest_path = out_nest / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
            report.nest_id = nest_id
            report.manifest = manifest
            report.manifest_path = str(manifest_path)
            report.inventory = inventory
            report.blob_count = len(inventory)
            report.total_bytes = sum(i.get("size_bytes", 0) for i in inventory)

            # -- P3 upload (optional) + P4 reconcile --
            if emitter is not None and uploader is not None:
                emitter.stage_start("P3", "Uploading")
            uploaded_sizes = uploader(out_blobs, manifest) if uploader is not None else None
            if emitter is not None:
                emitter.stage_start("P4", "Checking every byte that landed")
            missing, size_bad = _reconcile(manifest, out_blobs, uploaded_sizes)
            if missing or size_bad:
                report.findings = warnings + [
                    f"P4 check came up short: missing {missing}" if missing else "",
                    f"P4 size doesn't match: {size_bad}" if size_bad else "",
                ]
                fail = NestFailure(
                    "P4",
                    ErrorClass.HASH_MISMATCH,
                    "What landed in storage doesn't match. We never call that a success",
                    context={"missing": missing, "size_mismatch": size_bad},
                    exit_code=int(ExitCode.S2_HASH_MISMATCH),
                )
                report.failure = fail.to_error_object()
                report.exit_code = fail.exit_code
                report.ok = False
                return report

            report.findings = warnings
            report.restorable = not unrestorable
            report.unrestorable_reasons = list(unrestorable)
            report.ok = True
            report.exit_code = int(ExitCode.OK)
            log(f"Packed: {manifest_path} (nest {nest_id})")
            return report
    except PackError as e:
        report.exit_code = e.exit_code
        report.ok = False
        # Not every PackError carries a structured failure object yet; the ones
        # that do (the still-verifying timeout) must reach the JSON report
        # instead of leaving ``failure: null`` next to ``ok: false``.
        report.failure = e.failure
        report.findings = warnings + [e.human]
        # **A pack that stopped never earns "rebuildable elsewhere".** ``restorable``
        # defaults to True and this branch used to leave it there, so a run that died
        # mid-upload reported ``ok: false`` and ``restorable: true`` side by side.
        # Measured 2026-09-09 (first LLaMA-Factory pack attempt): storage answered one part with 502,
        # exit 14, ``hosted.nest_version_id: null`` -- nothing was registered, nothing
        # could be rebuilt from it -- and the report still said the nest was restorable.
        # Anything reading the JSON (hand-off, our own dashboards) reads that as a
        # usable nest.
        report.restorable = False
        report.unrestorable_reasons = list(unrestorable) + [
            "Packing stopped before it finished, so there is no complete nest to rebuild "
            f"from: {e.human}"
        ]
        return report
    except NestFailure as e:
        # The refusal gates inside packing (unresolved placeholders, and any
        # other P-stage NestFailure) end as a structured red report — exit code
        # and error object from the failure itself — not as a traceback with a
        # meaningless interpreter exit code.
        report.exit_code = e.exit_code
        report.ok = False
        report.failure = e.to_error_object()
        report.findings = warnings + [e.format_human()]
        return report
    except subprocess.CalledProcessError as e:
        report.exit_code = int(ExitCode.USAGE)
        report.ok = False
        report.findings = warnings + [f"tar failed while archiving the code: {e}"]
        return report


def _reconcile(
    manifest: dict, out_blobs: Path, uploaded_sizes: dict | None
) -> tuple[list[str], list[str]]:
    """P4: every blob in the manifest must exist with the declared size (local
    tree, or the uploader's returned {sha256: size})."""
    wanted: dict[str, int] = {}

    def walk(o) -> None:
        if isinstance(o, dict):
            if set(o) >= {"sha256", "size_bytes"}:
                wanted[o["sha256"]] = o["size_bytes"]
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(manifest)
    missing: list[str] = []
    size_bad: list[str] = []
    for h, size in wanted.items():
        if uploaded_sizes is not None:
            got = uploaded_sizes.get(h)
        else:
            p = out_blobs / h[:2] / h
            got = p.stat().st_size if p.exists() else None
        if got is None:
            missing.append(h[:12])
        elif got != size:
            size_bad.append(f"{h[:12]}:{got}≠{size}")
    return missing, size_bad


# Memory of "which nest did this folder last go into", so appending a version
# does not require copying an id by hand. It lives in the **target directory's**
# state area, not the user's global config: one machine holds several
# environment folders, each with its own nest, so this is a directory-level fact.
# It is a convenience only — failing to read or write it passes silently and
# must never block a pack.
#: Where the state file sits relative to the target directory (same directory
#: convention as restore.STATE_DIR_REL).
HOSTED_MEMORY_REL = ".renest/state/drive-nest.json"


def hosted_memory_read(target: str | os.PathLike[str]) -> dict | None:
    """Read "the nest this folder last went into". Wrong shape or unreadable →
    None (a missing memory is never an error)."""
    path = Path(target) / HOSTED_MEMORY_REL
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict) or not str(data.get("nest_id") or ""):
        return None
    return data


def hosted_memory_write(
    target: str | os.PathLike[str], *, nest_id: str, nest_name: str | None, origin: str
) -> None:
    """Record which nest this pack went into. Atomic write (os.replace); if it
    cannot be written, let it go."""
    path = Path(target) / HOSTED_MEMORY_REL
    payload = {
        "nest_id": nest_id,
        "nest_name": nest_name,
        # origin has to be recorded alongside: an id only means anything on the
        # service that issued it, so reusing an old id against a different
        # service address (a local dev server, say) would aim the pack at
        # someone else's 404.
        "origin": origin,
        "saved_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        return


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dir", required=True, help="Environment root folder (the one holding ComfyUI/)")
    parser.add_argument("--spec", help="pack-spec.json (a ready-made list; use this or --workflow)")
    parser.add_argument(
        "--workflow",
        help="Workflow JSON in API format — we work out the list from your ComfyUI folder "
             "(use this, --spec, or --auto)",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Pack this ComfyUI folder as it stands, without naming a workflow — we look for "
             "a picture it already produced (the recipe travels inside the picture, and we "
             "read only that text, never the picture itself) and use whichever run is newest "
             "purely to check the file list; every recipe found still ships with the nest. "
             "No picture with a recipe in it → the nest still packs, it just carries no "
             "record of a finished run (use this, --workflow, or --spec)",
    )
    parser.add_argument("--comfyui-dir", help="ComfyUI folder (found under --dir automatically if omitted)")
    parser.add_argument(
        "--program-dir",
        help="Where ComfyUI's own program files are, when they are not in the same folder "
             "as your nodes and models — the ComfyUI desktop app keeps them apart. That "
             "folder supplies ComfyUI itself and the version it is at; your nodes, models "
             "and workflow still come from the other one. The nest that comes out is an "
             "ordinary ComfyUI install either way",
    )
    parser.add_argument(
        "--framework",
        choices=["kohya", "llamafactory"],
        help="pack a training setup instead of a ComfyUI one — needs --run-record",
    )
    parser.add_argument(
        "--run-record",
        help="JSON record of the training run that worked: {\"cwd\", \"argv\", \"env\"}. "
        "Its recipe is read from there — the command line for kohya, the config file "
        "it names for LLaMA-Factory",
    )
    parser.add_argument("--out", help="Output folder, laid out like the drive (nests/ + blobs/); not needed for --dry-run")
    parser.add_argument("--no-hardlink", action="store_true", help="Always copy files instead of hardlinking them")
    parser.add_argument(
        "--full-rehash",
        action="store_true",
        help="Read every file from disk again. By default a repeat pack of this folder "
             "re-reads only files whose size, time or place on disk moved since last "
             "time — use this if you suspect a file changed without any of those moving",
    )
    parser.add_argument("--env-python", help="Python interpreter of the environment being packed (we read its details from there). Applies to the ComfyUI / generic pack path; in the fine-tuning pack path the python version is taken from the run record instead, so this flag does not set it there.")
    parser.add_argument("--no-fingerprint", action="store_true")
    parser.add_argument(
        "--no-licence-lookup",
        action="store_true",
        help="do not look up what licence each model carries. Packing works offline either "
             "way — this only means every licence stays marked as your own claim, unchecked",
    )
    parser.add_argument(
        "--mine",
        action="append",
        metavar="PATH",
        default=[],
        help="Declare a file as your own work (a LoRA you trained, your own images), by its "
             "path inside the environment. Repeat for more. Files you did not make are "
             "treated as restricted by default, which means they never travel to someone "
             "you hand the nest to — right for downloaded models, wrong for yours. A licence "
             "lookup that recognises the file still wins, so this cannot loosen a real "
             "restricted model",
    )
    parser.add_argument(
        "--i-know",
        action="store_true",
        help="Pack even though something in your code folder looks like a credential. "
             "Use this only when you are sure it is not a real one — a nest carries your "
             "code folder as-is, to whoever you hand it to",
    )
    parser.add_argument("--dry-run", action="store_true", help="Only show the manifest and a size estimate; pack nothing")
    parser.add_argument(
        "--pin-wheels",
        action="store_true",
        help="Pin packages carrying a vendor-only version (like torch==2.4.1+cu124) to direct "
             "wheel URLs — PyPI doesn't have those versions, so without a pinned address a "
             "restore can't install them. On by default; this flag only forces it back on "
             "when combined with --offline",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Pack with zero network: no wheel pinning, no licence lookups. The archive is "
             "still a faithful record of this machine, but packages pinned to a vendor-only "
             "version (torch==…+cuXXX) keep no download address, so the nest is marked as "
             "not rebuildable on another machine and a restore will say so up front. "
             "Licences stay marked as your own claim, unchecked. --pin-wheels and "
             "--no-licence-lookup still override their half individually",
    )
    # -- Direct upload to the hosted drive (needs an access token) -------------
    # First-layer help offers one road. "s3" stays a fully valid value — the
    # export and escape road reuses it — it is just not advertised here; metavar
    # hides the choice list while the parser still accepts and validates both.
    parser.add_argument(
        "--dest",
        choices=["hosted", "s3"],
        metavar="hosted",
        help="Where to upload. “hosted” = your Renest drive (needs an access token — see "
             "RENEST_TOKEN). Leave this out and the nest is only "
             "written to --out on this machine",
    )
    parser.add_argument(
        "--origin",
        help="Renest service address (default https://api.renest.ai, or the RENEST_ORIGIN "
             "environment variable)",
    )
    parser.add_argument("--nest-id", help="Upload into an existing nest as a new version (a new nest is created if omitted)")
    parser.add_argument("--nest-name", help="Name for the new nest (defaults to the name in the spec, or one we generate)")
    parser.add_argument(
        "--new-nest",
        action="store_true",
        help="Start a separate new nest even though this folder was packed into a nest "
             "before (by default we add a new version to that same nest)",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Don't report pack progress (by default the same token reports progress to your "
             "Renest drive; reporting never holds up the pack)",
    )


def run_from_args(args: argparse.Namespace, emitter: EventEmitter) -> int:
    spec: dict | None = None
    run_record: dict | None = None
    framework = getattr(args, "framework", None)
    auto = bool(getattr(args, "auto", False))
    chosen = [n for n, v in (("--spec", args.spec), ("--workflow", args.workflow),
                             ("--framework", framework), ("--auto", auto)) if v]
    if len(chosen) > 1:
        print(f"✗ Pick one of these, not {len(chosen)}: {', '.join(chosen)}", file=sys.stderr)
        return int(ExitCode.USAGE)
    if args.spec:
        try:
            spec = json.loads(Path(args.spec).read_text())
        except (OSError, json.JSONDecodeError) as e:
            print(f"✗ Can't read the pack-spec: {e}", file=sys.stderr)
            return int(ExitCode.USAGE)
    elif framework:
        if not getattr(args, "run_record", None):
            print(
                "✗ --framework needs --run-record: a JSON record of the run that worked "
                '({"cwd": …, "argv": [...], "env": {…}}). We pack what you actually ran, '
                "not what you might run.",
                file=sys.stderr,
            )
            return int(ExitCode.USAGE)
        from .training import load_run_record

        try:
            run_record = load_run_record(args.run_record)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"✗ Can't read that run record: {e}", file=sys.stderr)
            return int(ExitCode.USAGE)
    elif not args.workflow and not auto:
        print(
            "✗ pack needs one of: --spec, --workflow (a ComfyUI setup), --auto (pack it as it "
            "stands, no workflow to name), or --framework + --run-record (a training setup)",
            file=sys.stderr,
        )
        return int(ExitCode.USAGE)
    if not args.dry_run and not args.out:
        print("✗ A real pack needs --out", file=sys.stderr)
        return int(ExitCode.USAGE)

    # -- Upload destination. Both options obey the same discipline: **check the
    #    credentials first, pack second** — spending tens of GB on a pack and
    #    only then telling the user "no key configured" is the most hurtful
    #    possible failure order.
    hosted_uploader = None
    byos_uploader = None
    dest = getattr(args, "dest", None)
    if dest and args.dry_run:
        print(
            f"✗ --dest {dest} and --dry-run don't go together (a dry run uploads nothing)",
            file=sys.stderr,
        )
        return int(ExitCode.USAGE)

    if dest == "s3":
        # Bring-your-own-storage: the bucket key comes from the environment or
        # the [storage] section of the config file.
        from .config import ConfigError, CredentialSource, resolve_credentials

        try:
            creds = resolve_credentials(config_path=getattr(args, "config", None))
        except ConfigError as e:
            print(f"✗ {e.human}", file=sys.stderr)
            if e.hint:
                print(f"  → {e.hint}", file=sys.stderr)
            return e.exit_code
        if creds.source is not CredentialSource.BUCKET_KEY or creds.bucket_key is None:
            print(
                "✗ No bucket of your own is set up yet. Run `renest doctor --storage` — it "
                "prints the exact steps.",
                file=sys.stderr,
            )
            return int(ExitCode.CONFIG_OR_CREDENTIAL)
        # Exposure warnings go out **before** the upload starts, not after it
        # finishes: once a key has been synced away or committed, the nest
        # already being uploaded is no consolation.
        for warning in creds.exposure_warnings:
            print(f"⚠ {warning}", file=sys.stderr)
        if creds.warning:
            print(f"⚠ {creds.warning}", file=sys.stderr)
        from .byos import S3Uploader

        try:
            byos_uploader = S3Uploader(
                creds.bucket_key,
                log=None if args.json else (lambda m: print(m, file=sys.stderr)),
            )
        except PackError as e:
            print(f"✗ {e.human}", file=sys.stderr)
            return e.exit_code

    if dest == "hosted":
        from .config import ConfigError, resolve_token

        try:
            token = resolve_token(config_path=getattr(args, "config", None))
        except ConfigError as e:
            print(f"✗ {e.human}", file=sys.stderr)
            return e.exit_code
        if not token:
            print(
                "✗ No access token. Generate one in the web console, then put it in the "
                "RENEST_TOKEN environment variable, or write it into [auth] token in "
                "~/.config/renest/config.toml.",
                file=sys.stderr,
            )
            return int(ExitCode.CONFIG_OR_CREDENTIAL)
        from .hosted import DEFAULT_ORIGIN, HostedUploader

        origin = args.origin or os.environ.get("RENEST_ORIGIN") or DEFAULT_ORIGIN
        if origin.startswith("http://") and not origin.startswith(
            ("http://127.", "http://localhost", "http://[::1]")
        ):
            print(
                "⚠ This origin isn't https, so your access token crosses the network in the "
                "clear — only do this while testing on your own machine or local network",
                file=sys.stderr,
            )
        # "Which nest did this folder last go into": when no nest was named and
        # no new one was asked for, pack a new version into the previous nest —
        # that is what drive semantics mean (the same thing, changed = a new
        # version, not yet another file).
        new_nest = getattr(args, "new_nest", False)
        if args.nest_id and new_nest:
            print("✗ --nest-id and --new-nest contradict each other; pick one", file=sys.stderr)
            return int(ExitCode.USAGE)
        nest_id = args.nest_id
        if not nest_id and not new_nest:
            remembered = hosted_memory_read(args.dir)
            # The origin has to match: an id only means anything on the service
            # that issued it.
            if remembered and remembered.get("origin") == origin:
                nest_id = str(remembered["nest_id"])
                known = remembered.get("nest_name")
                print(
                    f"↻ This folder last went into nest {nest_id}"
                    + (f" (“{known}”)" if known else "")
                    + " — packing a new version of it. Use --new-nest to start a separate nest.",
                    file=sys.stderr,
                )
        hosted_uploader = HostedUploader(
            origin,
            token,
            nest_id=nest_id,
            nest_name=args.nest_name,
            log=None if args.json else (lambda m: print(m, file=sys.stderr)),
            report=not getattr(args, "no_report", False),
        )

    # Validate a hand-written spec against the schema — a misspelled enum should
    # die here on the local machine, not in the cloud after the rented hardware
    # is already paid for. **Keep it after the argument and credential gates**:
    # run earlier, a "spec has no name" complaint masks the real usage error.
    if args.spec:
        from .lint import kind_advice, validate_pack_spec

        problems = validate_pack_spec(spec)
        if problems:
            print("✗ The pack-spec has problems (fix these before packing):",
                  file=sys.stderr)
            for prob in problems:
                print(f"    {prob}", file=sys.stderr)
            return int(ExitCode.USAGE)
        # Said here rather than refused: since format 2.7 an asset kind is free text,
        # and the ecosystem it names is open. This one swap still costs a licence rule,
        # so it is worth a line before the machine starts costing money.
        for note in kind_advice(spec.get("files")):
            print(f"! {note}", file=sys.stderr)

    _pin, _no_licence = offline_effects(
        getattr(args, "offline", False),
        getattr(args, "pin_wheels", False),
        getattr(args, "no_licence_lookup", False),
    )
    report = pack(
        args.dir,
        spec,
        args.out,
        dry_run=args.dry_run,
        no_hardlink=args.no_hardlink,
        env_python=args.env_python,
        no_fingerprint=args.no_fingerprint,
        workflow=args.workflow,
        comfyui_dir=getattr(args, "comfyui_dir", None),
        program_dir=getattr(args, "program_dir", None),
        auto=auto,
        framework=framework,
        run_record=run_record,
        uploader=hosted_uploader or byos_uploader,
        emitter=None,
        pin_wheels=_pin,
        i_know=getattr(args, "i_know", False),
        no_licence_lookup=_no_licence,
        mine=set(getattr(args, "mine", None) or ()),
        full_rehash=getattr(args, "full_rehash", False),
        # Printed the moment it is known, not with the findings at the end: by
        # then the second copy has either fitted or filled the disk.
        notice=lambda m: print(f"⚠ {m}", file=sys.stderr, flush=True),
    )
    # Pack succeeded → record "this folder → this nest" in the target
    # directory's state area, so the next pack picks up where this one left off.
    hosted_ok = (
        report.ok and hosted_uploader is not None and hosted_uploader.result.nest_id
    )
    if hosted_ok:
        hr = hosted_uploader.result
        name_to_keep = hr.nest_name
        if name_to_keep is None:
            # Appending to an existing nest: reuse the name we recorded last
            # time (the client does not know the server-side name).
            prev = hosted_memory_read(args.dir)
            if prev and prev.get("nest_id") == hr.nest_id:
                name_to_keep = prev.get("nest_name")
        hosted_memory_write(
            args.dir, nest_id=hr.nest_id, nest_name=name_to_keep, origin=origin
        )

    if args.json:
        out = report.to_dict()
        if report.dry_run:
            out["manifest"] = report.manifest
        if hosted_uploader is not None:
            out["hosted"] = hosted_uploader.result.to_dict()
        if byos_uploader is not None:
            out["own_bucket"] = byos_uploader.result.to_dict()
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        for w in report.findings:
            if w:
                print(f"⚠ {w}", file=sys.stderr)
        if report.ok and not report.dry_run:
            print(sealed_summary(report), file=sys.stderr)
        elif report.ok:
            print(
                f"✓ Dry run: nest {report.nest_id} would seal "
                f"{report.blob_count} items / {report.total_bytes} bytes",
                file=sys.stderr,
            )
        else:
            print(
                f"✗ Pack failed: nest {report.nest_id} "
                f"({report.blob_count} items / {report.total_bytes} bytes)",
                file=sys.stderr,
            )
        # The one fact a hand-off or a restore decision hangs on, said at the
        # end where it cannot scroll away among the warnings. Deliberately
        # separate from the "renest inside the packed environment" advisory:
        # that one says the record may describe the wrong environment, this one
        # says the record cannot be rebuilt — mixing them buries both.
        # Kept OUTSIDE the success/dry-run/failure chain above: nested into it,
        # the chain's `else` once attached here and every restorable success
        # ended with "Pack failed" (0.1.14).
        if report.ok and not report.restorable:
            print(
                "■ Rebuildable elsewhere: NO — archived faithfully, but as packed "
                "this nest cannot be rebuilt on another machine:",
                file=sys.stderr,
            )
            for _r in report.unrestorable_reasons:
                print(f"  · {_r}", file=sys.stderr)
        if hosted_ok:
            hr = hosted_uploader.result
            human_version = f"version {hr.version_no}" if hr.version_no else "a new version"
            if hr.created_new_nest:
                print(
                    f"✓ On your Renest drive: new nest “{hr.nest_name}” "
                    f"(id {hr.nest_id}, {human_version})",
                    file=sys.stderr,
                )
            else:
                print(
                    f"✓ On your Renest drive: {human_version} of nest {hr.nest_id}",
                    file=sys.stderr,
                )
            print(
                "  Pack from this folder again and it lands in the same nest "
                f"(--new-nest starts a fresh one). See it any time:  renest list {hr.nest_id}",
                file=sys.stderr,
            )
    # Packing reads the compatibility facts too -- the node vocabulary decides what is
    # recognised, so stale facts here quietly collect one model fewer and the nest is
    # already sealed by the time anyone finds out. Same rule as doctor and restore: it
    # speaks up on stderr and changes nothing, because staleness is a reason to look and
    # never a reason to refuse.
    from .update_rules import warn_if_stale

    warn_if_stale(sys.stderr)
    return report.exit_code
