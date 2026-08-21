"""Which operating-system libraries a run needs the machine to provide (format 2.6).

These belong to the machine's distribution, so they cannot travel inside a nest. A
machine missing one restores every byte, starts, answers -- and silently loses whole
plugins, which the user only discovers when running their own workflow.

Two ways to find out, and they are **not** the same kind of statement:
  ``loaded``   -- ask the application that is still running what it actually loaded.
                  Authoritative; a consumer may refuse a rebuild on it.
  ``declared`` -- fallback: read what the installed compiled files declare they need.
                  Covers only part of the truth, so it may **only ever warn**.

``ldd`` is deliberately not used: measured 2026-08-12, it reported libraries the nest
carries itself as missing, and got the direction wrong on others.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import os
import re
import struct
import subprocess
from pathlib import Path

from .envlock import canonical_name, installed_dist_infos

__all__ = [
    "CONTESTED_MODULES",
    "collect_native_libs",
    "contested_module_missing_libs",
    "contested_winners",
    "elf_needed",
    "elf_runpaths",
    "elf_soname",
    "interpreter_site_packages",
    "lock_requirement_for",
    "lock_requirements",
    "looks_like_the_working_run",
    "missing_native_libs",
]

_DT_NULL, _DT_NEEDED, _DT_STRTAB, _DT_STRSZ, _DT_SONAME = 0, 1, 5, 10, 14
_DT_RPATH, _DT_RUNPATH = 15, 29

#: Where a distribution keeps its shared libraries. Used to answer "is this name on
#: this machine", never to decide what a nest needs -- that question is answered by
#: where a library actually loaded from at pack time.
LIB_DIRS = (
    "/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu", "/lib/aarch64-linux-gnu",
    "/usr/lib64", "/lib64", "/usr/lib", "/lib", "/usr/local/lib",
    "/usr/local/cuda/lib64", "/usr/local/cuda/compat",
)


#: A Python extension module, not a distribution's shared library. They are named
#: `_asyncio.cpython-312-aarch64-linux-gnu.so` and they arrive with the interpreter, so
#: recording them would (a) say nothing about what the machine must provide and (b) read
#: as missing everywhere, since no library directory carries that name. Measured
#: 2026-08-12 on a live app: 58 names collected, 26 of them reported missing on the very
#: machine that was running fine.
_EXT_MODULE = re.compile(r"\.(cpython|pypy)-\d+[^/]*\.so$")


#: The dynamic loader itself. It is what *runs* the program, not something the program
#: depends on, and it is present by definition wherever anything runs at all.
_LOADER = re.compile(r"^ld(-linux[^/]*|64|)\.so(\.\d+)?$")


def _is_lib(name: str) -> bool:
    return ".so" in name and not _EXT_MODULE.search(name) and not _LOADER.match(name)


def _read_elf(path: Path) -> tuple[str | None, list[str]] | None:
    """Return (this file's own name, the names it declares it needs, the folders it
    says to search first), or None when the file is not a shared object we can read.

    Parsed by hand rather than shelled out to, because the escape hatch's dependency
    promise is the model here: no new tool on the machine, and no import of anything
    that has to be installed first."""
    try:
        with path.open("rb") as f:
            head = f.read(64)
            if len(head) < 64 or head[:4] != b"\x7fELF":
                return None
            is64, end = head[4] == 2, ("<" if head[5] == 1 else ">")
            if is64:
                ph_off = struct.unpack_from(end + "Q", head, 32)[0]
                ph_size = struct.unpack_from(end + "H", head, 54)[0]
                ph_num = struct.unpack_from(end + "H", head, 56)[0]
            else:
                ph_off = struct.unpack_from(end + "I", head, 28)[0]
                ph_size = struct.unpack_from(end + "H", head, 42)[0]
                ph_num = struct.unpack_from(end + "H", head, 44)[0]
            if not ph_num:
                return None
            f.seek(ph_off)
            phdrs = f.read(ph_size * ph_num)
            loads: list[tuple[int, int, int]] = []
            dyn: tuple[int, int] | None = None
            for i in range(ph_num):
                ph = phdrs[i * ph_size:(i + 1) * ph_size]
                if len(ph) < ph_size:
                    break
                p_type = struct.unpack_from(end + "I", ph, 0)[0]
                if is64:
                    off, vaddr = struct.unpack_from(end + "QQ", ph, 8)
                    filesz = struct.unpack_from(end + "Q", ph, 32)[0]
                else:
                    off, vaddr = struct.unpack_from(end + "II", ph, 4)
                    filesz = struct.unpack_from(end + "I", ph, 16)[0]
                if p_type == 1:      # PT_LOAD
                    loads.append((vaddr, filesz, off))
                elif p_type == 2:    # PT_DYNAMIC
                    dyn = (off, filesz)
            if dyn is None:
                return None
            f.seek(dyn[0])
            data = f.read(dyn[1])
            step, fmt = (16, end + "Qq") if is64 else (8, end + "Ii")
            needed_at: list[int] = []
            runpath_at: list[int] = []
            soname_at: int | None = None
            strtab_v = strsz = None
            for i in range(0, len(data) - step + 1, step):
                tag, val = struct.unpack_from(fmt, data, i)
                if tag == _DT_NULL:
                    break
                if tag == _DT_NEEDED:
                    needed_at.append(val)
                elif tag == _DT_SONAME:
                    soname_at = val
                elif tag in (_DT_RPATH, _DT_RUNPATH):
                    runpath_at.append(val)
                elif tag == _DT_STRTAB:
                    strtab_v = val
                elif tag == _DT_STRSZ:
                    strsz = val
            if strtab_v is None or strsz is None:
                return None
            at = next(
                (o + (strtab_v - v) for v, sz, o in loads if v <= strtab_v < v + sz), None
            )
            if at is None:
                return None
            f.seek(at)
            strtab = f.read(strsz)

            def s(pos: int) -> str:
                end_at = strtab.find(b"\0", pos)
                return strtab[pos:end_at if end_at >= 0 else None].decode("utf-8", "replace")

            runpaths = [seg for o in runpath_at for seg in s(o).split(":") if seg]
            return (s(soname_at) if soname_at is not None else None,
                    [s(o) for o in needed_at], runpaths)
    except (OSError, struct.error, ValueError, IndexError):
        return None


def elf_soname(path: Path) -> str | None:
    got = _read_elf(path)
    return got[0] if got else None


def elf_needed(path: Path) -> list[str]:
    got = _read_elf(path)
    return got[1] if got else []


def elf_runpaths(path: Path) -> list[str]:
    """The search folders a shared object names for its own libraries (RPATH /
    RUNPATH), ``$ORIGIN`` left as written."""
    got = _read_elf(path)
    return got[2] if got else []


def _under(path: Path, roots: list[Path]) -> bool:
    p = str(path)
    return any(p == str(r) or p.startswith(str(r) + os.sep) for r in roots)


def _parent_of(pid: int) -> int:
    """The pid that started this one, 0 when it cannot be read.

    Parsed after the last ``)``: the program name sits in brackets and may itself
    contain brackets and spaces, so splitting the line from the left goes wrong on
    exactly the processes whose names are worth being careful about."""
    try:
        line = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    tail = line.rpartition(")")[2].split()
    return int(tail[1]) if len(tail) > 1 and tail[1].isdigit() else 0


def _our_own_chain() -> set[int]:
    """Us, and every process we were started from.

    **Measured the hard way (2026-08-12, real machine):** packing is normally run from
    inside the environment being packed, so the "working directory is under here" test
    matched **the packing process itself**, and what got recorded as "libraries the
    successful run needed" was our own tool's -- nine generic C-library entries plus one
    from our JSON checker, and not a single GPU library. Sampling yourself must be
    impossible, not unlikely."""
    seen: set[int] = set()
    pid = os.getpid()
    for _ in range(32):                       # a cycle or a very deep tree ends it
        if pid <= 1 or pid in seen:
            break
        seen.add(pid)
        pid = _parent_of(pid)
    return seen


def _pids_running_in(by_exe: list[Path], by_cwd: list[Path]) -> list[int]:
    """Which running processes are **this environment's application**.

    Two passes, and the order is the accuracy: a process whose *program* is this
    environment's own interpreter is certainly the app, while "working directory is
    somewhere under here" also catches the user's shell and their editor. When the
    environment root is a home directory the second test alone would sweep in half the
    machine, and every library those processes happen to load would be recorded as
    something this run needed."""
    proc = Path("/proc")
    if not proc.is_dir():
        return []
    ours = _our_own_chain()
    exact: list[int] = []
    loose: list[int] = []
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) in ours:
            continue
        # **argv[0] before /proc/exe.** A virtual environment's `bin/python` is a symlink
        # to the system binary, and `/proc/<pid>/exe` always reports the resolved one --
        # so matching on it alone can never recognise a venv's own app. The command line
        # keeps the name the user actually launched.
        argv0 = None
        try:
            raw = (entry / "cmdline").read_bytes().split(b"\0", 1)[0].decode(errors="replace")
            argv0 = Path(raw) if raw.startswith("/") else None
        except OSError:
            argv0 = None
        if argv0 is not None and _under(argv0, by_exe):
            exact.append(int(entry.name))
            continue
        try:
            exe = (entry / "exe").resolve()
        except OSError:
            exe = None
        if exe is not None and _under(exe, by_exe):
            exact.append(int(entry.name))
            continue
        try:
            cwd = (entry / "cwd").resolve()
        except OSError:
            continue
        if _under(cwd, by_cwd):
            loose.append(int(entry.name))
    return exact or loose


def _loaded_machine_libs(pids: list[int], nest_roots: list[Path]) -> list[str]:
    """Library names the run really loaded **from the machine**, as the program asked
    for them.

    Two rules that measurement forced, both easy to get wrong the other way:
    a library is the machine's or the nest's **by where it actually loaded from**, never
    by looking the name up (a common compression library sits under the same name inside
    an installed package while the machine's copy is the one in use); and the name is the
    file's own recorded name, copied verbatim -- most files on disk carry a version the
    program never asks for."""
    names: dict[str, None] = {}
    for pid in pids:
        try:
            maps = Path(f"/proc/{pid}/maps").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in maps.splitlines():
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            path = parts[5].strip()
            if not path.startswith("/") or not _is_lib(Path(path).name):
                continue
            p = Path(path)
            if _under(p, nest_roots) or not p.is_file():
                continue
            names.setdefault(elf_soname(p) or p.name, None)
    return sorted(names)


#: Names that only the GPU driver supplies. Every successful run this product exists for
#: loads one -- measured on two chip families -- and the driver is always the machine's,
#: never something a nest carries, so nothing inside a nest can imitate it.
_DRIVER_LIBS = ("libcuda.so", "libnvcuda", "libnvidia-")


def looks_like_the_working_run(names: list[str] | tuple[str, ...]) -> bool:
    """Does this list plausibly come from the run that worked?

    The question exists because "we asked a running process" is the **authoritative**
    answer, and a thin authoritative list is more dangerous than an honest fallback: a
    consumer trusts it more, so "nothing is missing here" gets stated with confidence
    about a machine nobody checked. Asked in one measured way -- a GPU run loads a driver
    library, and a list without one did not come from a GPU run."""
    return any(n.startswith(_DRIVER_LIBS) for n in names)


def _declared_machine_libs(scan_roots: list[Path]) -> list[str]:
    """Fallback: what the installed compiled files declare, minus what the nest itself
    carries. Never authoritative -- see the module docstring."""
    needed: set[str] = set()
    provided: set[str] = set()
    for root in scan_roots:
        if not root.is_dir():
            continue
        for p in root.rglob("*"):
            if not p.is_file() or not _is_lib(p.name):
                continue
            got = _read_elf(p)
            if got is None:
                continue
            provided.add(p.name)
            if got[0]:
                provided.add(got[0])
            needed.update(got[1])
    return sorted(needed - provided)


def _interpreter_prefixes(python: str | os.PathLike[str]) -> tuple[Path | None, Path | None]:
    """``(this environment's own prefix, the interpreter it was built on)`` -- **asked of
    the interpreter, never derived from the path**.

    A virtual environment's ``bin/python`` is a symlink to the system binary, so
    following the link lands on ``/usr``. Measured 2026-08-12 on a real running app: with
    ``/usr`` mistaken for the environment, every genuine machine library (all of them live
    under ``/usr/lib``) was filtered out as "inside the nest", so the authoritative branch
    returned nothing and the weak fallback ran instead -- on every ordinary venv, which
    includes every environment this tool itself rebuilds.
    """
    try:
        done = subprocess.run(  # noqa: S603
            [str(python), "-c", "import sys;print(sys.prefix);print(sys.base_prefix)"],
            capture_output=True, text=True, timeout=30, check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None, None
    got = [ln.strip() for ln in done.stdout.splitlines() if ln.strip()]
    if len(got) < 2:
        return None, None
    # Not resolved: the prefix is a real directory, and resolving it would undo the point.
    return Path(got[0]), Path(got[1])


def _interpreter_home(python: str | os.PathLike[str]) -> Path | None:
    """Kept for callers that only want the base interpreter."""
    return _interpreter_prefixes(python)[1]


def interpreter_site_packages(python: str | os.PathLike[str]) -> Path | None:
    """The site-packages folder of the environment this interpreter runs in,
    asked of the interpreter itself; None when it cannot be asked."""
    prefix, _ = _interpreter_prefixes(python)
    if prefix is None:
        return None
    hits = sorted(prefix.glob("lib/python*/site-packages")) or sorted(prefix.glob("Lib/site-packages"))
    return hits[0] if hits else None


def collect_native_libs(
    env_root: str | os.PathLike[str], python: str | os.PathLike[str] | None = None
) -> dict | None:
    """``{"method": "loaded"|"declared", "names": [...]}``, or None when nothing could
    be established -- in which case write nothing, rather than an empty list that reads
    like "this run needed none"."""
    if not Path("/proc").is_dir():
        return None
    root = Path(env_root).resolve()
    nest_roots = [root]
    site_dirs: list[Path] = []
    venv, home = _interpreter_prefixes(python) if python else (None, None)
    if python and venv is not None:
        nest_roots.append(venv)
        site_dirs += sorted(venv.glob("lib/python*/site-packages"))
    if home is not None:
        # Whether the interpreter's own libraries count depends on which Python this
        # environment uses. One managed by uv brings them along, so that layer needs no
        # scanning; a system Python does not, and skipping it there hides real answers.
        if _under(home, [root]):
            nest_roots.append(home)
        else:
            site_dirs.append(home / "lib")
    # "This environment's own program" first, "anything running under this folder"
    # only as a fallback — see _pids_running_in. **The base interpreter goes in only when
    # it lives inside this environment** (a uv-managed private Python does): a system one
    # sits at /usr, and searching there matched ten unrelated system processes on a real
    # machine and recorded their stdlib modules as libraries this run needed.
    by_exe = [p for p in nest_roots[1:] if p is not None]
    if home is not None and _under(home, [root]):
        by_exe.append(home)
    pids = _pids_running_in(by_exe, [root])
    loaded = _loaded_machine_libs(pids, nest_roots) if pids else []
    # **Better a truthful fallback than a false authority.** A process matched here may
    # simply have been passing through; if what it loaded does not look like the run that
    # worked, drop back to the declared list and say so, rather than dressing it up as
    # the authoritative one.
    if loaded and looks_like_the_working_run(loaded):
        return {"method": "loaded", "names": loaded}
    declared = _declared_machine_libs(site_dirs)
    return {"method": "declared", "names": declared} if declared else None


def missing_native_libs(names: list[str] | tuple[str, ...]) -> list[str]:
    """Which of these library names this machine does not have.

    Looked up by the exact name asked for, in the standard library folders -- the
    same thing the escape hatch does in shell, deliberately kept identical. **Not
    ``ldd``**: measured, it reported libraries the nest carries itself as missing and
    got the direction wrong on others, and a false alarm here trains people to ignore
    the real one."""
    if not Path("/proc").is_dir():
        return []
    return [n for n in names
            if isinstance(n, str) and n
            and not any((Path(d) / n).exists() for d in LIB_DIRS)]


#: Package families that all ship the same top-level module, so installing them
#: together makes the later ones overwrite the earlier ones' files. Which copy
#: survives decides which system libraries the module needs -- and the survivor
#: is not stable: measured 2026-08-17, the same lock on the same machine produced
#: a different survivor on back-to-back installs.
CONTESTED_MODULES: dict[str, tuple[str, ...]] = {
    "cv2": ("opencv-python", "opencv-contrib-python", "opencv-python-headless"),
}


def contested_module_missing_libs(site_packages: Path) -> dict[str, list[str]]:
    """For each contested module actually installed: system libraries its
    installed binaries declare they need, that the environment does not carry
    and this machine does not have.

    A declared-method statement (see module docstring): it may only ever warn.
    Names satisfied by files the environment carries next to the module (the
    ``*.libs`` convention wheels use) are not missing -- that mistake is exactly
    why ``ldd`` was rejected above."""
    out: dict[str, list[str]] = {}
    carried = {p.name: p for p in site_packages.glob("*.libs/*") if p.is_file()}
    for mod in CONTESTED_MODULES:
        mod_dir = site_packages / mod
        if not mod_dir.is_dir():
            continue
        # Walk **through** the libraries the wheel carries: `cv2.abi3.so` itself
        # asks for the bundled Qt, and it is Qt that asks the machine for
        # `libxcb.so.1` -- measured 2026-08-17, reading only the top level said
        # "nothing missing" on a machine where `import cv2` died on exactly that.
        # Names the machine has are not descended into: nothing to find there.
        seen: set[str] = set()
        needed: set[str] = set()
        queue = [so for so in mod_dir.glob("*.so")]
        while queue:
            so = queue.pop()
            for name in elf_needed(so):
                if name in seen:
                    continue
                seen.add(name)
                if name in carried:
                    queue.append(carried[name])
                else:
                    needed.add(name)
        gaps = missing_native_libs(sorted(n for n in needed if _is_lib(n)))
        if gaps:
            out[mod] = gaps
    return out


# --------------------------------------------------------------------------
# Contested modules, pack side (format 2.8): which candidate won on this machine
# --------------------------------------------------------------------------
#: One requirement line of a lock: ``name==version`` or ``name @ url``, with an
#: optional ``[extras]``. Hash options and continuation backslashes come after.
_LOCK_REQ = re.compile(
    r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[[^\]]*\])?\s*(?:==|@)\s*\S"
)


def lock_requirements(lock_text: str) -> list[tuple[str, str]]:
    """``(canonical name, requirement)`` for every requirement line of a lock, in
    file order. The requirement is the line with hash options, comments and the
    trailing continuation backslash removed -- exactly what an installer accepts
    on its command line."""
    out: list[tuple[str, str]] = []
    for line in (lock_text or "").splitlines():
        m = _LOCK_REQ.match(line)
        if not m:
            continue
        req = line.split(" #", 1)[0]
        req = re.split(r"\s+--hash=", req, 1)[0]
        req = req.rstrip().rstrip("\\").strip()
        if req:
            out.append((canonical_name(m.group(1)), req))
    return out


def lock_requirement_for(lock_text: str, name: str) -> str | None:
    """The requirement line pinning ``name`` in this lock, or None."""
    want = canonical_name(name)
    return next((req for n, req in lock_requirements(lock_text) if n == want), None)


def _record_hashes(dist_info: Path) -> dict[str, str]:
    """RECORD rows -> ``{path: sha256 hex}`` for the rows that carry a sha256."""
    rec = dist_info / "RECORD"
    out: dict[str, str] = {}
    try:
        with rec.open(encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.reader(fh):
                if len(row) < 2 or not row[1].startswith("sha256="):
                    continue
                digest = row[1][len("sha256="):]
                try:
                    out[row[0]] = base64.urlsafe_b64decode(digest + "=" * (-len(digest) % 4)).hex()
                except (ValueError, TypeError):
                    continue
    except OSError:
        return {}
    return out


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _survivor_file(mod_dir: Path, module: str) -> Path | None:
    """The compiled file whose bytes decide the module's behaviour: the extension
    module itself, whichever suffix this platform gives it."""
    for pattern in (f"{module}*.so", f"{module}*.pyd", f"{module}*.dylib"):
        hits = sorted(p for p in mod_dir.glob(pattern) if p.is_file())
        if hits:
            return hits[0]
    return None


def contested_winners(site_packages: Path, lock_text: str) -> tuple[list[dict], list[str]]:
    """For each contested module the lock installs more than one candidate of:
    which candidate the surviving copy in ``site_packages`` belongs to.

    Returns ``(entries for runtime.contested_modules, notes for the pack report)``.
    Two ways of telling, tried in this order and recorded in ``winner_evidence.method``:
    ``record_hash`` -- one candidate's RECORD lists the survivor with the very hash
    on disk; ``libs_dir`` -- the survivor's own search path (RUNPATH), or the
    bundled libraries it names, points into one candidate's ``*.libs`` folder.
    Neither -> no entry, one note. **The hash written is the file as installed**,
    never the wheel's: measured 2026-08-17, the two differ."""
    entries: list[dict] = []
    notes: list[str] = []
    order = [n for n, _ in lock_requirements(lock_text)]
    dists: dict[str, Path] | None = None
    for module, family in CONTESTED_MODULES.items():
        candidates = sorted(
            (f for f in family if canonical_name(f) in order),
            key=lambda f: order.index(canonical_name(f)),
        )
        if len(candidates) < 2:
            continue
        mod_dir = site_packages / module
        survivor = _survivor_file(mod_dir, module) if mod_dir.is_dir() else None
        if survivor is None:
            notes.append(
                f"The dependency list installs {len(candidates)} packages that all write "
                f"`{module}/`, but no compiled `{module}` module was found in this environment, "
                f"so which one your run used is not recorded. A rebuild installs them in "
                f"whatever order the installer picks."
            )
            continue
        rel = f"{module}/{survivor.name}"
        disk = _sha256_of(survivor)
        if dists is None:
            dists = installed_dist_infos(site_packages)
        records = {c: _record_hashes(dists[canonical_name(c)])
                   for c in candidates if canonical_name(c) in dists}
        winner, method = None, None
        by_hash = [c for c, rec in records.items() if rec.get(rel) == disk]
        if len(by_hash) == 1:
            winner, method = by_hash[0], "record_hash"
        else:
            hint = _libs_dir_family(survivor, site_packages)
            claimants = [c for c in candidates
                         if hint is not None
                         and canonical_name(c).replace("-", "_") == hint
                         and rel in records.get(c, {})]
            if len(claimants) == 1:
                winner, method = claimants[0], "libs_dir"
        if winner is None:
            notes.append(
                f"{len(candidates)} packages in the dependency list all write `{module}/` "
                f"({', '.join(candidates)}), and we could not tell which one the installed "
                f"copy came from, so it is not recorded. A rebuild installs them in whatever "
                f"order the installer picks, and the copy that ends up used may differ."
            )
            continue
        entries.append({
            "module": module,
            "candidates": candidates,
            "winner": winner,
            "winner_evidence": {"file": rel, "sha256": disk, "method": method},
        })
        # **Recording the winner is not the same as the user knowing there was a fight.**
        # Which variant won decides what the machine has to provide: the desktop build of
        # cv2 needs X11 libraries, the headless one does not. A rebuild reinstalls this
        # winner, so nothing is broken -- but the person can only tidy a dependency list
        # they know is ambiguous, and this is the one moment they are looking at it.
        others = [c for c in candidates if c != winner]
        notes.append(
            f"{len(candidates)} packages in the dependency list all write `{module}/` "
            f"({', '.join(candidates)}). The copy this environment actually used came from "
            f"**{winner}**, and that is what this nest records and reinstalls, so rebuilds "
            f"stay consistent. Worth knowing: which one wins decides what the machine has "
            f"to provide. If you meant only one of them, dropping "
            f"{' and '.join(others)} from the list makes this unambiguous."
        )
    return entries, notes


def _libs_dir_family(survivor: Path, site_packages: Path) -> str | None:
    """The family a compiled module belongs to, read from the ``<family>.libs``
    folder it searches (RUNPATH), or failing that from which ``*.libs`` folder
    holds the bundled libraries it names. Returns the folder stem, or None."""
    for seg in elf_runpaths(survivor):
        stem = Path(seg).name
        if stem.endswith(".libs"):
            return stem[:-len(".libs")]
    needed = set(elf_needed(survivor))
    if not needed:
        return None
    holders = [d for d in sorted(site_packages.glob("*.libs")) if d.is_dir()
               and any((d / n).exists() for n in needed)]
    if len(holders) == 1:
        return holders[0].name[:-len(".libs")]
    return None
