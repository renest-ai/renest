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
import json
import os
import re
import struct
import subprocess
from collections.abc import Sequence
from pathlib import Path

from .envlock import canonical_name, installed_dist_infos

__all__ = [
    "CONTESTED_MODULES",
    "LAYER_INTERPRETER",
    "LAYER_MACHINE",
    "LAYER_NEST",
    "collect_native_libs",
    "collect_native_libs_with_layers",
    "record_search_roots",
    "contested_module_missing_libs",
    "contested_winners",
    "elf_needed",
    "elf_runpaths",
    "elf_soname",
    "interpreter_site_packages",
    "library_layer",
    "lock_requirement_for",
    "lock_requirements",
    "looks_like_the_working_run",
    "machine_libs_checkable",
    "missing_native_libs",
    "split_by_layer",
    "this_platform_tag",
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


#: Prefixes that belong to the machine's distribution rather than to one interpreter.
#: A Python rooted at one of these **is** the distribution's, so its libraries are the
#: machine's and stay on the list. `/usr/local` falls under `/usr` on purpose: the
#: restore side looks for libraries in `/usr/local/lib` too, so a name found there is
#: answerable and dropping it would lose a true warning.
_DISTRO_PREFIXES = (Path("/usr"),)

#: Where a library was loaded from, as three kinds that a rebuild treats differently.
LAYER_NEST = "nest"                # travels inside the nest; never a machine requirement
LAYER_INTERPRETER = "interpreter"  # the packing interpreter's own; see library_layer
LAYER_MACHINE = "machine"          # the machine must provide it, or a rebuild is short


def library_layer(path: str | os.PathLike[str], nest_roots: Sequence[Path],
                  interpreter_prefix: Path | None) -> str:
    """Which of the three kinds this loaded file is, **decided by where it sits**.

    ``interpreter`` is the one that had no name before, and it is why this function
    exists. Measured 2026-08-30 in a `continuumio/miniconda3` container running the
    shipping collector against a live conda interpreter: of 13 libraries the run
    loaded, **8 came out of `/opt/conda/lib`** -- the interpreter's own copies of
    ssl, sqlite, lzma, ffi, bz2, uuid, z and crypto -- and 5 out of the
    distribution. A rebuild never uses that interpreter: restore creates the
    environment with ``uv venv --python <version>``, which brings its own. So a
    machine without those 8 is short of nothing, and saying it is short is a false
    alarm on a machine that would have worked.

    It is also the difference the old rule could not express. The base interpreter
    counted as the nest's only when it sat **inside the pack root**, so packing a
    conda environment directly hid conda's libraries while packing a `venv` built on
    top of that same conda reported every one of them -- same run, same files, two
    different answers depending on whether a `venv` sat in between.
    """
    p = Path(path)
    if _under(p, list(nest_roots)):
        return LAYER_NEST
    if interpreter_prefix is not None and _under(p, [interpreter_prefix]):
        return LAYER_INTERPRETER
    return LAYER_MACHINE


def _own_interpreter_prefix(home: Path | None, nest_roots: Sequence[Path]) -> Path | None:
    """The base interpreter's own prefix, when it is a place of its own.

    None when there is no such place: the interpreter lives inside the nest (its
    libraries already travel along), or it is the distribution's at ``/usr`` (its
    libraries really are the machine's, and dropping them would hide real gaps)."""
    if home is None or _under(home, list(nest_roots)):
        return None
    if any(home == d or _under(home, [d]) for d in _DISTRO_PREFIXES):
        return None
    return home


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


def os_release() -> str | None:
    """Which distribution this machine runs, as it names itself: ``"ubuntu 22.04"``.

    Recorded so a restore elsewhere can say *where* the package names below came from.
    A package name only means something next to its distribution: ``libGL.so.1`` is
    ``libgl1`` on Ubuntu, ``mesa-libGL`` on Fedora, ``libglvnd`` on Arch -- and on
    Ubuntu itself it was ``libgl1-mesa-glx`` before 22.04.
    """
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    got: dict[str, str] = {}
    for line in text.splitlines():
        k, _, v = line.partition("=")
        if v:
            got[k.strip()] = v.strip().strip('"')
    name = got.get("ID") or got.get("NAME")
    ver = got.get("VERSION_ID") or ""
    return f"{name} {ver}".strip() if name else None


def _paths_dpkg_might_know(path: str) -> list[str]:
    """The spellings of one file a package database might have recorded it under.

    **Measured on a live Ubuntu 22.04 machine, 2026-08-30** (three runs, $0.012):
    `dpkg -S /usr/lib/x86_64-linux-gnu/libc.so.6` answers "no path found matching
    pattern" and exits 1, even though the file is real (not a symlink) and dpkg holds
    237 package file lists. The reason is **merged-`/usr`**: `/lib` is a symlink to
    `/usr/lib`, and libc6's file list records the file under `/lib/...`, while the
    loader reports the path under `/usr/lib/...`. dpkg matches literal strings, so one
    spelling hits and the other misses -- and `Path.resolve()` makes it worse, since it
    canonicalises toward `/usr/lib`, away from what the database holds.

    So: ask about the path as seen, its resolved form, and both `/usr`-prefixed and
    `/usr`-stripped spellings. First answer wins; order is only about speed.
    """
    out = [path]
    try:
        real = str(Path(path).resolve())
    except OSError:
        real = path
    for candidate in (real,
                      path[4:] if path.startswith("/usr/") else "/usr" + path,
                      real[4:] if real.startswith("/usr/") else "/usr" + real):
        if candidate and candidate not in out:
            out.append(candidate)
    return out


def _packages_for(paths: dict[str, str]) -> dict[str, str]:
    """Which installed package owns each library file, **asked of this machine**.

    Why measured instead of a table: a library name maps to a different package on every
    distribution *and* on different releases of one -- ``libicudata.so.75`` is ``libicu75``
    on Ubuntu 24.04 and ``libicu70`` on 22.04, because the soname carries the version, so
    any table we wrote would go stale on the next ICU release without anyone noticing.
    The machine that ran the app already knows the answer; ask it once, at pack time.

    Unknown files are simply left out -- **a wrong package name is worse than none**
    (the same rule the small built-in table has followed since 2026-08-12).
    """
    out: dict[str, str] = {}
    for soname, path in paths.items():
        # **Ask about the real file, not the symlink.** Measured on a live machine
        # 2026-08-30: `dpkg -S /usr/lib/x86_64-linux-gnu/libc.so.6` answers "no path found
        # matching pattern" and exits 1 -- that name is a symlink `ldconfig` creates, and
        # no package ships it, so it is in no package's file list. The file it points at
        # (`libc-2.35.so`) is. Four of five libraries were lost to this before the resolve.
        tries = _paths_dpkg_might_know(path)
        for argv, cut in [(["dpkg", "-S", t], ":") for t in tries] + \
                         [(["rpm", "-qf", t], None) for t in tries]:
            try:
                r = subprocess.run(argv, capture_output=True, text=True, timeout=10)
            except (OSError, subprocess.SubprocessError):
                continue
            line = (r.stdout or "").strip().splitlines()
            if r.returncode != 0 or not line:
                continue
            first = line[0].strip()
            pkg = first.split(cut, 1)[0].strip() if cut else first
            # dpkg prints "pkg:arch: /path"; drop the architecture suffix.
            pkg = pkg.split(":", 1)[0].strip()
            if pkg and " " not in pkg:
                out[soname] = pkg
            break
    return out


def _loaded_machine_libs(pids: list[int], nest_roots: list[Path]) -> dict[str, str]:
    """Library names the run really loaded **from the machine**, as the program asked
    for them.

    Two rules that measurement forced, both easy to get wrong the other way:
    a library is the machine's or the nest's **by where it actually loaded from**, never
    by looking the name up (a common compression library sits under the same name inside
    an installed package while the machine's copy is the one in use); and the name is the
    file's own recorded name, copied verbatim -- most files on disk carry a version the
    program never asks for."""
    # **soname -> the file it actually loaded from.** The path used to be thrown away
    # here; it is what lets the packing machine be asked which package owns the file,
    # so a restore elsewhere gets a real package name instead of "look it up yourself".
    names: dict[str, str] = {}
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
            names.setdefault(elf_soname(p) or p.name, str(p))
    return names


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


#: Where the ComfyUI extension leaves the record of what a working run had loaded.
#: Reading a live process only works while the app is running; packing usually happens
#: hours later. Measured 2026-08-20 on one real environment: 97 libraries while running,
#: 29 from the fallback that reads what installed packages declare -- 76% lost.
RUN_RECORD_REL = ".renest/native-libs.json"


def record_search_roots(
    env_root: str | os.PathLike[str], record_roots: Sequence[str | os.PathLike[str]] = ()
) -> list[Path]:
    """Where to look for the run record, in order: our own root, then the callers'.

    **A named function on purpose.** Inline, the only way to test the order was to
    write the same list out again in the test -- and a test that rebuilds the logic
    it is checking passes no matter what the product does. That is exactly how the
    seam this exists for went unnoticed.
    """
    seen: dict[Path, None] = {}
    for r in [env_root, *record_roots]:
        seen.setdefault(Path(r).resolve(), None)
    return list(seen)


def read_run_record(root: str | os.PathLike[str]) -> dict | None:
    """The whole record the extension wrote when a run finished, or None when there is
    none to read there. It carries more than libraries -- video-memory readings ride
    along in it -- so the loading lives in one place and each reader takes its part.
    """
    try:
        raw = json.loads((Path(root) / RUN_RECORD_REL).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return raw if isinstance(raw, dict) else None


def _libs_from_run_record(root: Path, nest_roots: list[Path]) -> dict[str, str]:
    """``{soname: the file it actually loaded from}`` for the libraries named by the
    record the extension wrote when a run finished.

    The record holds raw paths and nothing else. **Which of them count and what each
    is called is decided here**, by the same rules a live process goes through -- one
    set of rules, in one place, so the two cannot drift apart.

    **The path is kept, not just the name.** It used to be dropped here and then
    guessed back by looking the name up in the distribution's library folders, which
    is a different file whenever the run loaded a different copy. Measured 2026-08-30
    in a `continuumio/miniconda3` container: of 13 libraries a live conda interpreter
    had loaded, the name lookup pointed at the wrong file for **8 of them** -- it
    answered `/usr/lib/x86_64-linux-gnu/libssl.so.3` for a run that loaded
    `/opt/conda/lib/libssl.so.3` -- so the package name recorded beside it described
    a file the run never touched.
    """
    raw = read_run_record(root)
    if raw is None:
        return {}
    paths = raw.get("mapped_library_paths")
    if not isinstance(paths, list):
        return {}
    found: dict[str, str] = {}
    for item in paths:
        if not isinstance(item, str) or not item.startswith("/"):
            continue
        p = Path(item)
        if not _is_lib(p.name) or _under(p, nest_roots) or not p.is_file():
            continue
        found.setdefault(elf_soname(p) or p.name, str(p))
    return dict(sorted(found.items()))


def collect_native_libs(
    env_root: str | os.PathLike[str],
    python: str | os.PathLike[str] | None = None,
    record_roots: Sequence[str | os.PathLike[str]] = (),
) -> dict | None:
    """The nest's machine-library list, or None when nothing could be established.

    Thin wrapper: :func:`collect_native_libs_with_layers` does the work and also hands
    back what it left off, for callers that want to say so.
    """
    return collect_native_libs_with_layers(env_root, python, record_roots)[0]


def collect_native_libs_with_layers(
    env_root: str | os.PathLike[str],
    python: str | os.PathLike[str] | None = None,
    record_roots: Sequence[str | os.PathLike[str]] = (),
) -> tuple[dict | None, dict[str, str]]:
    """``({"method": ..., "names": [...]} or None, {soname: file} left off)``.

    The first half is the nest's list -- None when nothing could be established, in
    which case write nothing rather than an empty list that reads like "this run
    needed none". The second half is what was **deliberately left off**: libraries the
    run loaded out of the packing interpreter's own installation. It is returned rather
    than discarded so the packing side can tell the user, which is the whole complaint
    this function was changed for -- the fact was being established and then thrown
    away in the same breath. Empty on an environment whose Python is uv-managed or the
    distribution's, because neither has a place of its own.

    ``record_roots``: extra places to look for the run record, tried in order after
    ``env_root``. The extension writes it beside the host application's own source,
    which is not always under the directory a pack is rooted at -- an install that
    keeps program and data in separate trees puts it in neither the pack root nor
    below it. Which directories those are is a fact about the host application, so
    the caller supplies them and this layer never names one.
    """
    if not Path("/proc").is_dir():
        return None, {}
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
    # The packing interpreter's own place, when it has one. Everything loaded out of it
    # is that interpreter's business, not the machine's -- see library_layer.
    interp = _own_interpreter_prefix(home, nest_roots)
    # "This environment's own program" first, "anything running under this folder"
    # only as a fallback — see _pids_running_in. **The base interpreter goes in only when
    # it lives inside this environment** (a uv-managed private Python does): a system one
    # sits at /usr, and searching there matched ten unrelated system processes on a real
    # machine and recorded their stdlib modules as libraries this run needed.
    by_exe = [p for p in nest_roots[1:] if p is not None]
    if home is not None and _under(home, [root]):
        by_exe.append(home)
    # The record the extension left at the moment a run finished comes first: it was
    # taken while everything the workflow needs was loaded, which is exactly the moment
    # this list is supposed to describe, and it survives the app being closed.
    # Own root first, then wherever the caller says the extension may have written.
    # **Why the parameter exists**: the extension writes beside the host application's
    # own source, which on a two-tree install is not under the pack root at all, so a
    # record from a real run was never found. Both halves had tests; the seam had none.
    recorded: dict[str, str] = {}
    for candidate in record_search_roots(root, record_roots):
        recorded = _libs_from_run_record(candidate, nest_roots)
        if recorded:
            break
    if recorded:
        by_path, theirs = split_by_layer(recorded, nest_roots, interp)
        if by_path and looks_like_the_working_run(list(by_path)):
            # **Ask the package manager about the file that was really loaded**, which
            # the record carried all along. This is the path a real pack takes: measured
            # 2026-08-30, the first packed 2.9 nest carried zero package names because
            # the resolution lived only on the live-process fallback below.
            got = _with_packages({"method": "loaded", "names": sorted(by_path)}, by_path)
            return got, theirs
    pids = _pids_running_in(by_exe, [root])
    seen = _loaded_machine_libs(pids, nest_roots) if pids else {}
    by_path, theirs = split_by_layer(seen, nest_roots, interp)
    loaded = sorted(by_path)
    # **Better a truthful fallback than a false authority.** A process matched here may
    # simply have been passing through; if what it loaded does not look like the run that
    # worked, drop back to the declared list and say so, rather than dressing it up as
    # the authoritative one.
    if loaded and looks_like_the_working_run(loaded):
        return _with_packages({"method": "loaded", "names": loaded}, by_path), theirs

    declared = _declared_machine_libs(site_dirs)
    # Nothing was reclassified on this branch: the declared list is read off installed
    # files, not off what a run loaded, so there is no path to classify by.
    return ({"method": "declared", "names": declared} if declared else None), {}


def _locate(names: list[str]) -> dict[str, str]:
    """Where a library of this name sits in the distribution's folders, if one does.

    **Not on the packing path any more, and not to be put back there.** It answers by
    name, and a name is not an identity: measured 2026-08-30 in the packing image, 9 of
    23 libraries existed under one file name in two places at once, and the copy the run
    loaded was never the distribution's. The run record carries the file each library
    actually loaded from, so pack asks about that file instead. Kept only for a
    development diagnostic that puts the two answers side by side; nothing the tool
    does calls it.
    """
    out: dict[str, str] = {}
    for name in names:
        for d in LIB_DIRS:
            f = Path(d) / name
            if f.is_file():
                out[name] = str(f)
                break
    return out


def split_by_layer(
    by_path: dict[str, str], nest_roots: Sequence[Path], interpreter_prefix: Path | None
) -> tuple[dict[str, str], dict[str, str]]:
    """Split ``{soname: file}`` into ``(the machine's, the packing interpreter's own)``.

    Only the first half belongs on a nest's machine list. A rebuild builds its own
    interpreter (``uv venv --python <version>``), so a machine without the second half
    is short of nothing -- reporting it is a false alarm on a machine that works.
    """
    mine: dict[str, str] = {}
    theirs: dict[str, str] = {}
    for name, path in by_path.items():
        layer = library_layer(path, nest_roots, interpreter_prefix)
        if layer == LAYER_INTERPRETER:
            theirs[name] = path
        elif layer == LAYER_MACHINE:
            mine[name] = path
    return mine, theirs


def _with_packages(out: dict, by_path: dict[str, str]) -> dict:
    """Attach the measured package names, when this machine can answer.

    Recorded rather than looked up in a table: a library name maps to a different package
    on every distribution and between releases of one (the soname carries the version), so
    a shipped table goes stale on the next release with nobody noticing.
    """
    if not by_path:
        return out
    pkgs = _packages_for(by_path)
    if pkgs:
        out["packages"] = dict(sorted(pkgs.items()))
        got = os_release()
        if got:
            out["packages_from"] = got
    return out


def this_platform_tag() -> str:
    """This machine's Python platform tag, or ``""`` when it cannot be read."""
    try:
        import sysconfig

        return str(sysconfig.get_platform() or "")
    except Exception:
        return ""


def machine_libs_checkable(platform_tag: str | None = None) -> bool:
    """Whether "does this machine have that library" can be answered here at all.

    A nest names Linux shared objects and they are looked up in Linux library
    folders. Ask that on macOS and every single one reads as missing, so a machine
    short of nothing is handed a full list of things it lacks -- and a warning that
    is always wrong is how people learn to skip the real one. Only a tag that says
    outright it is another system silences the check; an unreadable tag still gets
    checked, because losing a true warning costs more than an unnecessary look.
    No tag asks this machine; the escape hatch draws the same line from ``uname -s``.
    """
    tag = platform_tag or this_platform_tag()
    return str(tag).split("-", 1)[0].lower() in ("", "linux")


def missing_native_libs(names: list[str] | tuple[str, ...],
                        platform_tag: str | None = None) -> list[str]:
    """Which of these library names this machine does not have.

    Looked up by the exact name asked for, in the standard library folders -- the
    same thing the escape hatch does in shell, deliberately kept identical. **Not
    ``ldd``**: measured, it reported libraries the nest carries itself as missing and
    got the direction wrong on others, and a false alarm here trains people to ignore
    the real one. Empty off Linux, where the question has no meaning -- callers that
    report a count must ask :func:`machine_libs_checkable` first, or "nothing missing"
    will be printed where nothing was looked at."""
    if not machine_libs_checkable(platform_tag):
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
        req = re.split(r"\s+--hash=", req, maxsplit=1)[0]
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
