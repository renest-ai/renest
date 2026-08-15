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

import os
import re
import struct
import subprocess
from pathlib import Path

__all__ = [
    "collect_native_libs",
    "elf_needed",
    "elf_soname",
    "looks_like_the_working_run",
    "missing_native_libs",
]

_DT_NULL, _DT_NEEDED, _DT_STRTAB, _DT_STRSZ, _DT_SONAME = 0, 1, 5, 10, 14

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
    """Return (this file's own name, the names it declares it needs), or None when
    the file is not a shared object we can read.

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

            return (s(soname_at) if soname_at is not None else None, [s(o) for o in needed_at])
    except (OSError, struct.error, ValueError, IndexError):
        return None


def elf_soname(path: Path) -> str | None:
    got = _read_elf(path)
    return got[0] if got else None


def elf_needed(path: Path) -> list[str]:
    got = _read_elf(path)
    return got[1] if got else []


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
