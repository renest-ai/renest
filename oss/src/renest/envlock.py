"""Read a dependency list live from **the Python environment that is running**,
for environments that ship no lock file at all.

The ComfyUI desktop build is one: no requirements.lock, no uv.lock, not even a
requirements.txt, so skipping what we cannot find leaves a nest whose owner has
to retype hundreds of versions by hand. Reading the interpreter is legitimate
because a nest only captures a run that worked: what is installed *is* that run.

It asks the interpreter to report on itself (stdlib ``importlib.metadata``;
installs nothing, touches no network) and emits exact ``name==version`` pins, so
the trusted-index, mixed-CUDA and wheel-pinning checks all keep applying. The
**honest limit**, stated in the generated file and as a pack-time warning: no
hashes and no original index, so private indexes and vendor builds (torch's
``+cu124``) will not come back this way.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

__all__ = [
    "LOCK_FROM_INSTALLED_HEADER",
    "LOCK_FROM_ENV_HEADER",
    "env_dir_of",
    "find_env_python",
    "find_launchers",
    "find_site_packages",
    "freeze_environment",
    "freeze_from_installed",
    "interpreter_kernel",
    "launcher_interpreter_dir",
    "interpreter_python_series",
    "venv_python_candidates",
]

#: Header lines of the generated file, so whoever receives the nest can see at a
#: glance where this list came from.
LOCK_FROM_ENV_HEADER = (
    "# Read from the Python environment that ran this workflow — there was no lock\n"
    "# file to pack. Versions are pinned exactly as they were installed; package\n"
    "# hashes and original index URLs were not recorded, so a restore installs these\n"
    "# versions from the public index.\n"
)

#: The probe handed to that interpreter to execute. Stdlib only: installs
#: nothing, touches no network.
_FREEZE_SNIPPET = (
    "import importlib.metadata as m;"
    "seen=sorted({(d.metadata['Name'] or '').strip(): d.version "
    "for d in m.distributions() if d.metadata['Name']}.items(), "
    "key=lambda kv: kv[0].lower());"
    "print('\\n'.join(f'{n}=={v}' for n, v in seen if v))"
)


def find_env_python(candidates: list[Path]) -> Path | None:
    """Pick the first interpreter that actually works: it exists, it runs, and it
    can report its own version.

    Only **explicitly given executables** count. We never fall back to guessing
    ``python`` from ``PATH``: that is usually a different environment, and passing
    its dependencies off as the dependencies of the run that worked is worse than
    having no list at all.
    """
    for c in candidates:
        if not c or not c.is_file():
            continue
        try:
            out = subprocess.run(
                [str(c), "-c", "import sys; print(sys.version_info[0])"],
                capture_output=True, text=True, timeout=30, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if out.returncode == 0 and out.stdout.strip() == "3":
            return c
    return None


def venv_python_candidates(*roots: Path) -> list[Path]:
    """The usual virtualenv locations: the standard install puts ``.venv`` at the
    environment root, while the desktop build puts it under the data dir."""
    out: list[Path] = []
    for r in roots:
        if r is None:
            continue
        for rel in (".venv/bin/python", ".venv/Scripts/python.exe", "venv/bin/python"):
            out.append(r / rel)
    return out


def _uv_freeze(python_exe: str | Path) -> str | None:
    """Export through uv first. **This path is a correctness fix, not an optional
    optimisation.**

    The stdlib fallback below enumerates installed distributions, so it can only
    emit ``name==version``. The fine-tuning frameworks install themselves into the
    venv as editable installs, which come out as ``library==0.0.1`` /
    ``llamafactory==0.9.4`` — names that exist on no index, so a restore from such
    a line is guaranteed to fail. uv writes them as
    ``-e file:///absolute/path/to/source`` instead, which ``uv pip sync`` accepts.
    """
    venv = Path(python_exe).parent.parent
    try:
        out = subprocess.run(  # noqa: S603
            ["uv", "pip", "freeze", "--python", str(python_exe)],
            capture_output=True, text=True, timeout=300, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 or not out.stdout.strip():
        return None
    _ = venv
    return out.stdout.strip()


def freeze_environment(python_exe: str | Path) -> str | None:
    """Ask the interpreter which packages it has and at which versions. Returns
    ``None`` when it cannot be read — we report that honestly rather than invent a
    list.

    Two routes, and **the order matters**: uv first, because it understands
    editable installs; the stdlib-only route second, so machines without uv can
    still be captured, at the cost of not being able to express an editable
    install.
    """
    body = _uv_freeze(python_exe)
    if body:
        return LOCK_FROM_ENV_HEADER + body + "\n"
    try:
        out = subprocess.run(
            [str(python_exe), "-c", _FREEZE_SNIPPET],
            capture_output=True, text=True, timeout=180, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    body = out.stdout.strip()
    if not body:
        return None
    return LOCK_FROM_ENV_HEADER + body + "\n"


# -------------------------------------------------- reading it without running it --
# Everything above needs the interpreter to run. A shared all-in-one bundle breaks
# that: 2026-08-13, a Windows bundle packed from a Mac had 132 installed packages and
# we recorded none, because its interpreter was a ``python310.dll`` we cannot execute.
# The files alone answer it -- every installed package leaves a ``.dist-info`` folder
# with its name and version. Weaker than asking the interpreter (an editable install
# has no honest pin here), so it stays the last resort, and the generated file says so.

LOCK_FROM_INSTALLED_HEADER = (
    "# Worked out from the packages installed in this environment, by reading their\n"
    "# own metadata files — there was no lock file, and this environment's Python\n"
    "# could not be run on the packing machine. Versions are what is installed;\n"
    "# package hashes and original index URLs were not recorded. Packages installed\n"
    "# from a source folder cannot be expressed this way and are missing here.\n"
)

#: Where a site-packages folder sits, relative to a root we were handed. Bounded on
#: purpose: a whole-tree search over an environment holding hundreds of GB of weights
#: costs minutes and finds nothing extra.
_SITE_PACKAGES_GLOBS = (
    "Lib/site-packages", "lib/site-packages", "lib/python*/site-packages",
    "*/Lib/site-packages", "*/lib/site-packages", "*/lib/python*/site-packages",
    "*/*/Lib/site-packages", "*/*/lib/python*/site-packages",
)


def find_site_packages(*roots: Path) -> Path | None:
    """First site-packages folder found under any of ``roots``, or ``None``."""
    for r in roots:
        if r is None or not r.is_dir():
            continue
        for pattern in _SITE_PACKAGES_GLOBS:
            for hit in sorted(r.glob(pattern)):
                if hit.is_dir():
                    return hit
    return None


def env_dir_of(site_packages: Path) -> Path:
    """The environment root a site-packages folder belongs to.

    Windows lays it out as ``<env>/Lib/site-packages``, POSIX as
    ``<env>/lib/python3.11/site-packages``.
    """
    parent = site_packages.parent
    if parent.name.startswith("python") and parent.parent.name.lower() == "lib":
        return parent.parent.parent
    if parent.name.lower() == "lib":
        return parent.parent
    return parent


def _name_and_version(dist_info: Path) -> tuple[str, str] | None:
    """Read Name/Version out of a dist-info METADATA header block."""
    meta = dist_info / "METADATA"
    if not meta.is_file():
        return None
    name = version = ""
    try:
        with meta.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    break               # headers end at the first blank line
                low = line.lower()
                if low.startswith("name:") and not name:
                    name = line.split(":", 1)[1].strip()
                elif low.startswith("version:") and not version:
                    version = line.split(":", 1)[1].strip()
                if name and version:
                    break
    except OSError:
        return None
    return (name, version) if name and version else None


def freeze_from_installed(site_packages: Path) -> str | None:
    """``name==version`` for every package installed under ``site_packages``."""
    found: dict[str, str] = {}
    for d in sorted(site_packages.glob("*.dist-info")):
        pair = _name_and_version(d)
        if pair:
            found.setdefault(pair[0], pair[1])
    if not found:
        return None
    body = "\n".join(f"{n}=={v}" for n, v in sorted(found.items(), key=lambda kv: kv[0].lower()))
    return LOCK_FROM_INSTALLED_HEADER + body + "\n"


#: Start scripts a shared bundle puts beside the application. Only the top two levels
#: are looked at: this is the file a user double-clicks, not something buried deep.
_LAUNCHER_SUFFIXES = (".bat", ".cmd", ".ps1", ".sh", ".command")
#: A start script is a few kilobytes. Anything larger is not one, and reading it would
#: only cost time.
_LAUNCHER_MAX_BYTES = 64 * 1024
_ASSIGNMENT = re.compile(r"^\s*(?:set\s+|export\s+|\$env:)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")
_VAR_REF = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%|\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_SCRIPT_DIR_REF = re.compile(r"%~[a-zA-Z]*0")


def find_launchers(env_root: Path) -> list[Path]:
    """Start scripts sitting at or just below the environment root."""
    if not env_root.is_dir():
        return []
    out = [p for pattern in ("*", "*/*") for p in sorted(env_root.glob(pattern))
           if p.is_file() and p.suffix.lower() in _LAUNCHER_SUFFIXES
           and p.stat().st_size <= _LAUNCHER_MAX_BYTES]
    return out


def launcher_interpreter_dir(script: Path) -> Path | None:
    """The interpreter folder a start script points at, if it names one that exists.

    A bundle's launcher spells out what the layout alone only implies -- which folder
    holds the Python, where the entry file is, which extra folders have to be on the
    search path. We read the variable assignments and follow the ones that turn out
    to be a real interpreter folder on disk. Anything we cannot resolve is skipped:
    guessing here would be worse than the layout scan this backs up.
    """
    try:
        text = script.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    here = script.parent
    values: dict[str, str] = {}
    for line in text.splitlines():
        m = _ASSIGNMENT.match(line)
        if not m or line.lstrip().startswith(("#", "::", "rem ", "REM ")):
            continue
        values[m.group(1).upper()] = m.group(2).strip('"')
    for raw in values.values():
        resolved = _expand(raw, values, here)
        if resolved is None:
            continue
        cand = resolved if resolved.is_dir() else resolved.parent
        if interpreter_kernel(cand):
            return cand
    return None


def _expand(raw: str, values: dict[str, str], here: Path) -> Path | None:
    """``%PYTHON_ENV%\\python.exe`` -> an absolute path, or ``None`` if we can't."""
    def sub(m: re.Match[str]) -> str:
        name = (m.group(1) or m.group(2) or "").upper()
        return values.get(name, "\x00")     # unknown -> poison, so we give up below
    # Variables are built out of each other (`PYTHON_ENV=%ROOT_DIR%\...`), so one pass
    # only swaps in another variable's still-unexpanded text. Repeat until it settles.
    # `%~dp0` (the folder the script sits in) carries no closing %, unlike everything
    # else in a .bat, so it needs its own pass inside the loop.
    text = raw
    for _ in range(8):
        nxt = _VAR_REF.sub(sub, _SCRIPT_DIR_REF.sub(str(here) + "/", text))
        if nxt == text:
            break
        text = nxt
    text = text.replace("\\", "/")
    if "\x00" in text or "%" in text or "$" in text or not text.strip():
        return None
    p = Path(text.replace("//", "/"))
    if not p.is_absolute():
        p = here / p
    try:
        return p.resolve() if p.exists() else None
    except OSError:
        return None


def interpreter_kernel(env_dir: Path) -> str | None:
    """Which operating-system family this environment's interpreter is built for.

    Read off the files, never off the machine we happen to be running on: told apart
    by ``python.exe``/``pythonNN.dll`` versus a ``bin/python``. ``None`` means we
    could not tell, which must stay distinguishable from "same as here".
    """
    if not env_dir.is_dir():
        return None
    if (env_dir / "python.exe").is_file() or any(env_dir.glob("python*.dll")):
        return "windows"
    if (env_dir / "bin" / "python").exists() or any(env_dir.glob("bin/python3*")):
        return "posix"
    return None


def interpreter_python_series(env_dir: Path) -> str | None:
    """``3.10`` from ``python310.dll`` or ``lib/python3.10/``. Two components only.

    Deliberately not passed off as ``runtime.python_version``: that field is spelled
    ``3.x.y`` and the third number is not written anywhere in these layouts. Half an
    answer belongs in a warning, never in the manifest.
    """
    if not env_dir.is_dir():
        return None
    for dll in sorted(env_dir.glob("python[0-9][0-9]*.dll")):
        digits = dll.stem.removeprefix("python")
        if digits.isdigit() and len(digits) >= 2:
            return f"{digits[0]}.{digits[1:]}"
    for lib in sorted(env_dir.glob("lib/python3.*")):
        if lib.is_dir():
            return lib.name.removeprefix("python")
    return None
