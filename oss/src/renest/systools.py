"""System tools a restore needs from the machine -- and installing them when we can.

A nest carries files and a dependency list; it cannot carry the machine's own programs.
Three of them decide whether a rebuild works and are cheap to add: ``git`` (a dependency
installed straight from a git repository), a C compiler (``triton`` builds a helper with
it the first time a model runs -- real batch, 2026-10: "Failed to find C compiler",
fixed by the user installing build-essential -- and any package built from source), and
``git-lfs`` (setup commands that pull large files).

**What a nest tells us, and what it cannot.** Needs are derived only from data the nest
records: lock lines (``git+`` sources, ``triton``, packages known to be built from source,
lines pinned to a source archive) and the setup commands it brings (``post_install``).
It cannot tell us whether a package with no ready-made build for *this* machine will
compile here (that depends on the machine, and only the install finds out), nor whether a
custom node calls ``git`` or a compiler at run time. Those still surface as errors later,
and those errors name the tool and the command (:func:`missing_tool_in`,
:func:`missing_tool_advice`).

**Installing, not just telling.** When this account is root or has password-free sudo,
the restore offers to install what is missing before anything is downloaded, and
``--yes`` installs without asking. Without that privilege, or with nobody at the
keyboard, it prints one command to paste and carries on as before. The escape hatch
(``restore.sh``) is unchanged: it only ever informs.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "MANAGERS",
    "PACKAGES",
    "TOOL_CC",
    "TOOL_GIT",
    "TOOL_LFS",
    "Machine",
    "Need",
    "SystemPlan",
    "Outcome",
    "needs_from_nest",
    "needs_from_code",
    "programs_called_in",
    "tool_present",
    "package_manager",
    "privilege",
    "install_commands",
    "pasteable",
    "plan_system_install",
    "ensure_system_tools",
    "missing_tool_in",
    "missing_tool_advice",
]

TOOL_GIT = "git"
TOOL_LFS = "git-lfs"
TOOL_CC = "c-compiler"
#: A program a custom node runs by name through ``subprocess`` (probe H, 2026-10-08:
#: a node calling ``ffmpeg`` restored byte for byte and then died on
#: ``FileNotFoundError: 'ffmpeg'`` -- nothing at pack or restore said a word).
TOOL_FFMPEG = "ffmpeg"

#: How a tool is named to a person.
LABEL = {TOOL_GIT: "git", TOOL_LFS: "git-lfs", TOOL_CC: "a C compiler", TOOL_FFMPEG: "ffmpeg"}

#: The package managers we drive, in the order they are looked for. ``dnf`` before
#: ``yum``: on machines that have both, ``yum`` is a compatibility shim.
MANAGERS: tuple[str, ...] = ("apt-get", "dnf", "yum", "apk")

#: Which packages bring each tool, per package manager.
PACKAGES: dict[str, dict[str, tuple[str, ...]]] = {
    # ffmpeg is in Debian/Ubuntu and Alpine main; Fedora/RHEL ship it only from an extra
    # repository (RPM Fusion), so there it is named, never installed for the user.
    "apt-get": {TOOL_GIT: ("git",), TOOL_LFS: ("git-lfs",), TOOL_CC: ("build-essential",),
                TOOL_FFMPEG: ("ffmpeg",)},
    "dnf": {TOOL_GIT: ("git",), TOOL_LFS: ("git-lfs",), TOOL_CC: ("gcc", "gcc-c++", "make"),
            TOOL_FFMPEG: ()},
    "yum": {TOOL_GIT: ("git",), TOOL_LFS: ("git-lfs",), TOOL_CC: ("gcc", "gcc-c++", "make"),
            TOOL_FFMPEG: ()},
    "apk": {TOOL_GIT: ("git",), TOOL_LFS: ("git-lfs",), TOOL_CC: ("build-base",),
            TOOL_FFMPEG: ("ffmpeg",)},
}

#: Packages that compile something with the machine's C compiler when they first run.
#: Only ones with real evidence: triton's "Failed to find C compiler" on a restored
#: machine (batch 22, 2026-10), fixed by installing build-essential.
_JIT_NEEDS_CC = frozenset({"triton"})

#: Packages that are always built from source on the installing machine (kept in step
#: with ``envlock.COMPILE_REQUIRED_PACKAGES``).
_ALWAYS_BUILT = frozenset({"flash-attn", "mamba-ssm", "causal-conv1d"})

_VCS = re.compile(r"\b(?:git)\+(?:https?|ssh|git|file)://", re.IGNORECASE)
_SDIST_URL = re.compile(r"https?://\S+\.(?:tar\.gz|tar\.bz2|tgz|zip)(?:[#?]\S*)?(?:\s|$)",
                        re.IGNORECASE)
_GIT_WORD = re.compile(r"(?:^|[\s;&|(`$])git(?:\s|$)")
_LFS_WORDS = re.compile(r"(?:^|[\s;&|(`$])git(?:\s+-\S+)*\s+lfs\b|\bgit-lfs\b")


def _names(names: Sequence[str], limit: int = 3) -> str:
    """``a``, ``a and b``, ``a, b and c``, ``a, b, c and 2 more``."""
    shown = list(names[:limit])
    rest = len(names) - len(shown)
    if rest > 0:
        return ", ".join(shown) + f" and {rest} more"
    if len(shown) <= 1:
        return "".join(shown)
    return ", ".join(shown[:-1]) + " and " + shown[-1]


def _canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _lock_lines(lock_text: str) -> list[tuple[str, str]]:
    """``(canonical name, line)`` for each requirement line of a lock."""
    out: list[tuple[str, str]] = []
    for raw in (lock_text or "").splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-r ", "-c ", "--")):
            continue
        stem = re.sub(r"^-e\s+", "", line)
        stem = re.split(r"\s+@\s+|===|==|>=|<=|~=|!=|<|>|@|;|\s", stem, maxsplit=1)[0]
        out.append((_canon(stem.split("[", 1)[0]), line))
    return out


@dataclass(frozen=True)
class Need:
    tool: str
    why: str


def _setup_commands(manifest: dict | None) -> list[str]:
    m = manifest or {}
    cmds: list[str] = []
    if isinstance(m.get("post_install"), str):
        cmds.append(m["post_install"])
    for dep in m.get("code_deps") or []:
        if isinstance(dep, dict) and isinstance(dep.get("post_install"), str):
            cmds.append(dep["post_install"])
    return cmds


def needs_from_nest(lock_text: str | None, manifest: dict | None) -> list[Need]:
    """Which system tools this nest will call on, read only from what it records."""
    lines = _lock_lines(lock_text or "")
    reasons: dict[str, list[str]] = {}

    def add(tool: str, why: str) -> None:
        reasons.setdefault(tool, [])
        if why not in reasons[tool]:
            reasons[tool].append(why)

    vcs = [name for name, line in lines if _VCS.search(line)]
    if vcs:
        add(TOOL_GIT, f"the dependency list installs {_names(vcs)} straight from "
                      f"{'a git repository' if len(vcs) == 1 else 'git repositories'}")
    setup = _setup_commands(manifest)
    if any(_LFS_WORDS.search(c) for c in setup):
        add(TOOL_LFS, "a setup command this nest runs uses git lfs")
        add(TOOL_GIT, "a setup command this nest runs uses git")
    elif any(_GIT_WORD.search(c) for c in setup):
        add(TOOL_GIT, "a setup command this nest runs uses git")
    names = {name for name, _ in lines}
    for jit in sorted(names & _JIT_NEEDS_CC):
        add(TOOL_CC, f"{jit} builds a small helper with the machine's C compiler the "
                     f"first time it runs")
    built = sorted(names & _ALWAYS_BUILT)
    if built:
        add(TOOL_CC, f"{_names(built)} {'is' if len(built) == 1 else 'are'} compiled "
                     f"from source on this machine")
    sdists = sorted({name for name, line in lines
                     if _SDIST_URL.search(line) and not _VCS.search(line)})
    if sdists:
        one = len(sdists) == 1
        add(TOOL_CC, f"{_names(sdists)} {'is' if one else 'are'} pinned to "
                     f"{'a source archive' if one else 'source archives'}, so "
                     f"{'it is' if one else 'they are'} compiled on this machine")
    order = (TOOL_GIT, TOOL_LFS, TOOL_CC)
    return [Need(t, "; ".join(reasons[t])) for t in order if t in reasons]


#: Programs a custom node may run by name that a nest cannot carry and a package
#: manager can install. Kept tiny and evidence-led: each entry is a program real nodes
#: shell out to (video nodes call ffmpeg / ffprobe), mapped to the tool that brings it.
_CALLED_PROGRAMS = {"ffmpeg": TOOL_FFMPEG, "ffprobe": TOOL_FFMPEG}
#: The program name as a string literal on its own -- ``"ffmpeg"`` or ``'ffprobe'`` --
#: which is how ``subprocess.run(["ffmpeg", ...])`` and ``shutil.which("ffmpeg")`` spell
#: it. A name inside a longer string (a path, a sentence) does not count.
_PROGRAM_LITERAL = re.compile(r"""["'](ffmpeg|ffprobe)["']""")
#: Only files that can start a program at all.
_RUNS_PROGRAMS = re.compile(
    r"\bsubprocess\b|\bos\.(?:system|popen|exec\w*|spawn\w*)\b|\bshutil\.which\b")
#: Folders inside a code tree that are somebody else's installed code, not the node's.
_SKIP_DIRS = frozenset({".git", "__pycache__", "node_modules", "site-packages", ".venv", "venv"})
_MAX_SOURCE_BYTES = 2 << 20


def programs_called_in(code_dir: Path) -> dict[str, list[str]]:
    """``{program: [files that call it]}`` for the programs in ``_CALLED_PROGRAMS`` that
    the Python files under ``code_dir`` start by name. Read off the source: a node's
    call to ffmpeg happens only when it runs, long after packing and restoring."""
    found: dict[str, list[str]] = {}
    if not code_dir.is_dir():
        return found
    for dirpath, dirnames, filenames in os.walk(code_dir):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for fn in sorted(filenames):
            if not fn.endswith(".py"):
                continue
            f = Path(dirpath) / fn
            try:
                if f.stat().st_size > _MAX_SOURCE_BYTES:
                    continue
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if not _RUNS_PROGRAMS.search(text):
                continue
            for prog in sorted(set(_PROGRAM_LITERAL.findall(text))):
                found.setdefault(prog, []).append(f.relative_to(code_dir).as_posix())
    return found


def needs_from_code(code_dirs: Sequence[tuple[str, Path]]) -> list[Need]:
    """System programs the restored code will start by name, from ``(label, folder)``
    pairs -- one per code folder. Unlike :func:`needs_from_nest` this reads the code
    itself, so it can only run once the code is on disk."""
    reasons: dict[str, list[str]] = {}
    for label, d in code_dirs:
        for prog, files in programs_called_in(d).items():
            tool = _CALLED_PROGRAMS[prog]
            why = f"{label} runs {prog} ({files[0]})"
            reasons.setdefault(tool, [])
            if why not in reasons[tool]:
                reasons[tool].append(why)
    return [Need(t, "; ".join(w)) for t, w in reasons.items()]


# --------------------------------------------------------------------------
# The machine
# --------------------------------------------------------------------------
def _default_run(argv: Sequence[str]) -> int:
    try:
        return subprocess.run(list(argv), capture_output=True, timeout=10, check=False).returncode
    except (OSError, subprocess.SubprocessError):
        return 127


def _default_stream(argv: Sequence[str], env: dict[str, str] | None) -> tuple[int, str]:
    """Run one install command with its output shown live (on stderr, so ``--json``'s
    stdout stays machine-clean). Returns the exit code and the output's tail."""
    tail: list[str] = []
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv is built from fixed package names
            list(argv), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env={**os.environ, **(env or {})}, bufsize=1,
        )
    except OSError as e:
        return 127, str(e)
    assert proc.stdout is not None
    for line in proc.stdout:
        sys.stderr.write(f"    {line}")
        sys.stderr.flush()
        tail.append(line)
        del tail[:-40]
    return proc.wait(), "".join(tail)


def _default_ask(prompt: str) -> str:
    sys.stderr.write(prompt)
    sys.stderr.flush()
    try:
        return sys.stdin.readline()
    except (OSError, ValueError):
        return ""


def _default_interactive() -> bool:
    try:
        return sys.stdin.isatty() and sys.stderr.isatty()
    except (AttributeError, ValueError):
        return False


@dataclass
class Machine:
    """Everything this module asks of the machine, in one place so tests can swap it."""

    which: Callable[[str], str | None] = shutil.which
    run: Callable[[Sequence[str]], int] = _default_run
    stream: Callable[[Sequence[str], dict[str, str] | None], tuple[int, str]] = _default_stream
    geteuid: Callable[[], int] = field(default=lambda: os.geteuid() if hasattr(os, "geteuid") else -1)
    interactive: Callable[[], bool] = _default_interactive
    ask: Callable[[str], str] = _default_ask
    environ: dict[str, str] | None = None


def tool_present(tool: str, machine: Machine | None = None) -> bool:
    m = machine or Machine()
    if tool == TOOL_GIT:
        return bool(m.which("git"))
    if tool == TOOL_LFS:
        return bool(m.which("git-lfs"))
    if tool == TOOL_CC:
        cc = ((m.environ if m.environ is not None else os.environ).get("CC") or "").split()
        if cc and m.which(cc[0]):
            return True
        return any(m.which(c) for c in ("gcc", "clang", "cc"))
    if tool == TOOL_FFMPEG:
        return bool(m.which("ffmpeg"))
    raise ValueError(tool)


def package_manager(machine: Machine | None = None) -> str | None:
    m = machine or Machine()
    return next((pm for pm in MANAGERS if m.which(pm)), None)


def privilege(machine: Machine | None = None) -> str:
    """``root``, ``sudo`` (password-free) or ``none``."""
    m = machine or Machine()
    if m.geteuid() == 0:
        return "root"
    if m.which("sudo") and m.run(["sudo", "-n", "true"]) == 0:
        return "sudo"
    return "none"


_APT_ENV = ("env", "DEBIAN_FRONTEND=noninteractive")


def install_commands(manager: str, packages: Sequence[str], *, sudo: bool) -> list[list[str]]:
    pre = ["sudo"] if sudo else []
    pkgs = list(packages)
    if manager == "apt-get":
        return [pre + ["apt-get", "update"],
                pre + [*_APT_ENV, "apt-get", "install", "-y", "--no-install-recommends", *pkgs]]
    if manager in ("dnf", "yum"):
        return [pre + [manager, "install", "-y", *pkgs]]
    if manager == "apk":
        return [pre + ["apk", "add", "--no-cache", *pkgs]]
    raise ValueError(manager)


def pasteable(manager: str, packages: Sequence[str], *, sudo: bool) -> str:
    return " && ".join(shlex.join(c) for c in install_commands(manager, packages, sudo=sudo))


@dataclass
class SystemPlan:
    missing: list[Need]                 # tools this nest needs and this machine lacks
    lib_packages: dict[str, str]        # library file -> package that brings it
    manager: str | None
    packages: list[str]
    privilege: str

    def command(self, *, sudo: bool | None = None) -> str:
        if not self.manager or not self.packages:
            return ""
        use = (self.privilege != "root") if sudo is None else sudo
        return pasteable(self.manager, self.packages, sudo=use)


def plan_system_install(
    needs: Sequence[Need],
    *,
    lib_packages: dict[str, str] | None = None,
    machine: Machine | None = None,
) -> SystemPlan | None:
    """What is missing here and what would bring it. ``None`` = nothing to do.

    ``lib_packages`` are Debian/Ubuntu package names (that is what the packing machine
    and the built-in table know), so they are only offered when this machine uses
    apt-get; elsewhere the existing missing-library advice stands on its own."""
    m = machine or Machine()
    missing = [n for n in needs if not tool_present(n.tool, m)]
    manager = package_manager(m)
    libs = dict(lib_packages or {}) if manager == "apt-get" else {}
    if not missing and not libs:
        return None
    packages: list[str] = []
    if manager:
        for n in missing:
            for p in PACKAGES[manager][n.tool]:
                if p not in packages:
                    packages.append(p)
        for p in libs.values():
            if p not in packages:
                packages.append(p)
    return SystemPlan(missing=missing, lib_packages=libs, manager=manager,
                      packages=packages, privilege=privilege(m))


@dataclass
class Outcome:
    #: installed | declined | no-keyboard | no-privilege | no-manager | failed
    status: str
    still_missing: list[str] = field(default_factory=list)
    message: str = ""

    @property
    def failed(self) -> bool:
        return self.status == "failed"


def _what_is_missing(plan: SystemPlan) -> list[str]:
    lines = [f"  - {LABEL[n.tool]}: {n.why}" for n in plan.missing]
    for lib, pkg in plan.lib_packages.items():
        lines.append(f"  - {lib} (package {pkg}): the working run loaded this system library")
    return lines


def ensure_system_tools(
    plan: SystemPlan,
    *,
    assume_yes: bool,
    say: Callable[[str], None],
    rerun: str,
    machine: Machine | None = None,
    recheck_libs: Callable[[list[str]], list[str]] | None = None,
    before: str = "The nest's files have not been downloaded yet. ",
) -> Outcome:
    """Install what ``plan`` names when this machine lets us; otherwise say how.

    Never hangs: with nobody at the keyboard and no ``--yes`` it prints the command
    and returns. Never raises: the caller decides what a failed install means.
    ``before`` opens the failure message with what has not happened yet (a restore:
    nothing downloaded; a pack: nothing packed)."""
    m = machine or Machine()
    what = [LABEL[n.tool] for n in plan.missing] + list(plan.lib_packages)
    head = ["This machine is missing what this nest needs:", *_what_is_missing(plan)]
    again = f"Then run the same command again: {rerun}"
    if not plan.manager:
        say("\n".join(head + [
            f"This machine has none of the package managers renest can drive "
            f"({', '.join(MANAGERS)}), so install {', '.join(what)} with your system's own "
            f"installer. {again}"]))
        return Outcome("no-manager", what)
    if plan.privilege == "none":
        say("\n".join(head + [
            "renest cannot install them itself: this account is not root and sudo asks "
            "for a password. Run this, then run the same command again:",
            f"  {plan.command(sudo=True)}",
            f"  {rerun}"]))
        return Outcome("no-privilege", what)
    cmd = plan.command()
    how = "as root" if plan.privilege == "root" else "with sudo"
    if not assume_yes:
        if not m.interactive():
            say("\n".join(head + [
                "Not installing them: nobody is at the keyboard to say yes. Run this, or "
                "add --yes to let renest install them itself:",
                f"  {cmd}",
                "Carrying on without them."]))
            return Outcome("no-keyboard", what)
        say("\n".join(head + [f"renest can install them now {how}:", f"  {cmd}"]))
        answer = (m.ask("Install them now? [Y/n] ") or "").strip().lower()
        if answer not in ("", "y", "yes"):
            say("\n".join([
                "Not installing them. To do it yourself later:", f"  {cmd}",
                "Carrying on without them."]))
            return Outcome("declined", what)
    else:
        say("\n".join(head + [f"Installing them now {how} (--yes):", f"  {cmd}"]))
    sudo = plan.privilege != "root"
    env = {"DEBIAN_FRONTEND": "noninteractive"} if plan.manager == "apt-get" else None
    for argv in install_commands(plan.manager, plan.packages, sudo=sudo):
        if sudo:
            argv = ["sudo", "-n", *argv[1:]]
        code, tail = m.stream(argv, env)
        if code != 0:
            msg = (f"Installing {', '.join(what)} failed: `{shlex.join(argv)}` exited {code}. "
                   f"{before}Install them yourself "
                   f"with: {cmd} -- the output above says why it failed. {again}")
            say(msg)
            return Outcome("failed", what, msg)
    still = [LABEL[n.tool] for n in plan.missing if not tool_present(n.tool, m)]
    if recheck_libs is not None and plan.lib_packages:
        still += recheck_libs(list(plan.lib_packages))
    if still:
        msg = (f"The install finished but {', '.join(still)} is still not on this machine. "
               f"Install it yourself with: {cmd} -- then run the same command again: {rerun}")
        say(msg)
        return Outcome("failed", still, msg)
    say(f"Installed: {', '.join(plan.packages)}.")
    return Outcome("installed")


# --------------------------------------------------------------------------
# Later failures that come down to one of these tools
# --------------------------------------------------------------------------
#: Words other programs print when one of these tools is not there. Copied from real
#: output, not written from memory -- 2026-10-07, a plain ubuntu:22.04 container with
#: neither git nor a compiler: uv's "Git executable not found. Ensure that Git is
#: installed and available." for a git+ requirement; git's own "git: 'lfs' is not a git
#: command" when git-lfs is absent; setuptools' "error: [Errno 2] No such file or
#: directory: 'c++'" building a source package; bash's "gcc: command not found".
#: triton's "Failed to find C compiler" is from the batch-22 restore (2026-10).
_TOOL_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (TOOL_LFS, re.compile(r"git: 'lfs' is not a git command|git-lfs: (?:command )?not found")),
    (TOOL_GIT, re.compile(r"git executable not found|\bgit: (?:command )?not found"
                          r"|no such file or directory: 'git'")),
    (TOOL_CC, re.compile(
        r"failed to find c compiler"
        r"|no such file or directory: '(?:[\w.-]*-)?(?:gcc|g\+\+|c\+\+|cc|clang)'"
        r"|(?:^|[\s/:])(?:gcc|g\+\+|c\+\+|cc|clang): (?:command )?not found"
        r"|unable to execute '(?:[\w.-]*-)?(?:gcc|g\+\+|c\+\+|cc)'")),
)


def missing_tool_in(text: str | None) -> str | None:
    """Did this failure happen because git, git-lfs or a C compiler is not here?"""
    low = (text or "").lower()
    for tool, pattern in _TOOL_MARKERS:
        if pattern.search(low):
            return tool
    return None


def missing_tool_advice(tool: str, rerun: str, machine: Machine | None = None) -> str:
    """One sentence that names the tool, the command that installs it here, and the
    command to run afterwards."""
    m = machine or Machine()
    manager = package_manager(m)
    name = LABEL[tool]
    if manager:
        priv = privilege(m)
        cmd = pasteable(manager, PACKAGES[manager][tool], sudo=priv != "root")
        how = f"Install it with: {cmd}"
    else:
        how = (f"Install it with your system's own installer (none of "
               f"{', '.join(MANAGERS)} is on this machine)")
    return (f"This failed because {name} is not installed on this machine -- it is a "
            f"program the machine provides, not part of the nest, and your files are not "
            f"damaged. {how} -- then run the same command again: {rerun}")
