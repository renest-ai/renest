"""Git LFS placeholders in a code folder at pack time -- download them, or decide.

A node repository that keeps big files in Git LFS, cloned without ``git lfs pull``
(or with ``GIT_LFS_SKIP_SMUDGE=1``), holds a few hundred bytes of pointer text in
place of each of those files. tar archives that text, sha256 matches on restore,
and the rebuilt folder holds placeholders. Real case, batch 22 (2026-10): ComfyUI-
LTXVideo carried 13 of them, every one under ``example_workflows/assets`` --
example pictures and videos, not code -- and pack refused the whole nest with a
message that said the code would be missing.

What happens now, in order:

1. **Download them for the user.** When the folder is a git checkout, renest runs
   ``git lfs pull`` there after asking ``[Y/n]`` (``--yes`` skips the question;
   with nobody at the keyboard it does not ask and does not pull). When git or
   git-lfs is missing it offers to install them first, through
   :mod:`renest.systools` -- same question, same privilege rules as a restore.
2. **What is still a placeholder is judged by what it is.** Pictures, videos and
   documents (and example workflows/audio sitting in an example or docs folder)
   are not code or model weights; they are left out of the archive, and pack says
   so in one line naming them. Anything else could be code or weights the run
   loads, so pack keeps refusing -- with the reason the download did not happen
   and the exact command.

A placeholder standing in for a model listed in ``files[]`` is a different check
(:func:`renest.integrity.probe_model_bytes`) and stays an error.
"""

from __future__ import annotations

import shlex
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from . import systools

__all__ = [
    "MEDIA_SUFFIXES",
    "DOC_SUFFIXES",
    "unused_by_a_run",
    "split_placeholders",
    "pull_command",
    "refusal_message",
    "dropped_line",
    "Settled",
    "settle_placeholders",
]

#: Pictures and videos. A missing example picture never stops a run.
MEDIA_SUFFIXES = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".svg", ".ico",
    ".avif", ".heic",
    ".mp4", ".webm", ".mov", ".avi", ".mkv", ".m4v",
})
#: Documents. Not ``.txt``: a tokenizer's vocabulary is a ``.txt`` file code loads.
DOC_SUFFIXES = frozenset({".md", ".rst", ".pdf"})
#: Only inside an example or docs folder: a workflow ``.json`` or audio sample there
#: is example material; elsewhere a ``.json`` can be a config the code reads.
_EXAMPLE_ONLY_SUFFIXES = frozenset({".json", ".mp3", ".wav", ".flac", ".ogg", ".m4a"})
_EXAMPLE_DIRS = frozenset({
    "example", "examples", "example_workflows", "example-workflows", "workflows",
    "workflow", "docs", "doc", "assets", "demo", "demos", "samples",
})


def unused_by_a_run(rel: str) -> bool:
    """Is this path example material (a picture, a video, a document) rather than
    something a run could load as code or weights?"""
    p = PurePosixPath(rel)
    suffix = p.suffix.lower()
    if suffix in MEDIA_SUFFIXES or suffix in DOC_SUFFIXES:
        return True
    if suffix in _EXAMPLE_ONLY_SUFFIXES:
        return any(part.lower() in _EXAMPLE_DIRS for part in p.parts[:-1])
    return False


def split_placeholders(pointers: Sequence[str]) -> tuple[list[str], list[str]]:
    """``(left out, still needed)``."""
    drop = [r for r in pointers if unused_by_a_run(r)]
    keep = [r for r in pointers if not unused_by_a_run(r)]
    return drop, keep


def _named(items: Sequence[str], limit: int = 5) -> str:
    shown = list(items[:limit])
    rest = len(items) - len(shown)
    if rest > 0:
        return ", ".join(shown) + f" and {rest} more"
    if len(shown) == 1:
        return shown[0]
    return ", ".join(shown[:-1]) + " and " + shown[-1]


def pull_command(src_dir: Path | str) -> str:
    """The command that downloads the real files into this checkout."""
    return (f"cd {shlex.quote(str(src_dir))} && git lfs install --local "
            f"&& git lfs pull")


def refusal_message(install_path: str, needed: Sequence[str], src_dir: Path | str,
                    *, why: str | None = None, install_first: str = "",
                    is_checkout: bool = True, dry_run: bool = False) -> str:
    """Why pack stops on placeholders that could be code or model weights."""
    n = len(needed)
    lines = [
        f"{install_path} has {n} file{'s' if n != 1 else ''} that "
        f"{'are' if n != 1 else 'is'} only Git LFS pointer text -- a small placeholder, "
        f"not the real file: {_named(needed)}. "
        f"{'They' if n != 1 else 'It'} could be code or model weights the run loads, "
        f"so a nest without the real {'files' if n != 1 else 'file'} might not run.",
    ]
    if why:
        lines.append(f"  Not downloaded: {why}")
    if is_checkout:
        cmd = pull_command(src_dir)
        if install_first:
            cmd = f"{install_first} && {cmd}"
        it = "them" if n != 1 else "it"
        if dry_run:
            lines.append(f"  A real pack offers to download {it} first, and stops if it "
                         f"cannot. By hand:\n  {cmd}")
        else:
            lines.append(f"  Download {it}, then pack again:\n  {cmd}")
    else:
        lines.append(
            f"  This folder is not a git checkout, so `git lfs pull` cannot fetch "
            f"{'them' if n != 1 else 'it'} here: install this extension again with git-lfs "
            f"installed (a fresh `git clone` then downloads "
            f"{'them' if n != 1 else 'it'}), then pack again.")
    return "\n".join(lines)


def dropped_line(install_path: str, dropped: Sequence[str]) -> str:
    n = len(dropped)
    return (f"{install_path}: {n} Git LFS placeholder file{'s' if n != 1 else ''} "
            f"({_named(dropped)}) {'were' if n != 1 else 'was'} never downloaded. "
            f"{'They are' if n != 1 else 'It is'} example material (pictures, videos or "
            f"documents), not code or model weights, so {'they are' if n != 1 else 'it is'} "
            f"left out of the archive and the rebuild does not need "
            f"{'them' if n != 1 else 'it'}.")


@dataclass
class Settled:
    #: placeholders to leave out of the archive (relative to the code folder)
    dropped: list[str] = field(default_factory=list)
    #: placeholders that could be code or weights -- non-empty means refuse
    needed: list[str] = field(default_factory=list)
    #: why the download did not happen (None when it was not tried or worked)
    why: str | None = None
    #: a system-tool install command to put in front of the pull command
    install_first: str = ""
    is_checkout: bool = True
    pulled: bool = False


def _is_checkout(src_dir: Path) -> bool:
    return (src_dir / ".git").exists()


def _pull(src_dir: Path, install_path: str, n: int, *, assume_yes: bool, may_ask: bool,
          say: Callable[[str], None], rerun: str,
          machine: systools.Machine) -> tuple[bool, str | None, str]:
    """Try to download the real files. ``(pulled, why not, install command)``."""
    m = machine
    files = f"{n} file{'s' if n != 1 else ''}"
    interactive = may_ask and m.interactive()
    needs = [
        systools.Need(systools.TOOL_GIT, f"{install_path} has {files} kept in Git LFS "
                                         f"that this copy never downloaded"),
        systools.Need(systools.TOOL_LFS, f"git-lfs downloads the real {files} into "
                                         f"{install_path} (renest runs `git lfs pull` "
                                         f"there once it is installed)"),
    ]
    plan = systools.plan_system_install(needs, machine=m)
    if plan is not None and plan.missing:
        tools = " and ".join(systools.LABEL[n.tool] for n in plan.missing)
        are = "are" if len(plan.missing) > 1 else "is"
        no_priv = (f"{tools} {are} not installed here, and renest cannot install "
                   f"{'them' if len(plan.missing) > 1 else 'it'} on this account (not root, "
                   f"and sudo asks for a password).")
        if not (assume_yes or interactive):
            if plan.privilege == "none":
                return False, no_priv, plan.command()
            return False, (f"{tools} {are} not installed here, and nobody is at the keyboard "
                           f"to say yes to installing {'them' if len(plan.missing) > 1 else 'it'} "
                           f"(add --yes to let renest do it)."), plan.command()
        outcome = systools.ensure_system_tools(
            plan, assume_yes=assume_yes, say=say, rerun=rerun, machine=m,
            before="Nothing has been packed yet. ")
        if outcome.status != "installed":
            reasons = {
                "declined": f"you chose not to install {tools}.",
                "no-privilege": no_priv,
                "no-manager": f"{tools} {are} not installed here, and this machine has none "
                              f"of the package managers renest can drive.",
                "failed": f"installing {tools} failed (the output above says why).",
                "no-keyboard": f"nobody is at the keyboard to say yes to installing {tools}.",
            }
            return False, reasons.get(outcome.status, outcome.status), plan.command()
    else:
        cmd = pull_command(src_dir)
        if not assume_yes:
            if not interactive:
                return False, ("nobody is at the keyboard to say yes (add --yes to let "
                               "renest download them)."), ""
            say(f"{install_path} has {files} kept in Git LFS that this copy never "
                f"downloaded. renest can download them now:\n  {cmd}")
            answer = (m.ask("Download them now? [Y/n] ") or "").strip().lower()
            if answer not in ("", "y", "yes"):
                return False, "you chose not to download them.", ""
        else:
            say(f"{install_path} has {files} kept in Git LFS that this copy never "
                f"downloaded. Downloading them now (--yes):\n  {cmd}")
    # `install --local` writes the LFS filter into this repo's own config, so git sees
    # the downloaded files as unchanged; a failure there (an existing hook) is not a
    # reason to skip the pull.
    m.stream(["git", "-C", str(src_dir), "lfs", "install", "--local"], None)
    code, _tail = m.stream(["git", "-C", str(src_dir), "lfs", "pull"], None)
    if code != 0:
        return False, f"`git lfs pull` exited {code} (its output above says why).", ""
    return True, None, ""


def settle_placeholders(
    src_dir: Path,
    install_path: str,
    find: Callable[[], list[str]],
    *,
    dry_run: bool,
    assume_yes: bool = False,
    may_ask: bool = False,
    say: Callable[[str], None] | None = None,
    rerun: str = "the same `renest pack` command",
    machine: systools.Machine | None = None,
) -> Settled:
    """Download what can be downloaded, then sort what is left.

    ``find`` lists the placeholders the archive would carry (called again after a
    download). A dry run never downloads or installs anything -- it changes nothing
    on disk -- and reports what the real pack would do."""
    pointers = find()
    if not pointers:
        return Settled()
    checkout = _is_checkout(src_dir)
    out = Settled(is_checkout=checkout)
    # Download first, whatever they are: the faithful copy of this folder is the one
    # with the real files. Sorting only decides what happens when that cannot be done.
    if checkout and not dry_run:
        pulled, why, install_first = _pull(
            src_dir, install_path, len(pointers), assume_yes=assume_yes, may_ask=may_ask,
            say=say or (lambda _t: None), rerun=rerun, machine=machine or systools.Machine())
        out.pulled, out.why, out.install_first = pulled, why, install_first
        if pulled:
            pointers = find()
            if pointers:
                out.why = ("`git lfs pull` finished but these are still placeholders -- "
                           "the repository's LFS server may no longer have them.")
    out.dropped, out.needed = split_placeholders(pointers)
    return out
