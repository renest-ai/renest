"""Files the working run fetched for itself, found after the fact.

Why (batch 24 U1, 2026-10-09): a face-swap node downloaded 13 files into
``ComfyUI/models/`` the first time it ran -- detection models, a classifier, face
restorers. Packing only named them, with nine ``--add`` lines to paste; the nest went
out without them and the restore fetched 0.88 GB again without a word. With the
``--add`` lines in place nothing was fetched and the picture came back the same
(SSIM 0.997). Batch 22 C6 (Florence2) is the same story at 3.1 GB, 18 files.

So a file is carried on the user's behalf when **both** hold:

1. it appeared inside the run window -- from the start of the ComfyUI process that
   produced the picture, to that picture. Its modification time falls in the window and
   its inode-change time is not before it (the change time alone is not trusted): a model
   copied in by hand with its times kept (``cp -p``, ``rsync -a``) has an old
   modification time, and one merely touched (``chmod``) during the run has an old one
   too. Neither counts;
2. it sits where ComfyUI looks for models: under ``models/`` or an
   ``extra_model_paths.yaml`` folder. Anything elsewhere -- a scratch folder, a
   checkout someone unpacked by hand -- never matches. Temporary folders never count.

The process start comes from ``/proc`` of the ComfyUI that is running now, and only
when it started before the picture was written (a ComfyUI restarted after the run is
not the one that ran it). The extension's run record has no start time, so without a
live process there is no window, and packing falls back to naming the files.

**Which of them the run really loaded** is read from the same live process, through
``/proc/<pid>/maps`` and ``/proc/<pid>/fd``. That answer is only ever used one way:
in a folder where the run is holding one weight file, another weight file that
appeared beside it and is not held is taken for an unused duplicate (Florence-2 ships
the same weights as ``model.safetensors`` *and* ``pytorch_model.bin``). It is named
and left out. Small companion files (configs, tokenizers) are always carried -- a
loader reads them and closes them, so "not held open" says nothing about them -- and
in a folder where nothing is held open, everything is carried and the pack says it
could not tell.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .integrity import WEIGHT_SUFFIXES

__all__ = [
    "TEMP_ROOTS",
    "WINDOW_SLACK_S",
    "Fetched",
    "RunWindow",
    "comfyui_processes",
    "files_fetched_in",
    "held_open",
    "process_start",
    "run_end_from_spec",
    "run_window",
    "split_by_use",
]

#: Folders whose contents never count, however they got there.
TEMP_ROOTS: tuple[str, ...] = ("/tmp", "/var/tmp", "/dev/shm")

#: Seconds added on both ends: process start times are kept in clock ticks, and the
#: picture's time as recorded in a nest is cut to whole seconds.
WINDOW_SLACK_S = 2.0

#: Names that are a download still in flight or a lock beside one, never a file a run
#: loaded: huggingface_hub's ``.incomplete``, browsers' and wget's ``.part``.
_IN_FLIGHT = (".incomplete", ".part", ".lock", ".tmp")


@dataclass(frozen=True)
class RunWindow:
    start: float
    end: float
    pid: int


@dataclass
class Fetched:
    """What :func:`split_by_use` decided."""

    carry: list[Path] = field(default_factory=list)
    #: ``(file, the file held open beside it)`` -- appeared in the run, never loaded.
    unused: list[tuple[Path, Path]] = field(default_factory=list)
    #: Folders carried whole because nothing in them was held open.
    undetermined: list[Path] = field(default_factory=list)


def _proc() -> Path:
    return Path("/proc")


def _boot_time() -> float | None:
    try:
        for line in (_proc() / "stat").read_text(encoding="utf-8").splitlines():
            if line.startswith("btime "):
                return float(line.split()[1])
    except (OSError, ValueError):
        return None
    return None


def process_start(pid: int) -> float | None:
    """When ``pid`` started, as a Unix time; None when ``/proc`` cannot say."""
    try:
        line = (_proc() / str(pid) / "stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    # Field 22 counted from the start; parsed after the last ")" because the program
    # name in brackets may itself hold spaces and brackets.
    tail = line.rpartition(")")[2].split()
    boot = _boot_time()
    if len(tail) < 20 or boot is None or not tail[19].isdigit():
        return None
    try:
        hz = os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError, AttributeError):
        hz = 100
    return boot + int(tail[19]) / float(hz or 100)


def _our_own_chain() -> set[int]:
    from .syslibs import _our_own_chain as chain

    return chain()


def comfyui_processes(program_dirs: Sequence[Path]) -> list[int]:
    """Running processes started as ``python <program_dir>/main.py``.

    Matched on the command line, resolved against the process's own working folder --
    the way ComfyUI is started by hand, by systemd units, by the pod templates and by
    comfy-cli. A shell or an editor sitting in the folder does not match."""
    proc = _proc()
    if not proc.is_dir():
        return []
    wanted = set()
    for d in program_dirs:
        with contextlib.suppress(OSError):
            wanted.add(os.path.realpath(Path(d) / "main.py"))
    ours = _our_own_chain()
    found: list[int] = []
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) in ours:
            continue
        try:
            argv = (entry / "cmdline").read_bytes().split(b"\0")
            cwd = os.readlink(entry / "cwd")
        except OSError:
            continue
        for raw in argv[1:6]:
            arg = raw.decode(errors="replace")
            if not arg.endswith("main.py"):
                continue
            full = arg if arg.startswith("/") else os.path.join(cwd, arg)
            if os.path.realpath(full) in wanted:
                found.append(int(entry.name))
                break
    return sorted(found)


def run_end_from_spec(spec: dict) -> float | None:
    """The time of the picture the working run wrote, as the nest records it
    (``adapters.comfyui.verified_run.queue_completed_at``); None when there is none --
    a ``--workflow`` pack with no picture, or a spec written by hand."""
    vr = (((spec.get("adapters") or {}).get("comfyui") or {}).get("verified_run") or {})
    stamp = vr.get("queue_completed_at") if isinstance(vr, dict) else None
    if not isinstance(stamp, str):
        return None
    try:
        when = _dt.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.UTC)
    except ValueError:
        return None
    # Recorded cut to the second: the picture landed somewhere in the next one.
    return when.timestamp() + 1.0


def run_window(program_dirs: Sequence[Path], end: float | None) -> tuple[RunWindow | None, str]:
    """``(window, why there is none)``. The window belongs to the ComfyUI process that
    was running when the picture was written: of the matching processes, the one that
    started last but still before the picture."""
    if end is None:
        return None, "there is no picture from a finished run to measure the run against"
    pids = comfyui_processes(program_dirs)
    if not pids:
        return None, "ComfyUI is not running, so when the run started cannot be read"
    started = [(s, p) for p in pids if (s := process_start(p)) is not None]
    before = [(s, p) for s, p in started if s <= end + WINDOW_SLACK_S]
    if not before:
        return None, ("the ComfyUI running now started after that picture was written, so "
                      "it is not the process that ran it")
    s, p = max(before)
    return RunWindow(start=s - WINDOW_SLACK_S, end=end + WINDOW_SLACK_S, pid=p), ""


def _under_temp(path: Path) -> bool:
    real = os.path.realpath(path)
    return any(real == t or real.startswith(t.rstrip("/") + "/") for t in TEMP_ROOTS)


def files_fetched_in(window: RunWindow, dirs: Iterable[Path],
                     skip: Iterable[Path] = ()) -> list[Path]:
    """Files under ``dirs`` that appeared inside ``window``, sorted. ``skip``: files
    already in the nest. Hidden folders (a download's own ``.cache`` bookkeeping) and
    in-flight names are never counted."""
    skip_real = {os.path.realpath(p) for p in skip}
    seen: set[str] = set()
    out: list[Path] = []
    for d in dirs:
        if not Path(d).is_dir() or _under_temp(Path(d)):
            continue
        for dirpath, dirnames, filenames in os.walk(d, followlinks=False):
            dirnames[:] = sorted(n for n in dirnames if not n.startswith(".")
                                 and n != "__pycache__")
            for name in sorted(filenames):
                if name.startswith(".") or name.endswith(_IN_FLIGHT):
                    continue
                p = Path(dirpath) / name
                try:
                    if p.is_symlink():
                        continue
                    st = p.stat()
                except OSError:
                    continue
                if not _in_window(window, st):
                    continue
                real = os.path.realpath(p)
                if real in seen or real in skip_real or _under_temp(p):
                    continue
                seen.add(real)
                out.append(p)
    return out


def held_open(pid: int) -> set[str] | None:
    """Every file ``pid`` has mapped or open right now, as real paths; None when
    ``/proc`` will not say (another user's process, no ``/proc``)."""
    base = _proc() / str(pid)
    got: set[str] = set()
    readable = False
    with contextlib.suppress(OSError):
        for line in (base / "maps").read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split(None, 5)
            if len(parts) == 6 and parts[5].startswith("/"):
                got.add(os.path.realpath(parts[5].removesuffix(" (deleted)")))
        readable = True
    with contextlib.suppress(OSError):
        for fd in (base / "fd").iterdir():
            with contextlib.suppress(OSError):
                target = os.readlink(fd)
                if target.startswith("/"):
                    got.add(os.path.realpath(target))
        readable = True
    return got if readable else None


def _is_weight(p: Path) -> bool:
    if p.suffix.lower() in WEIGHT_SUFFIXES:
        return True
    from .payload import payload_kind

    return payload_kind(p) is not None


def split_by_use(files: Sequence[Path], held: set[str] | None) -> Fetched:
    """Which fetched files to carry. See the module docstring for the one rule."""
    res = Fetched()
    by_dir: dict[Path, list[Path]] = {}
    for f in files:
        by_dir.setdefault(f.parent, []).append(f)
    for folder, group in by_dir.items():
        weights = [f for f in group if _is_weight(f)]
        loaded = [f for f in weights if held is not None and os.path.realpath(f) in held]
        if not loaded:
            res.carry.extend(group)
            if weights:
                res.undetermined.append(folder)
            continue
        for f in group:
            if f in weights and f not in loaded:
                res.unused.append((f, loaded[0]))
            else:
                res.carry.append(f)
    res.carry.sort()
    res.unused.sort()
    return res


# -- Model caches under the home folder (format 2.14) -------------------------
# Measured on Spark 2026-10-10 against current releases: popular nodes download real
# weights into home-folder caches without overriding the path -- Hugging Face's hub
# cache (CLIPSeg, grounding-dino), rembg (~/.rembg/models/<name>/<name>.onnx),
# transparent-background (~/.transparent-background), insightface (~/.insightface).
# Only these four, by an allowlist (renest.roots.HOME_CACHE_PREFIXES): a cache is never
# swept whole, and the rest of the home folder (telemetry, font and compiler caches,
# the access token) is never looked at.


def process_environ(pid: int) -> dict[str, str] | None:
    """The environment ``pid`` was started with, or None when ``/proc`` will not say.
    Where a library keeps its cache is decided by the app's settings, not ours."""
    try:
        raw = (_proc() / str(pid) / "environ").read_bytes()
    except OSError:
        return None
    out: dict[str, str] = {}
    for item in raw.split(b"\0"):
        k, sep, v = item.partition(b"=")
        if sep and k:
            out[k.decode(errors="replace")] = v.decode(errors="replace")
    return out


def home_cache_roots(env: dict[str, str] | None = None) -> list[tuple[str, Path]]:
    """``(prefix under the home folder, where that cache is on this machine)`` for each
    allowlisted cache, honouring each library's own setting the way it does."""
    e = dict(os.environ) if env is None else env
    home = Path(e.get("HOME") or Path.home())
    if e.get("HF_HUB_CACHE"):
        hub = Path(e["HF_HUB_CACHE"]).expanduser()
    elif e.get("HF_HOME"):
        hub = Path(e["HF_HOME"]).expanduser() / "hub"
    else:
        hub = home / ".cache" / "huggingface" / "hub"
    if e.get("REMBG_HOME"):
        rembg = Path(e["REMBG_HOME"]).expanduser()
    elif e.get("XDG_DATA_HOME"):
        rembg = Path(e["XDG_DATA_HOME"]).expanduser() / "rembg"
    else:
        rembg = home / ".rembg"
    tbp = e.get("TRANSPARENT_BACKGROUND_FILE_PATH")
    tb = (Path(tbp).expanduser() if tbp else home) / ".transparent-background"
    return [(".cache/huggingface/hub/", hub), (".rembg/", rembg),
            (".transparent-background/", tb), (".insightface/", home / ".insightface")]


@dataclass
class HomeFetched:
    """What :func:`home_cache_files` decided: ``(file on this machine, path under the
    home folder)`` pairs to carry, and what was left out."""

    carry: list[tuple[Path, str]] = field(default_factory=list)
    unused: list[tuple[str, str]] = field(default_factory=list)   # (rel, held beside it)
    undetermined: list[str] = field(default_factory=list)          # rel folders


def _in_window(window: RunWindow, st: os.stat_result) -> bool:
    """Written during the run (modification time inside the window), and not a file that
    existed before it (inode change time not before the window). The change time has no
    upper bound on purpose: packing hard-links every file it carries into the nest, and a
    new link moves the change time -- an upper bound made a second pack of the same
    environment drop exactly the files the first one carried (Spark, 2026-10-11)."""
    return window.start <= st.st_mtime <= window.end and st.st_ctime >= window.start


def _touched(window: RunWindow, held: set[str] | None, p: Path) -> bool:
    try:
        real = os.path.realpath(p)
        if held is not None and real in held:
            return True
        if _in_window(window, os.stat(real)):
            return True
        return p.is_symlink() and _in_window(window, os.lstat(p))
    except OSError:
        return False


def home_cache_files(window: RunWindow, held: set[str] | None,
                     roots: Sequence[tuple[str, Path]]) -> HomeFetched:
    """Which files under the allowlisted home caches the working run used: held open by
    the run, or appeared during it. Files the run did not touch are never carried.

    The Hugging Face hub cache keeps ``blobs/`` plus ``snapshots/<rev>/`` links into it
    plus ``refs/<branch>``; what travels is ``refs/``, the snapshot entries as real
    files (Hugging Face reads that form offline), never the links, and that revision's
    empty ``.no_exist/`` markers. A snapshot the run
    touched brings its small companions (config, tokenizer) too -- a loader reads those
    and closes them, so "not open now" says nothing about them."""
    from .roots import HOME_NEVER_CARRY, ROOT_PATH_PATTERNS

    pat = ROOT_PATH_PATTERNS["home"]
    res = HomeFetched()
    for prefix, base in roots:
        if not base.is_dir() or _under_temp(base):
            continue
        if prefix.startswith(".cache/huggingface/hub/"):
            _hub_files(window, held, prefix, base, res, pat)
            continue
        touched: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
            for name in sorted(filenames):
                p = Path(dirpath) / name
                if name in HOME_NEVER_CARRY or name.endswith(_IN_FLIGHT) or p.is_symlink():
                    continue
                if _touched(window, held, p):
                    touched.append(p)
        split = split_by_use(touched, held)
        for p in split.carry:
            rel = prefix + p.relative_to(base).as_posix()
            if pat.match(rel):
                res.carry.append((Path(os.path.realpath(p)), rel))
        res.unused += [(prefix + f.relative_to(base).as_posix(), b.name) for f, b in split.unused]
        res.undetermined += [prefix + d.relative_to(base).as_posix() for d in split.undetermined]
    return res


def _hub_files(window: RunWindow, held: set[str] | None, prefix: str, base: Path,
               res: HomeFetched, pat) -> None:
    from .roots import HOME_NEVER_CARRY

    for repo in sorted(base.glob("models--*")):
        snaps = repo / "snapshots"
        if not snaps.is_dir():
            continue
        for snap in sorted(s for s in snaps.iterdir() if s.is_dir()):
            files = sorted(p for p in snap.rglob("*")
                           if p.name not in HOME_NEVER_CARRY and p.is_file())
            touched = [p for p in files if _touched(window, held, p)]
            if not touched:
                continue
            split = split_by_use(touched, held)
            left_out = {f for f, _ in split.unused}
            carry = set(split.carry) | {p for p in files
                                        if not _is_weight(p) and p not in left_out}
            for p in sorted(carry):
                rel = prefix + p.relative_to(base).as_posix()
                if pat.match(rel):
                    res.carry.append((p, rel))  # read through the link; keeps its name
            res.unused += [(prefix + f.relative_to(base).as_posix(), b.name)
                           for f, b in split.unused]
            res.undetermined += [prefix + d.relative_to(base).as_posix()
                                 for d in split.undetermined]
            # The pointer that names this revision: without it, loading by repo name
            # fails offline and blames the network.
            refs = repo / "refs"
            for ref in sorted(refs.glob("*")) if refs.is_dir() else []:
                try:
                    if ref.is_file() and ref.read_text(encoding="utf-8").strip() == snap.name:
                        rel = prefix + ref.relative_to(base).as_posix()
                        if pat.match(rel):
                            res.carry.append((ref, rel))
                except OSError:
                    continue
            # Hugging Face's record of the files this revision does not have (empty
            # markers under ``.no_exist/<rev>/``). Without them a restored cache asks the
            # network again, on the first load, for every optional file the loader tries
            # -- processor_config.json, chat_template.json, added_tokens.json ... (U7,
            # 2026-10-11). Only empty files: a marker never has content, so anything
            # else there is not one.
            nox = repo / ".no_exist" / snap.name
            for p in sorted(nox.rglob("*")) if nox.is_dir() else []:
                try:
                    if p.is_symlink() or not p.is_file() or p.stat().st_size != 0:
                        continue
                except OSError:
                    continue
                if p.name in HOME_NEVER_CARRY:
                    continue
                rel = prefix + p.relative_to(base).as_posix()
                if pat.match(rel):
                    res.carry.append((p, rel))
