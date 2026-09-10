"""Run a training command and record which machine libraries it really loaded.

**Why this exists.** A nest names the operating-system libraries its working run
needed, and that list comes in two kinds (see ``syslibs``): ``loaded`` -- read off the
application while it runs, authoritative, a rebuild may refuse on it -- and
``declared`` -- read off installed packages, over-wide, so it may only ever warn.

ComfyUI stays running, so packing finds its process and reads the strong list. A
trainer does not: ``accelerate launch train_network.py ...`` runs and exits, and by
packing time there is nothing left to read. Measured on a real fine-tune nest
(2026-09-09): the machine check said only ``machine check: warn``, 2.1 GB downloaded,
and the rebuild stopped at S4 on a missing ``libGL.so.1`` -- **after the bytes were
paid for**. The product was honest; it was honest too late.

So record it while the run is happening. This wraps the command the user was going to
run anyway and, at the end, writes the same run record the ComfyUI extension writes,
which ``syslibs.collect_native_libs`` already reads **first**, ahead of looking for a
live process, precisely because a record "survives the app being closed".

**It changes nothing about the run.** Same arguments, same environment, same standard
output and error, same exit code. If this file cannot read anything (no ``/proc``, no
permission), the command still runs and still returns its own exit code -- it just
records nothing and says so. A wrapper that can change the outcome of a training run
is worse than no wrapper: people would stop using it, and rightly.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

from .errors import ExitCode
from .syslibs import RUN_RECORD_REL

#: How often to look at what the run has mapped. Libraries arrive over the whole life
#: of a run (torch pulls its CUDA stack in on the first tensor, a data loader pulls
#: image codecs in on the first batch), so one look at the end is not enough -- and a
#: look at the end is exactly what is unavailable, because by then it has exited.
_SAMPLE_SECONDS = 2.0

#: Reading `/proc` costs nothing next to a training run, but a runaway loop on a
#: machine without `/proc` would spin. Give up quietly after this many failed passes.
_MAX_BLIND_PASSES = 3


def _descendants(pid: int) -> list[int]:
    """``pid`` and every process below it, read off ``/proc``.

    Trainers are launched through a launcher: ``accelerate launch`` is the parent, and
    **the child is where torch and its libraries actually load**. Sampling only the
    process we started would record the launcher's own handful of libraries and miss
    every one that matters.
    """
    try:
        alive = [int(p.name) for p in Path("/proc").iterdir() if p.name.isdigit()]
    except OSError:
        return [pid]
    parent: dict[int, int] = {}
    for p in alive:
        try:
            # `/proc/<pid>/stat` field 4 is the parent pid; the process name in field 2
            # can contain spaces and brackets, so split after the closing bracket.
            text = Path(f"/proc/{p}/stat").read_text(encoding="utf-8", errors="replace")
            parent[p] = int(text[text.rindex(")") + 1:].split()[1])
        except (OSError, ValueError, IndexError):
            continue
    out, frontier = {pid}, [pid]
    while frontier:
        head = frontier.pop()
        for child, dad in parent.items():
            if dad == head and child not in out:
                out.add(child)
                frontier.append(child)
    return sorted(out)


def _mapped_paths(pid: int) -> set[str]:
    """Absolute file paths this process has mapped, straight out of ``/proc/<pid>/maps``.

    **Raw paths, nothing else.** Which of them count as machine libraries, and what
    each is called, is decided by the reader (``syslibs._libs_from_run_record``) --
    one set of rules in one place, so a writer cannot drift away from the reader.
    """
    found: set[str] = set()
    try:
        with open(f"/proc/{pid}/maps", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                # `address perms offset dev inode pathname`; pathname may be absent,
                # or a pseudo-entry like `[heap]` / `[stack]`.
                parts = line.split(maxsplit=5)
                if len(parts) < 6:
                    continue
                path = parts[5].strip()
                if path.startswith("/"):
                    found.add(path)
    except (OSError, ValueError):
        pass
    return found


class _Sampler(threading.Thread):
    """Watches the run from the side. Never touches it."""

    def __init__(self, pid: int) -> None:
        super().__init__(daemon=True)
        self.pid = pid
        self.paths: set[str] = set()
        self.stop = threading.Event()
        self.blind = 0

    def run(self) -> None:
        while not self.stop.is_set():
            got: set[str] = set()
            for p in _descendants(self.pid):
                got |= _mapped_paths(p)
            if got:
                self.paths |= got
                self.blind = 0
            else:
                self.blind += 1
                if self.blind >= _MAX_BLIND_PASSES and not self.paths:
                    return          # no /proc here; stop looking, the run carries on
            self.stop.wait(_SAMPLE_SECONDS)


def write_run_record(env_root: Path, paths: set[str]) -> Path | None:
    """Write the record ``syslibs`` reads. Returns the file, or None when nothing was seen.

    **Nothing seen means nothing written.** An empty list is not "this run needed no
    libraries"; it is "we could not look". Writing it would replace a real earlier
    reading with a false one -- the same trap the ComfyUI extension documents at its
    own writer, and it was caught there by a test, not by review.
    """
    if not paths:
        return None
    dest = Path(env_root) / RUN_RECORD_REL
    payload = {
        # Same shape the extension writes. `mapped_library_paths` is the key the
        # reader has always taken and still takes; the extension stopped writing it
        # when it started relying on its own process staying up, which is exactly the
        # assumption that does not hold for a trainer.
        "record_version": 3,
        "recorded_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "python": sys.executable,
        "mapped_library_paths": sorted(paths),
    }
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".json.part")
        tmp.write_text(json.dumps(payload, indent=1), encoding="utf-8")
        tmp.replace(dest)
    except OSError:
        return None
    return dest


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--env-root",
        default=".",
        help="the folder that will be packed (default: the current one). The record "
             "is written inside it, where packing looks for it",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="the command to run, after a `--`: renest watch -- accelerate launch train.py",
    )


def run_from_args(args: argparse.Namespace, emitter) -> int:
    argv = list(args.command or [])
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print("Nothing to run. Put the command after a `--`, for example:\n"
              "  renest watch -- accelerate launch train_network.py --config x.toml",
              file=sys.stderr)
        return int(ExitCode.USAGE)

    root = Path(args.env_root).resolve()
    try:
        proc = subprocess.Popen(argv)  # noqa: S603 - the user's own command, unchanged
    except OSError as exc:
        print(f"Could not start that command: {exc}", file=sys.stderr)
        return int(ExitCode.USAGE)

    sampler = _Sampler(proc.pid)
    sampler.start()
    try:
        code = proc.wait()
    except KeyboardInterrupt:
        # Hand the signal on and report what the run reported. Swallowing it here
        # would leave a training run alive with nothing watching it.
        proc.terminate()
        code = proc.wait()
    finally:
        sampler.stop.set()
        sampler.join(timeout=_SAMPLE_SECONDS * 2)

    wrote = write_run_record(root, sampler.paths)
    if wrote is not None:
        emitter.log(
            f"Recorded {len(sampler.paths)} mapped file(s) from this run. Packing this "
            f"folder now names the machine libraries the run really loaded, so a rebuild "
            f"on a machine missing one stops before it downloads anything.",
            stage="watch",
        )
    else:
        emitter.log(
            "Nothing could be read about this run's libraries (no /proc, or it ended too "
            "quickly), so no record was written. Packing falls back to what installed "
            "packages declare, which can only ever warn.",
            stage="watch", level="warning",
        )
    # **The run's own exit code, always.** This command reports on a run; it does not
    # get a verdict of its own.
    return code
