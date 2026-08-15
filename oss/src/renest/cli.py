"""`renest` command-line entry point.

Global shape::

    renest [--json] [--config PATH] [--verbose] [--version] <subcommand> [args]

Global flags (``--json`` / ``--config`` / ``--verbose``) live on the top parser,
before the subcommand. Every verb sits at the same level, no nested groups.

Each real subcommand module exposes ``add_arguments(parser)`` and
``run_from_args(args, emitter) -> int``; the CLI is a thin registry over them.

Windows portability holds throughout: pathlib, os.replace for atomic writes, no
unix-only calls; stdout/stderr forced to UTF-8 for cp936/cp1252 consoles.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from collections.abc import Sequence

from . import MANIFEST_VERSIONS, __version__
from . import doctor as _doctor
from . import export as _export
from . import lint as _lint
from . import listing as _listing
from . import pack as _pack
from . import presign as _presign
from . import restore as _restore
from . import update_rules as _update_rules
from . import serve as _serve
from . import support as _support
from . import verify as _verify
from .errors import ExitCode
from .events import EventEmitter

__all__ = ["build_parser", "main"]

#: One line per subcommand for `renest --help`. The first screen a user sees
#: should say what each command is for, not repeat its own name.
_SUMMARY = {
    "doctor": "check whether this machine can rebuild a nest",
    "pack": "pack up the setup you got working",
    "restore": "rebuild a nest here",
    "verify": "check a rebuilt nest against what it should be",
    "lint": "check a nest file for problems",
    "serve": "run the local agent ComfyUI talks to",
    "update-rules": "refresh the checks and compatibility data",
    "presign": "sign time-limited links so a rented machine never sees your key",
    "support": "turn a failed run into something you can read, then paste into a ticket",
    "list": "list the nests on your Renest drive (add an id to see its versions)",
    "export": "take a complete copy of a nest off your drive — to this machine, or on into your own bucket",
}

#: subcommand -> (add_arguments, run_from_args) for wired commands.
_HANDLERS = {
    "doctor": (_doctor.add_arguments, _doctor.run_from_args),
    "pack": (_pack.add_arguments, _pack.run_from_args),
    "restore": (_restore.add_arguments, _restore.run_from_args),
    "verify": (_verify.add_arguments, _verify.run_from_args),
    "lint": (_lint.add_arguments, _lint.run_from_args),
    "serve": (_serve.add_arguments, _serve.run_from_args),
    "update-rules": (_update_rules.add_arguments, _update_rules.run_from_args),
    # Signs time-limited links on the machine that holds the bucket key, so the
    # key itself never leaves that machine.
    "presign": (_presign.add_arguments, _presign.run_from_args),
    # Turns a failed run into text the user reads first and then pastes wherever
    # they want. It never goes online and never uploads.
    "support": (_support.add_arguments, _support.run_from_args),
    # Lists the nests and versions on the drive. Without it there is nowhere to
    # look up an id, so `pack --nest-id` is out of reach.
    "list": (_listing.add_arguments, _listing.run_from_args),
    # The self-serve way out of the hosted drive: download the whole archive,
    # optionally push it on into the user's own bucket.
    "export": (_export.add_arguments, _export.run_from_args),
}

#: subcommand -> note for commands not built yet (none left).
_PLACEHOLDER_CARDS: dict[str, str] = {}

#: the full registered subcommand set (wired + placeholder).
SUBCOMMANDS = tuple(_HANDLERS) + tuple(_PLACEHOLDER_CARDS)


def _version_string() -> str:
    manifest = ", ".join(MANIFEST_VERSIONS)
    return f"renest {__version__} (manifest: {manifest})"


def _reconfigure_streams() -> None:
    """Force UTF-8 on stdout/stderr, for Windows console encodings."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass  # detached/captured streams: nothing to do


def _handle_placeholder(args: argparse.Namespace, emitter: EventEmitter) -> int:
    card = _PLACEHOLDER_CARDS[args.command]
    print(
        f"renest {args.command}: not built yet (coming with task card {card}).",
        file=sys.stderr,
    )
    return int(ExitCode.USAGE)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="renest",
        description="Pack up the setup you got working — an image workflow or a fine-tuning run — then rebuild it byte-for-byte anywhere.",
    )
    parser.add_argument("--version", action="version", version=_version_string())
    parser.add_argument(
        "--json",
        action="store_true",
        help="print machine-readable output to stdout. Accepted before or after the "
        "subcommand. Two shapes, by command: doctor / lint / verify / presign print "
        "ONE json document; pack / restore print a stream of json events, ONE PER LINE, "
        "and the LAST line is always the final report",
    )
    parser.add_argument("--config", metavar="PATH", help="use this config file")
    parser.add_argument("--verbose", action="store_true", help="print debug logs to stderr")

    subparsers = parser.add_subparsers(dest="command", metavar="<subcommand>")
    subparsers.required = True
    for command, (add_arguments, handler) in _HANDLERS.items():
        sub = subparsers.add_parser(command, help=_SUMMARY.get(command, ""))
        add_arguments(sub)
        # `--json` is accepted in BOTH positions: it is a global flag, but
        # `renest pack ... --json` is the form everyone types first, and argparse
        # would answer that with a blunt usage error. Same dest either way.
        sub.add_argument("--json", action="store_true", dest="json", default=argparse.SUPPRESS,
                         help="same as the global --json (accepted here for convenience)")
        sub.set_defaults(handler=handler)
    for command, card in _PLACEHOLDER_CARDS.items():
        sub = subparsers.add_parser(command, help=f"(not built yet, card {card})")
        sub.set_defaults(handler=_handle_placeholder)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    _reconfigure_streams()
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse exits itself: 0 for --version/--help, 2 for usage errors.
        code = exc.code
        if code is None:
            return int(ExitCode.OK)
        return code if isinstance(code, int) else int(ExitCode.USAGE)

    _maybe_ask_about_telemetry(args)
    _maybe_ask_about_rules_refresh(args)
    # Draw a rewriting progress line when a person is watching a terminal; a pipe, a log
    # file or --json gets exactly what it got before (see EventEmitter.live_progress).
    emitter = EventEmitter(json_mode=args.json,
                           live_progress=not args.json and sys.stderr.isatty())
    return int(args.handler(args, emitter))


def _maybe_ask_about_telemetry(args: argparse.Namespace) -> None:
    """Anonymous usage data: off by default, asked about once on a terminal.

    It lives in main() because the rule is "ask once on ANY subcommand"; per
    command it would be eight chances to forget one. It must never take the CLI
    down, so cheap checks rule out most calls first and any exception at all is
    swallowed as "did not ask".
    """
    if args.json or args.command == "serve" or not sys.stdin.isatty():
        return
    try:
        from . import telemetry
        from .config import load_config

        # `--config` goes in as config_path, which REPLACES the user-level
        # layer; the separate `user_config` argument exists for tests.
        config = load_config(config_path=getattr(args, "config", None))
        telemetry.ask_once(
            config,
            stdin=sys.stdin,
            stderr=sys.stderr,
            json_mode=args.json,
            command=args.command,
            config_path=Path(args.config) if getattr(args, "config", None) else None,
        )
    except Exception:  # noqa: BLE001 - asking once must never block the real work
        return


def _maybe_ask_about_rules_refresh(args: argparse.Namespace) -> None:
    """Keeping the check data fresh: off by default, asked about once.

    The check data holds which driver a CUDA generation needs, which download
    sources are trusted, which GPUs are tested. Stale facts turn a perfectly
    good machine away at the door. We ask instead of refreshing automatically
    because going online must always be explicit. Like the usage-data block
    above, any exception at all is swallowed as "did not ask".
    """
    if args.json or args.command in {"serve", "update-rules"} or not sys.stdin.isatty():
        return
    try:
        from . import update_rules as _ur
        from .config import load_config

        config = load_config(config_path=getattr(args, "config", None))
        _ur.ask_refresh_once(
            config,
            stdin=sys.stdin,
            stderr=sys.stderr,
            json_mode=args.json,
            command=args.command,
            config_path=Path(args.config) if getattr(args, "config", None) else None,
        )
    except Exception:  # noqa: BLE001 - asking once must never block the real work
        return


if __name__ == "__main__":
    sys.exit(main())
