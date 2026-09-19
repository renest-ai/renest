"""``renest start`` — run what a restore rebuilt, for the person who would
otherwise copy a command out of the closing lines and paste it back.

Measured 2026-09-13, first outside user: restore's closing lines named the start
command, and the follow-up question was "where do I even paste that?" This
command is the answer. It reads the facts a successful restore left at
``<target>/.renest/start.json`` and runs exactly the command those lines printed
— same resolution of ``argv[0]`` (nest's own venv, never the system PATH), same
environment variables, same working directory. Nothing is decided here that the
rebuild did not already prove: a fact the restore did not leave is an error,
never a guess.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

from .errors import ExitCode
from .restore import START_REL, loopback_bind, rebind_argv, resolve_argv0
from .roots import materialise_entrypoint_env

__all__ = [
    "StartFailure",
    "add_arguments",
    "run_from_args",
    "load_start_facts",
    "start_command",
]


class StartFailure(Exception):
    """A user-facing "you cannot start this here" — the message is the remedy.

    Not a NestFailure on purpose: those carry the S0–S5 stage machine, and `start`
    has no stage of its own — it either finds what a successful restore proved
    and runs it, or tells the person what to run instead. Never a guess.
    """

    @property
    def human(self) -> str:
        return str(self)


def load_start_facts(target: Path) -> dict:
    p = target / START_REL
    if not p.is_file():
        raise StartFailure(
            f"No rebuild to start was found at {p}. Either run `renest restore` first, "
            f"or this nest is an older format with no start command recorded — the "
            f"closing lines of its restore named the command to run by hand.",
        )
    try:
        facts = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise StartFailure(f"The rebuild facts at {p} are unreadable ({e}). Run `renest restore` again "
            f"— it rewrites them, and everything already fetched is reused.",
        ) from e
    if not isinstance(facts, dict):
        raise StartFailure(f"The rebuild facts at {p} are not what this tool writes. Run `renest restore` "
            f"again to rewrite them.",
        )
    return facts


def start_command(
    facts: dict, target: Path, *, listen: str | None = None,
) -> tuple[list[str], Path, dict[str, str]]:
    """Rebuild the exact command the closing lines printed — or refuse.

    Same rules as the restore's own launch: ``argv[0]`` resolves only inside the
    rebuild root (interpreter names swap for the rebuilt venv's Python, paths
    stay relative to the root, bare names look up only in the nest's venv bin).

    ``listen`` is the one thing a person may change, and only by asking: the
    recorded command binds where the rebuild's own check needed it to (loopback,
    on a real ComfyUI nest), and a browser on another machine reaches nothing
    there. Changing it rewrites **the value of an address flag the command
    already has** — never adds one, so an application that takes no such flag
    gets a refusal with the reason, not a crash.
    """
    ep = facts.get("entrypoint") if isinstance(facts.get("entrypoint"), dict) else {}
    argv = ep.get("argv")
    if not (isinstance(argv, list) and argv):
        raise StartFailure(
            "This nest records no start command (older format). The closing lines of its "
            "restore named the command to run by hand.",
        )
    venv_py = target / ".venv" / "bin" / "python"
    exe = resolve_argv0(str(argv[0]), target, venv_py)
    if not exe.is_file():
        raise StartFailure(f"The program this nest starts is not here: {exe}. Run `renest restore` again "
            f"— it reuses everything already fetched and carries on.",
        )
    rest = [str(a) for a in argv[1:]]
    if listen is not None:
        try:
            rest = rebind_argv(rest, listen)
        except ValueError as e:
            raise StartFailure(
                f"Cannot point this nest at {listen}: {e}. Start it by hand with whatever "
                f"flag this application uses for its address."
            ) from e
    cmd = [str(exe), *rest]
    app_rel = facts.get("app_dir") or "."
    cwd = target / str(app_rel)
    if not cwd.is_dir():
        raise StartFailure(f"The working directory this nest starts from is not here: {cwd}. "
            f"Run `renest restore` again — it reuses everything already fetched.",
        )
    env_extra: dict[str, str] = {}
    if ep.get("env"):
        try:
            env_extra = materialise_entrypoint_env(ep.get("env"), target)
        except ValueError as e:
            raise StartFailure(f"This nest's recorded environment variables cannot be reconstructed "
                f"here ({e}). The closing lines of the restore printed them — set them "
                f"by hand and run the command it printed.",
            ) from e
    return cmd, cwd, env_extra


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--dir", default=".",
        help="the folder you restored into (default: the current directory)",
    )
    parser.add_argument(
        "--listen", metavar="ADDRESS",
        help="listen on this address instead of the one recorded (use 0.0.0.0 to "
             "reach it from your own browser on a rented box)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="print the command that would run, then stop",
    )


def run_from_args(args: argparse.Namespace, emitter) -> int:  # noqa: ANN001
    target = Path(args.dir).expanduser().resolve()
    try:
        facts = load_start_facts(target)
        # `getattr`, not `args.listen`: this function is called with a hand-built
        # namespace in places that predate the flag, and a crash there would be
        # the tool falling over on its own new option.
        _listen = getattr(args, "listen", None)
        cmd, cwd, env_extra = start_command(facts, target, listen=_listen)
    except StartFailure as e:
        print(f"[start] {e.human}", file=sys.stderr, flush=True)
        return int(ExitCode.USAGE)
    env = dict(os.environ)
    env.update(env_extra)
    print(f"[start] cd {cwd} && {shlex.join(cmd)}", file=sys.stderr, flush=True)
    # Said before it runs, not after: once the application has the terminal, its
    # own output buries anything printed later, and the person is already trying
    # the address that will not answer.
    if _listen is None:
        ep = facts.get("entrypoint") if isinstance(facts.get("entrypoint"), dict) else {}
        bound = loopback_bind([str(a) for a in (ep.get("argv") or [])[1:]])
        if bound:
            print(
                f"[start] It listens on {bound} — this machine only. If you are on a "
                f"rented box and want it in your own browser, stop it and run this again "
                f"with --listen 0.0.0.0.",
                file=sys.stderr, flush=True,
            )
    if facts.get("port"):
        print(
            f"[start] It answers on port {facts['port']}. On a rented GPU box, reaching it "
            f"from your own browser also means exposing that port in your provider's panel.",
            file=sys.stderr, flush=True,
        )
    if args.dry_run:
        return int(ExitCode.OK)
    try:
        proc = subprocess.run(cmd, cwd=cwd, env=env)
    except KeyboardInterrupt:
        return 130
    except OSError as e:
        print(f"[start] Could not run it: {e}", file=sys.stderr, flush=True)
        return int(ExitCode.USAGE)
    # A signal death arrives as a negative returncode; -N is the honest "128+N".
    return proc.returncode if proc.returncode >= 0 else 128 - proc.returncode
