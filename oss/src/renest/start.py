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
from .restore import (
    PASTE_NOTE,
    RECIPE_REL,
    START_REL,
    browser_address,
    expose_note,
    loopback_bind,
    place_sidebar_workflow,
    rebind_argv,
    resolve_argv0,
    start_listen_port,
    system_dir_refusal,
)
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


def parse_port(value: str) -> int | None:
    """``value`` as a TCP port (1-65535), or None."""
    v = str(value).strip()
    if not (v.isascii() and v.isdigit()):
        return None
    n = int(v)
    return n if 1 <= n <= 65535 else None


def _report_argv(argv: list[str], port: int, *, known: bool) -> list[str]:
    """``argv`` listening on ``port``: the recorded ``--port N`` / ``--port=N``
    rewritten (the spellings ``start_listen_port`` reads), else one appended --
    but only when the app's port was known at restore; never a guessed flag."""
    out = list(argv)
    for i, tok in enumerate(out):
        if tok == "--port" and i + 1 < len(out):
            out[i + 1] = str(port)
            break
        if tok.startswith("--port="):
            out[i] = f"--port={port}"
            break
    else:
        if not known:
            raise StartFailure(
                f"Cannot move this nest to port {port}: its start command names no port "
                f"and the port this application listens on is not known, so there is "
                f"nothing to change -- adding a flag it may not accept would break a "
                f"start that works. Start it by hand with whatever flag this application "
                f"uses for its port."
            )
        if out and out[-1] == "--port":
            out.append(str(port))
        else:
            out += ["--port", str(port)]
    if start_listen_port(out, None) != port:  # same reading as the closing lines
        raise StartFailure(
            f"Cannot move this nest to port {port}: its recorded --port is not in a "
            f"form this tool can change. Start it by hand with --port {port}."
        )
    return out


def start_command(
    facts: dict, target: Path, *, listen: str | None = None, port: int | None = None,
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

    ``port`` is the other: on a box where something already holds the recorded
    port (a provider's own ComfyUI on 8188), the start collides. It rewrites the
    ``--port`` the command has, or adds one only when the restore knew which port
    the app listens on (``listen_port``: ComfyUI's own default) -- the same
    spellings ``start_listen_port`` reads, so the number said afterwards is this one.
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
    if port is not None:
        rest = _report_argv(rest, port, known=bool(facts.get("listen_port")))
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
        "--port", metavar="PORT",
        help="listen on this port instead of the one recorded (use it when something "
             "else on this box already holds that port)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="print the command that would run, then stop",
    )


def run_from_args(args: argparse.Namespace, emitter) -> int:  # noqa: ANN001
    # Same refusal as restore: an app started inside a system folder writes its
    # outputs there (into memory, for /run).
    _why = system_dir_refusal(args.dir)
    if _why:
        print(f"[start] ✗ {_why} Restore into it, then start it from there.",
              file=sys.stderr, flush=True)
        return int(ExitCode.USAGE)
    _port_arg = getattr(args, "port", None)
    _port = None
    if _port_arg is not None:
        _port = parse_port(_port_arg)
        if _port is None:
            print(f"[start] ✗ --port takes a whole number from 1 to 65535, not {_port_arg!r}.",
                  file=sys.stderr, flush=True)
            return int(ExitCode.USAGE)
    target = Path(args.dir).expanduser().resolve()
    try:
        facts = load_start_facts(target)
        # `getattr`, not `args.listen`: this function is called with a hand-built
        # namespace in places that predate the flag, and a crash there would be
        # the tool falling over on its own new option.
        _listen = getattr(args, "listen", None)
        cmd, cwd, env_extra = start_command(facts, target, listen=_listen, port=_port)
    except StartFailure as e:
        print(f"[start] {e.human}", file=sys.stderr, flush=True)
        return int(ExitCode.USAGE)
    env = dict(os.environ)
    env.update(env_extra)
    # Put the recipe back in ComfyUI's Workflows sidebar if it went missing since the
    # restore (idempotent: the same bytes already there are left as they are). Only
    # when the restore recorded that it placed one -- never derived anew here.
    _wf_name = facts.get("sidebar_workflow")
    if isinstance(_wf_name, str) and _wf_name and not args.dry_run:
        # The restored file it came from; a start.json from before that was recorded
        # means the staged recipe. Never a path outside the restore folder.
        _src = target / RECIPE_REL
        _rec = facts.get("sidebar_workflow_source")
        if isinstance(_rec, str) and _rec:
            _cand = (target / _rec).resolve()
            if _cand.is_relative_to(target):
                _src = _cand
        _placed = place_sidebar_workflow(cwd, _src, _wf_name, [str(a) for a in cmd])
        if _placed is not None:
            print(f"[start] In ComfyUI, open Workflows (left sidebar) → {_placed.stem} "
                  f"for the workflow this nest was packed from.",
                  file=sys.stderr, flush=True)
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
    # "listen_port", never the old "port" key: that one held the spare port the
    # rebuild's check borrowed, which the command below does not use (2026-09-30).
    _answers = _port if _port is not None else facts.get("listen_port")
    # The address the provider gives this port, from the command actually run (after
    # --listen / --port), so it is the one that will answer -- never a guess.
    _url = browser_address([str(a) for a in cmd[1:]], _answers) if _answers else None
    if _url:
        # The address alone on its line, so a triple-click copies exactly it.
        print(f"[start] It answers on port {_answers}. Open it at:", file=sys.stderr, flush=True)
        print(_url, file=sys.stderr, flush=True)
        print(f"[start] {PASTE_NOTE[0].upper()}{PASTE_NOTE[1:]}.", file=sys.stderr, flush=True)
        # Restore's closing lines say this; the address alone used to drop it, and
        # RunPod's address exists whether or not the port was ever opened.
        print(f"[start] If it doesn't answer, {expose_note(_answers)}.",
              file=sys.stderr, flush=True)
    elif _answers:
        print(
            f"[start] It answers on port {_answers}. On a rented GPU box, reaching it "
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
