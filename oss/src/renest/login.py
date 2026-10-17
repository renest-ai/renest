"""`renest login` — sign this machine in to a Renest account from its own terminal.

Device sign-in: this machine asks the service for a short code, the person opens the
page it names in their own browser (already signed in there), checks the code and
approves. The machine then receives a sign-in token and keeps it as ``auth.token`` in
the CLI's 0600 config file.

[SECURITY-REVIEW] That token can do exactly one thing: ask for one upload to be
approved, again in the person's browser. It cannot upload, list or read anything by
itself. It is printed nowhere, and the file it lands in is named so the person knows
where it is.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from collections.abc import Callable
from pathlib import Path

import httpx

from .approval import ApprovalError, poll_device_login, start_device_login
from .config import (
    TOKEN_ENV,
    ConfigError,
    record_auth_token,
    resolve_token,
    token_file_exposure_warnings,
    user_config_path,
)
from .errors import ExitCode
from .events import EventEmitter
from .update_rules import DEFAULT_ORIGIN

__all__ = ["add_arguments", "device_sign_in", "machine_label", "run_from_args"]

#: Bounds on how often the service is asked; whatever it suggests is kept inside them.
_MIN_INTERVAL_S = 1.0
_MAX_INTERVAL_S = 30.0


def machine_label() -> str:
    """What the approval page calls this machine: its host name, nothing more."""
    try:
        name = socket.gethostname().strip()
    except OSError:
        name = ""
    return (name or "this machine")[:120]


def device_sign_in(
    client: httpx.Client,
    origin: str,
    *,
    say: Callable[[str], None],
    sleep: Callable[[float], None] | None = None,
    clock: Callable[[], float] | None = None,
    min_interval: float | None = None,
) -> tuple[str, str]:
    """Run the device sign-in to the end. Returns ``(token, account_email)``.

    Raises :class:`ApprovalError` with a plain sentence when it was denied, expired, or
    the service could not be reached.
    """
    sleep = sleep or time.sleep
    clock = clock or time.monotonic
    min_interval = _MIN_INTERVAL_S if min_interval is None else min_interval
    start = start_device_login(client, origin, machine_label())
    say("To sign this machine in to Renest, open this page in a browser where you are signed in:")
    say(f"  {start.verify_url}")
    say("Check that the page shows this code, then approve it:")
    say(f"  {start.user_code}")
    say("Waiting for you to approve...")
    deadline = clock() + start.expires_in + 5
    gap = min(max(start.interval, min_interval), _MAX_INTERVAL_S)
    while clock() < deadline:
        sleep(gap)
        got = poll_device_login(client, origin, start.device_code)
        status = str(got.get("status") or "")
        if status == "approved":
            token = got.get("token")
            if not isinstance(token, str) or not token:
                raise ApprovalError("The sign-in was approved but no token came back. Run renest login again.")
            return token, str(got.get("account_email") or "")
        if status == "denied":
            raise ApprovalError("The sign-in was denied in the browser. Nothing was saved.")
        if status == "expired":
            raise ApprovalError("The sign-in code expired before it was approved. Run renest login again.")
        if status == "consumed":
            raise ApprovalError("This sign-in was already collected once. Run renest login again.")
        if status not in ("", "pending"):
            raise ApprovalError(f"The sign-in ended in a state this version does not know ({status[:40]}). "
                                "Run renest login again.")
    raise ApprovalError("The sign-in code expired before it was approved. Run renest login again.")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--replace", action="store_true",
        help="sign in again even though this machine already has a Renest token "
        "(the token in the config file is replaced)",
    )
    parser.add_argument(
        "--origin", default=None,
        help="the Renest service to sign in to (default: your Renest drive's API address)",
    )


def run_from_args(args: argparse.Namespace, emitter: EventEmitter) -> int:
    json_mode = bool(getattr(args, "json", False))
    origin = getattr(args, "origin", None) or os.environ.get("RENEST_ORIGIN") or DEFAULT_ORIGIN
    config_path = Path(args.config) if getattr(args, "config", None) else user_config_path()

    def say(line: str) -> None:
        print(line, file=sys.stderr, flush=True)

    try:
        existing_in_file = resolve_token(env={}, config_path=config_path,
                                         system_config=os.devnull)
    except ConfigError:
        existing_in_file = None
    if existing_in_file and not getattr(args, "replace", False):
        # Left alone on purpose: a personal access token there already lets the panel
        # ask for approvals, and replacing it with a sign-in would take away everything
        # else it can do.
        say(f"This machine already has a Renest token in {config_path}; the panel will use it. "
            "To replace it, run: renest login --replace")
        if json_mode:
            print(json.dumps({"ok": True, "already_signed_in": True,
                              "config_path": str(config_path)}))
        return int(ExitCode.OK)
    if existing_in_file:
        say(f"Note: {config_path} already holds an access token; signing in replaces it.")
    if os.environ.get(TOKEN_ENV, "").strip():
        say(f"Note: {TOKEN_ENV} is set in this shell, and it is used before the saved sign-in.")

    try:
        with httpx.Client() as client:
            token, email = device_sign_in(client, origin, say=say)
        saved = record_auth_token(token, path=config_path)
    except ApprovalError as e:
        say(f"✗ {e.human}")
        if json_mode:
            print(json.dumps({"ok": False, "error": e.human}))
        return int(ExitCode.CONFIG_OR_CREDENTIAL)
    except ConfigError as e:
        say(f"✗ {e.human}")
        if json_mode:
            print(json.dumps({"ok": False, "error": e.human}))
        return int(ExitCode.CONFIG_OR_CREDENTIAL)
    finally:
        token = None  # noqa: F841 - drop the only reference as soon as it is saved

    who = email or "your Renest account"
    say(f"✓ This machine is signed in to Renest as {who}.")
    say(f"The sign-in is saved in {saved} (readable only by you). It can only ask for "
        "an upload to be approved in your browser; it cannot upload by itself.")
    for warning in token_file_exposure_warnings(saved):
        say(f"⚠ {warning}")
    if json_mode:
        print(json.dumps({"ok": True, "account_email": email, "config_path": str(saved)}))
    return int(ExitCode.OK)
