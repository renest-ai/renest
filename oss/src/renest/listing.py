"""``renest list`` — see which nests are on your Renest drive.

Without it there is nowhere to look a nest id up, which puts ``pack --nest-id``
(append a version to an existing nest) out of reach. Two read-only answers:
``renest list`` for the drive (name / id / versions / size / last updated), and
``renest list <id>`` for one nest's versions, ending in a paste-ready append command.

The command is ``list``, not ``nests``: ``nest`` belongs to the asset vocabulary and
never enters tool-facing names. The module is ``listing`` because ``list.py`` would
shadow a Python builtin.

It reads **only your own account's** index metadata, never a bucket or an object
listing. Credentials are the same token as ``pack --dest hosted``, resolved the same
way; there is no ``--token`` flag, since arguments end up in shell history.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

import httpx

from .config import ConfigError, resolve_token
from .errors import ExitCode
from .events import EventEmitter
from .hosted import DEFAULT_ORIGIN, _error_message

__all__ = ["add_arguments", "run_from_args", "append_command"]

#: Timeout for the small control-plane JSON calls. Past this, a query command is
#: better off failing and letting the person retry than hanging on the network.
_TIMEOUT = 30.0


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "nest_id",
        nargs="?",
        help="a nest id to inspect: show its versions and how to pack the next one "
        "into it. Leave it out to list every nest on your drive",
    )
    parser.add_argument(
        "--origin",
        help="Renest service address (default https://api.renest.ai, or the RENEST_ORIGIN "
        "environment variable)",
    )


def append_command(nest_id: str) -> str:
    """The one line a user pastes to pack the next version into ``nest_id``.

    A function rather than three literals: the list footer, the detail footer and
    pack's closing line all say this, and three copies drift."""
    return f"renest pack --dest hosted --nest-id {nest_id} …"


def _fmt_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _fmt_when(iso: str | None) -> str:
    #: The server sends ISO-8601; a date is enough for a person here — this answers
    #: "when was it last updated", not "at what instant" for an audit.
    return (iso or "")[:10] or "—"


#: Version status → plain words. The vocabulary matches the server's version status
#: (uploading / verifying / committed / failed / blocked). An unrecognised value is
#: passed through as-is rather than guessed at.
_STATUS_HUMAN = {
    "committed": "✓ stored & verified",
    "verifying": "◌ still verifying",
    "uploading": "◌ still uploading",
    "failed": "✗ failed",
    "blocked": "✗ blocked by safety policy",
}


def _get(client: httpx.Client, origin: str, token: str, path: str) -> httpx.Response:
    return client.get(
        f"{origin.rstrip('/')}/api/v1{path}",
        headers={"Authorization": f"Bearer {token}"},
    )


def _print_list(nests: list[dict[str, Any]]) -> None:
    if not nests:
        print("Your drive has no nests yet. Pack one with:  renest pack --dest hosted …")
        return
    # Column widths follow the data. Ids are fixed-width; names are cut at 32 so a
    # row does not run off the screen.
    name_w = min(max((len(str(n.get("name", ""))) for n in nests), default=4), 32)
    name_w = max(name_w, len("NAME"))
    print(f"{'NAME':<{name_w}}  {'NEST ID':<26}  {'VERSIONS':>8}  {'SIZE':>9}  UPDATED")
    for n in nests:
        name = str(n.get("name", ""))
        if len(name) > name_w:
            name = name[: name_w - 1] + "…"
        print(
            f"{name:<{name_w}}  {str(n.get('id', '')):<26}  "
            f"{n.get('version_count', 0):>8}  {_fmt_bytes(int(n.get('size_bytes', 0))):>9}  "
            f"{_fmt_when(n.get('latest_version_at') or n.get('created_at'))}"
        )
    print()
    print(f"Pack a new version into one of these:  {append_command('<NEST ID>')}")


def _print_detail(detail: dict[str, Any]) -> None:
    versions = detail.get("versions") or []
    print(f"{detail.get('name', '')}  (nest {detail.get('id', '')})")
    if not versions:
        print("  No versions yet — the first upload into this nest never finished.")
    for v in versions:
        latest = " · latest" if v.get("id") == detail.get("head_version_id") else ""
        status = str(v.get("status", ""))
        print(
            f"  v{v.get('version_no', '?'):<3} {_STATUS_HUMAN.get(status, status):<22} "
            f"{_fmt_bytes(int(v.get('size_bytes', 0))):>9} · {v.get('blob_count', 0)} files · "
            f"{_fmt_when(v.get('committed_at') or v.get('created_at'))}{latest}"
        )
    print()
    print(f"Pack the next version into this nest:  {append_command(str(detail.get('id', '')))}")


def run_from_args(args: argparse.Namespace, emitter: EventEmitter) -> int:  # noqa: ARG001
    try:
        token = resolve_token(config_path=getattr(args, "config", None))
    except ConfigError as e:
        print(f"✗ {e.human}", file=sys.stderr)
        return e.exit_code
    if not token:
        # Word for word the same line as pack --dest hosted: same gap, same way out.
        print(
            "✗ No access token. Generate one in the web console, then put it in the "
            "RENEST_TOKEN environment variable, or write it into [auth] token in "
            "~/.config/renest/config.toml.",
            file=sys.stderr,
        )
        return int(ExitCode.CONFIG_OR_CREDENTIAL)

    origin = args.origin or os.environ.get("RENEST_ORIGIN") or DEFAULT_ORIGIN
    path = f"/nests/{args.nest_id}" if args.nest_id else "/nests"
    client = getattr(args, "_client", None) or httpx.Client(timeout=_TIMEOUT)
    try:
        resp = _get(client, origin, token, path)
    except httpx.HTTPError as e:
        print(
            f"✗ Cannot reach your Renest drive at {origin}: {type(e).__name__}",
            file=sys.stderr,
        )
        return int(ExitCode.S1_NETWORK_INTERRUPTED)
    finally:
        if getattr(args, "_client", None) is None:
            client.close()

    if resp.status_code in (401, 403):
        print(
            "✗ That access token was refused — it may have been revoked. Generate a "
            "fresh one in the web console and update RENEST_TOKEN (or [auth] token).",
            file=sys.stderr,
        )
        return int(ExitCode.CONFIG_OR_CREDENTIAL)
    if resp.status_code == 404 and args.nest_id:
        print(
            f"✗ No nest with id {args.nest_id} on your drive. Run `renest list` "
            "to see what's there — ids are in the second column.",
            file=sys.stderr,
        )
        return int(ExitCode.USAGE)
    if resp.status_code != 200:
        print(f"✗ Your Renest drive said no: {_error_message(resp)}", file=sys.stderr)
        return int(ExitCode.S1_STORAGE_UNAVAILABLE)

    data = resp.json()
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    elif args.nest_id:
        _print_detail(data)
    else:
        _print_list(data)
    return int(ExitCode.OK)
