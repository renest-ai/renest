"""Restore-progress uplink sink (pod → service event pipe).

Rule, no exceptions: reporting never blocks and never affects the restore. Errors are
swallowed, the per-batch timeout is short, and a failure degrades to "no more
reporting for this run".

Active when ``renest restore --grant <URL>`` runs without ``--no-report``: the origin
comes from the grant URL and events go to ``{origin}/api/v1/runs/report``. A grant read
from a local file has no origin, so reporting stays off (``RENEST_REPORT_URL`` can
name one).

**[SECURITY-REVIEW]** The grant id *is* the credential. Every event passes through
``uplink.scrub_event`` first: user content (local paths, other programs' error text,
the source host) is held back; only machine facts (GPU, driver, free disk) go out.
"""

from __future__ import annotations

import atexit
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from .uplink import UPLINK_CONTRACT_VERSION, machine_facts, scrub_event

_FLUSH_AT = 20  # events per batch
_TIMEOUT_S = 3.0  # per-batch timeout; short, because reporting is a side channel
_FINAL_TYPES = {"result", "error"}  # flush on arrival: leave no tail at the end


def origin_from_grant_source(source: str) -> str | None:
    """scheme://host[:port] when the grant came from a URL; None for a local path."""
    if not source.lower().startswith(("http://", "https://")):
        return None
    p = urllib.parse.urlsplit(source)
    if not p.scheme or not p.netloc:
        return None
    return f"{p.scheme}://{p.netloc}"


def make_report_sink(
    grant_id: str, origin: str, *, target: str | None = None
) -> tuple[Callable[[dict[str, Any]], None], Callable[[], None]]:
    """Return ``(sink, final_flush)``: the sink hangs off EventEmitter, and
    ``final_flush`` is registered with ``atexit`` as a backstop.

    ``target`` is this restore's directory. It is used **only** to measure free space
    on that disk; the path itself never goes up.
    """
    endpoint = f"{origin}/api/v1/runs/report"
    buf: list[dict[str, Any]] = []
    dead = False  # after one failure this process stops trying: a slow network
    # would otherwise cost 3s on every batch
    machine: dict[str, Any] | None = None  # collected once, not per batch

    def _flush() -> None:
        nonlocal dead, machine
        if dead or not buf:
            return
        batch, buf[:] = list(buf), []
        if machine is None:
            try:
                machine = machine_facts(target)
            except Exception:  # noqa: BLE001 — leave it empty rather than
                # disturb the restore
                machine = {}
        payload = json.dumps(
            {"grant_id": grant_id, "uplink_version": UPLINK_CONTRACT_VERSION,
             "events": batch, "machine": machine}
        ).encode()
        req = urllib.request.Request(
            endpoint, data=payload, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT_S):
                pass
        except (urllib.error.URLError, OSError, ValueError):
            dead = True  # silent degradation: no more reporting for this restore

    def sink(event: dict[str, Any]) -> None:
        if dead:
            return
        # The gate: only the scrubbed event enters the buffer, so the raw one has no
        # path out. One entrance, not a check at every exit.
        kept = scrub_event(event)
        if kept is None:
            return  # logs and unregistered types: whole category stays local
        buf.append(kept)
        if len(buf) >= _FLUSH_AT or event.get("type") in _FINAL_TYPES:
            _flush()

    atexit.register(_flush)
    return sink, _flush


def maybe_report_sink(
    grant_source: object,
    grant: dict | None,
    *,
    disabled: bool,
    target: str | None = None,
) -> Callable[[dict[str, Any]], None] | None:
    """Build the sink if the conditions hold; return None otherwise, with no side effects."""
    if disabled or not grant:
        return None
    grant_id = grant.get("grant_id")
    if not isinstance(grant_id, str) or not grant_id:
        return None
    src = grant_source if isinstance(grant_source, str) else ""
    grant_origin = grant.get("origin") if isinstance(grant.get("origin"), str) else None
    origin = (
        os.environ.get("RENEST_REPORT_URL")
        or grant_origin  # origin recorded in the grant envelope, so a file-sourced
        # grant can still report
        or origin_from_grant_source(src)
    )
    if not origin:
        return None
    sink, _ = make_report_sink(grant_id, origin.rstrip("/"), target=target)
    return sink
