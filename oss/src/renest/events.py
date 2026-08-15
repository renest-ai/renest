"""NDJSON event stream emitter (frozen public contract).

Master plan 1.5 / CLI design §3.3: with ``--json`` the CLI's stdout is a
pure NDJSON event stream — one JSON object per line, each with ``type``
and ``ts``. Event types: ``stage_start`` / ``progress`` / ``log`` /
``stage_done`` / ``error`` / ``result``.

The ``progress`` event's fields (percent / bytes_done / bytes_total /
speed_mbps / active_sources) and the ``result`` / ``error`` structures are
frozen as a public contract (FC-3); changes go through the version process.
"""

from __future__ import annotations

import json
import re
import sys
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import IO, Any

from .errors import NestFailure

__all__ = ["EVENT_TYPES", "PROGRESS_FIELDS", "EventEmitter", "sanitise_terminal"]

#: Terminal control sequences that start with ESC (CSI colour/cursor moves, OSC
#: window-title changes, and single-character escapes).
_ANSI = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")
#: The remaining C0 control characters. **\n and \t stay** (real text needs them);
#: everything else becomes a visible marker. \r is stripped too — a carriage return
#: can **erase and rewrite a line already printed**, the cheapest way to forge output.
_CTRL = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]")


def sanitise_terminal(s: str) -> str:
    """Strip control characters from text that is about to be printed to a terminal.

    **[SECURITY-REVIEW]** A manifest carries plain-text fields that the sender fills
    in and that we print verbatim: ``name``, the various ``note`` fields,
    ``redactions[].placeholder``, ``api_deps[].endpoint_hint``. They execute nothing,
    which is exactly why they look harmless — but terminals interpret ANSI escapes,
    so a sender can **forge a line that looks like it came from us** ("✓ verified"),
    or use ``\\r`` to erase a real warning and rewrite it.

    What the recipient sees on screen is the whole basis for deciding whether to trust
    a nest. Letting someone else draw on that screen hands the disclosure surface to
    the party being disclosed.

    ``\\n`` and ``\\t`` are kept (error text is genuinely multi-line); every other
    control character becomes ``·`` — **not silently dropped**. Dropping hides that
    something was tampered with; a visible marker shows it.
    """
    return _CTRL.sub("·", _ANSI.sub("", s))

#: Frozen event vocabulary. blob-level details ride on ``log`` events as
#: structured extra fields; new event types are a contract change.
EVENT_TYPES: frozenset[str] = frozenset(
    {"stage_start", "progress", "log", "stage_done", "error", "result"}
)

#: Frozen field set of the ``progress`` event (FC-3).
PROGRESS_FIELDS: tuple[str, ...] = (
    "percent",
    "bytes_done",
    "bytes_total",
    "speed_mbps",
    "active_sources",
)


def _iso_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class EventEmitter:
    """Emit contract events as NDJSON (machine mode) and/or to a sink.

    * ``json_mode=True``: every event is written to ``stream`` (default
      stdout) as one UTF-8 JSON line — the ``--json`` contract.
    * ``sink``: optional in-process consumer (serve job store, tests);
      called for every event regardless of ``json_mode``.

    Human-mode narration goes to stderr via :meth:`log`; stdout is never
    touched unless ``json_mode`` is on, so pipes stay machine-safe.
    """

    def __init__(
        self,
        json_mode: bool = False,
        *,
        stream: IO[str] | None = None,
        sink: Callable[[dict[str, Any]], None] | None = None,
        live_progress: bool = False,
    ) -> None:
        self.json_mode = json_mode
        self._stream = stream
        self._sink = sink
        # Draw a rewriting progress line for a person watching a terminal. Off by default:
        # a pipe, a log file or --json must keep receiving exactly what they did before.
        self.live_progress = live_progress
        self._live_len = 0
        self._live_at = 0.0

    # -- the rewriting progress line ------------------------------------------
    def clear_live(self) -> None:
        """Wipe the progress line so ordinary output can print on a clean row.

        Callers that print to stderr themselves must call this first, otherwise their
        line lands on top of half a progress bar and both become unreadable."""
        if self._live_len and not self.json_mode:
            err = sys.stderr
            err.write("\r" + " " * self._live_len + "\r")
            err.flush()
            self._live_len = 0

    def _draw_progress(self, event: dict[str, Any]) -> None:
        """One line, rewritten in place. **Throttled**: 12 GB arrives as ~12,000 chunks,
        and redrawing on every one of them is its own kind of noise (and slow over ssh)."""
        done = int(event.get("bytes_done") or 0)
        total = int(event.get("bytes_total") or 0)
        pct = float(event.get("percent") or 0.0)
        now = time.monotonic()
        if pct < 100.0 and now - self._live_at < 0.4:
            return
        self._live_at = now
        filled = int(round(min(pct, 100.0) / 5))
        bar = "█" * filled + "░" * (20 - filled)
        mbps = float(event.get("speed_mbps") or 0.0)
        left = ""
        if mbps > 0 and total > done:
            secs = (total - done) * 8 / (mbps * 1e6)
            left = (f" · ~{int(secs // 60)}m {int(secs % 60):02d}s left" if secs >= 60
                    else f" · ~{int(secs)}s left")
        line = (f"  {bar} {pct:5.1f}%  {done / 2**30:.2f}/{total / 2**30:.2f} GiB"
                f"  {mbps:.0f} Mbps{left}")
        err = sys.stderr
        err.write("\r" + line.ljust(self._live_len))
        err.flush()
        self._live_len = len(line)

    # -- core ---------------------------------------------------------------

    def emit(self, type_: str, **fields: Any) -> dict[str, Any]:
        """Emit one event; returns the event dict (with type/ts)."""
        if type_ not in EVENT_TYPES:
            raise ValueError(f"unknown event type: {type_!r} (frozen contract)")
        # Sanitise at the **single exit**: every event goes through here — the
        # human-readable stderr, the NDJSON under --json, and any injected sink.
        # Doing it at each narrate() call site instead would miss some.
        event: dict[str, Any] = {
            "type": type_,
            "ts": _iso_now(),
            **{k: sanitise_terminal(v) if isinstance(v, str) else v for k, v in fields.items()},
        }
        if self.live_progress and not self.json_mode:
            if type_ == "progress":
                self._draw_progress(event)
            else:
                # Anything else means the progress line is finished with; take it down
                # before the next line prints over it.
                self.clear_live()
        if self._sink is not None:
            self._sink(event)
        if self.json_mode:
            stream = self._stream if self._stream is not None else sys.stdout
            stream.write(json.dumps(event, ensure_ascii=False) + "\n")
            stream.flush()
        return event

    # -- typed helpers (one per contract event) -------------------------------

    def stage_start(self, stage: str, desc: str, **fields: Any) -> dict[str, Any]:
        return self.emit("stage_start", stage=stage, desc=desc, **fields)

    def progress(
        self,
        stage: str,
        *,
        percent: float,
        bytes_done: int,
        bytes_total: int,
        speed_mbps: float,
        active_sources: Sequence[str],
        **fields: Any,
    ) -> dict[str, Any]:
        """Frozen progress event — all five contract fields are mandatory."""
        return self.emit(
            "progress",
            stage=stage,
            percent=percent,
            bytes_done=bytes_done,
            bytes_total=bytes_total,
            speed_mbps=speed_mbps,
            active_sources=list(active_sources),
            **fields,
        )

    def log(
        self,
        message: str,
        *,
        stage: str | None = None,
        level: str = "info",
        **fields: Any,
    ) -> dict[str, Any]:
        return self.emit(
            "log",
            level=level,
            message=message,
            **({"stage": stage} if stage is not None else {}),
            **fields,
        )

    def stage_done(self, stage: str, duration_s: float, **fields: Any) -> dict[str, Any]:
        return self.emit("stage_done", stage=stage, duration_s=duration_s, **fields)

    def error(self, failure: NestFailure) -> dict[str, Any]:
        """Contract 1.3 error object as an ``error`` event."""
        return self.emit("error", **failure.to_error_object())

    def result(self, *, ok: bool, exit_code: int, **fields: Any) -> dict[str, Any]:
        return self.emit("result", ok=ok, exit_code=exit_code, **fields)
