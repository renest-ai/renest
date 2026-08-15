"""Watch how much video memory a run actually uses, from the outside.

The app keeps no high-water mark of its own and we are a separate process, so
its internal counters are out of reach. What is left: ask its status endpoint
how much video memory is free every few seconds and keep the largest use seen.
Checks that far apart can miss a short burst, so this is an **observed maximum**
and the true high point can only be higher. Hence two rules baked in here: the
number always travels with the interval it was sampled at, and it may only ever
warn, never turn a machine away.

Reading the endpoint over HTTP keeps us clear of the app's licence -- none of
its code is imported. Watching is a side activity next to the run it watches, so
nothing in this module raises at the caller.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field, replace
from typing import Any

__all__ = [
    "ADVICE_LEVEL",
    "DEFAULT_INTERVAL_S",
    "MISSING_MEANS",
    "STATS_PATH",
    "DeviceVram",
    "VramWatchResult",
    "VramWatcher",
    "read_devices",
    "sample_once",
]

#: The app's own status endpoint, read over HTTP.
STATS_PATH = "/system_stats"

#: Default gap between checks: short enough to catch a model being loaded, long
#: enough that watching costs nothing next to the run itself.
DEFAULT_INTERVAL_S = 2.0

#: How long one check may take before it counts as unanswered.
_REQUEST_TIMEOUT_S = 5.0

#: What a shortfall against this number may do, and all it may ever do. The number
#: is a sampled floor that is too low by design, so acting on it any harder than a
#: warning would turn away machines that would have run the job fine.
ADVICE_LEVEL = "warn"

#: What an empty reading means -- spelled out because the wrong reading of it
#: ("nothing recorded, so nothing needed") is the dangerous one.
MISSING_MEANS = (
    "No reading here means we did not measure video memory use on this run. "
    "It does not mean the run needs none."
)


def _num(value: Any) -> float | None:
    """A real number; a bool is not one."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _shares_system_memory(dev: dict, total: float) -> bool | None:
    """Left unknown unless the reply shows the one signature seen on such a machine:
    a card total above zero while the torch figures read 0.

    A guess here would put a wrong flag in the archive, and a wrong flag is worse
    than an empty one; the dependable answer comes from torch where the run happens.
    """
    torch_total = _num(dev.get("torch_vram_total"))
    if torch_total is not None and torch_total == 0 and total > 0:
        return True
    return None


def read_devices(payload: Any) -> list[dict]:
    """Pick the per-card readings out of one status reply; a shape we do not
    recognise gives an empty list, never an exception.

    Totals come from the card's own ``vram_total`` and never from the torch
    figures: on a machine that shares memory with the system those read 0, and a
    0 total would make every use look like the whole card.
    """
    if not isinstance(payload, dict):
        return []
    devices = payload.get("devices")
    if not isinstance(devices, list):
        return []
    out: list[dict] = []
    for position, dev in enumerate(devices):
        if not isinstance(dev, dict):
            continue
        total = _num(dev.get("vram_total"))
        free = _num(dev.get("vram_free"))
        if total is None or free is None or total <= 0:
            continue
        index = dev.get("index")
        name = dev.get("name")
        has_index = isinstance(index, int) and not isinstance(index, bool)
        out.append(
            {
                "index": index if has_index else position,
                "name": name if isinstance(name, str) else "",
                "total_bytes": int(total),
                "used_bytes": int(max(0.0, total - min(free, total))),
                "unified_memory": _shares_system_memory(dev, total),
            }
        )
    return out


def sample_once(
    base_url: str,
    *,
    client: Any = None,
    timeout_s: float = _REQUEST_TIMEOUT_S,
) -> list[dict]:
    """One check. Unreachable, slow, refused, or a reply we do not recognise all come
    back as an empty list -- a failed check must never disturb the run being watched.

    Pass ``client`` to reuse an open connection; without one a short-lived client is
    opened and closed here.
    """
    own = client is None
    try:
        if own:
            import httpx

            client = httpx.Client(timeout=timeout_s)
        resp = client.get(base_url.rstrip("/") + STATS_PATH, timeout=timeout_s)
        if resp.status_code >= 400:
            return []
        return read_devices(resp.json())
    except Exception:  # noqa: BLE001 - a failed check is recorded, never raised
        return []
    finally:
        if own and client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass


@dataclass
class DeviceVram:
    """One card's readings. ``observed_max_used_bytes`` is the largest use seen across
    the checks, and it is only meaningful next to the interval on the result."""

    index: int
    name: str
    total_bytes: int
    observed_max_used_bytes: int
    unified_memory: bool | None = None

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "name": self.name,
            "total_bytes": self.total_bytes,
            "observed_max_used_bytes": self.observed_max_used_bytes,
            "unified_memory": self.unified_memory,
        }


@dataclass
class VramWatchResult:
    """What the watching produced: per-card maximums, the interval they were sampled
    at, and how many checks actually answered.

    ``samples`` counts answered checks only. Zero of them is a real answer -- see
    :data:`MISSING_MEANS` -- and must be reported as such rather than as a zero use.
    """

    sample_interval_s: float
    samples: int = 0
    unanswered_checks: int = 0
    devices: list[DeviceVram] = field(default_factory=list)

    @property
    def measured(self) -> bool:
        return self.samples > 0 and bool(self.devices)

    def to_dict(self) -> dict:
        return {
            "sample_interval_s": self.sample_interval_s,
            "samples": self.samples,
            "unanswered_checks": self.unanswered_checks,
            "measured": self.measured,
            "advice_level": ADVICE_LEVEL,
            "devices": [d.to_dict() for d in self.devices],
        }

    def describe(self) -> str:
        """Plain words for a person, with the interval always beside the number."""
        every = _every(self.sample_interval_s)
        if not self.measured:
            return (
                f"We could not read video memory use while this ran "
                f"({self.unanswered_checks} checks went unanswered). {MISSING_MEANS}"
            )
        lines = [
            f"Most video memory we saw in use, checking every {every} "
            f"({self.samples} checks answered):"
        ]
        for dev in self.devices:
            label = dev.name or f"card {dev.index}"
            tail = " — this machine shares its memory with the system" if dev.unified_memory else ""
            lines.append(
                f"  {label}: {_gib(dev.observed_max_used_bytes)} of {_gib(dev.total_bytes)}{tail}"
            )
        lines.append(
            f"Checking every {every} can miss a short burst, so the real high point can "
            f"only be above this figure, never below it."
        )
        return "\n".join(lines)


def _gib(num_bytes: int) -> str:
    return f"{num_bytes / 2**30:.1f} GiB"


def _every(seconds: float) -> str:
    return f"{seconds:g} seconds"


class VramWatcher:
    """Sample the app's status endpoint on a background thread: start, stop, take the
    result. ``client`` is for tests, which must never touch a real socket."""

    def __init__(
        self,
        base_url: str,
        *,
        interval_s: float = DEFAULT_INTERVAL_S,
        client: Any = None,
        timeout_s: float = _REQUEST_TIMEOUT_S,
    ) -> None:
        self.base_url = base_url
        self.interval_s = float(interval_s) if interval_s and interval_s > 0 else DEFAULT_INTERVAL_S
        self._client = client
        self._timeout_s = timeout_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._samples = 0
        self._unanswered = 0
        self._seen: dict[int, DeviceVram] = {}

    def start(self) -> VramWatcher:
        """Begin checking. Calling it twice does nothing the second time."""
        if self._thread is not None:
            return self
        self._stop.clear()
        thread = threading.Thread(target=self._run, name="renest-vram-watch", daemon=True)
        self._thread = thread
        thread.start()
        return self

    def stop(self, join_timeout_s: float = 10.0) -> VramWatchResult:
        """Stop checking and hand back what was collected. Safe before ``start``."""
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=join_timeout_s)
        return self.result()

    def result(self) -> VramWatchResult:
        """A snapshot, copied out -- the caller never holds objects the thread mutates."""
        with self._lock:
            devices = [replace(self._seen[i]) for i in sorted(self._seen)]
            return VramWatchResult(
                sample_interval_s=self.interval_s,
                samples=self._samples,
                unanswered_checks=self._unanswered,
                devices=devices,
            )

    def __enter__(self) -> VramWatcher:
        return self.start()

    def __exit__(self, *_exc: Any) -> None:
        self.stop()

    def _run(self) -> None:
        # First check happens straight away, so a run that ends quickly still has one.
        owned = self._client is None
        client = self._client
        if owned:
            try:
                import httpx

                client = httpx.Client(timeout=self._timeout_s)
            except Exception:  # noqa: BLE001
                client = None
        try:
            while True:
                self._take_one(client)
                if self._stop.wait(self.interval_s):
                    return
        finally:
            if owned and client is not None:
                try:
                    client.close()
                except Exception:  # noqa: BLE001
                    pass

    def _take_one(self, client: Any) -> None:
        readings = sample_once(self.base_url, client=client, timeout_s=self._timeout_s)
        with self._lock:
            if not readings:
                self._unanswered += 1
                return
            self._samples += 1
            for reading in readings:
                self._merge(reading)

    def _merge(self, reading: dict) -> None:
        index = reading["index"]
        seen = self._seen.get(index)
        if seen is None:
            self._seen[index] = DeviceVram(
                index=index,
                name=reading["name"],
                total_bytes=reading["total_bytes"],
                observed_max_used_bytes=reading["used_bytes"],
                unified_memory=reading["unified_memory"],
            )
            return
        seen.observed_max_used_bytes = max(seen.observed_max_used_bytes, reading["used_bytes"])
        seen.total_bytes = max(seen.total_bytes, reading["total_bytes"])
        if reading["unified_memory"] is True:
            seen.unified_memory = True
        if not seen.name and reading["name"]:
            seen.name = reading["name"]
