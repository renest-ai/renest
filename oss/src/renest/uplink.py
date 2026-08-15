"""What goes up to the server: a **whitelist gate** plus a **machine facts snapshot**
(shared by ``restore --grant`` and ``pack --dest hosted``).

Forwarding events verbatim leaks user content, and these fields are why: ``error.detail``
(raw uv output -- local paths, private index URLs that often embed a password),
``error.context`` (local file paths), ``error.human`` / ``log.message`` (free text full of
paths and file names), ``result.evidence_dir`` and ``result.oneshot.log`` (local paths),
``result.redactions`` (which key of which config file points at something of the user's),
``progress.active_sources`` (which host this run pulled from). **None of them go up.**

Three hard constraints: **whitelist, not blacklist**, per type and per field, so a new
upstream field fails as "did not go up" instead of leaking; **a string passes only if it
comes from a frozen vocabulary** (free text is exactly what paths and raw error output
look like, so the whole ``log`` type never goes up); **never block, never raise**.
"""

from __future__ import annotations

import os
import re
from typing import Any, Mapping

from .errors import PACK_STAGES, STAGES, ErrorClass

__all__ = [
    "UPLINK_CONTRACT_VERSION",
    "UPLINK_FIELDS",
    "NEVER_UPLINKED",
    "MACHINE_FIELDS",
    "scrub_event",
    "scrub_events",
    "machine_facts",
    "disclosure",
]

# --------------------------------------------------------------------------
# Value shapes (the whitelist lets only these through; anything else is dropped)
# --------------------------------------------------------------------------
_NUM = "number"  # int/float (a bool does not count as a number)
_INT = "int"
_BOOL = "bool"
_STAGE = "stage"  # must be a frozen stage code (S0...S5 / P1...P4)
_ERROR_CLASS = "error_class"  # must be one of the frozen failure classes
_STAGE_SECONDS = "stage_seconds"  # {stage code: seconds}
_METRICS = "metrics"  # {a fixed set of metric names: number}
_BLOBS = "blobs"  # {total/downloaded/cached: counts}

#: Stage-code vocabulary: the five rebuild stages plus the four pack stages
#: (frozen in ``errors.py``).
_STAGE_VOCAB = frozenset(STAGES) | frozenset(PACK_STAGES)

#: Failure-class vocabulary (frozen in ``errors.py``).
_ERROR_CLASS_VOCAB = frozenset(str(c) for c in ErrorClass)

#: Metric names allowed to go up inside ``result.metrics``. Any extra key (for example
#: a human-readable ``_note``) is dropped: it is a string, and strings hide paths.
_METRIC_KEYS = frozenset(
    {
        "transfer_seconds",
        "transfer_bytes",
        "deps_seconds",
        "verify_seconds",
        "total_seconds",
    }
)

#: Counter names allowed to go up inside ``result.blobs``.
_BLOB_KEYS = frozenset({"total", "downloaded", "cached"})

#: Timestamp shape (produced by ``events.py`` itself, not user input; shape-checked
#: anyway).
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# --------------------------------------------------------------------------
# The whitelist itself: event type -> {field: (shape, what this field is)}. That
# trailing sentence is the promise made to the user; :func:`disclosure` renders it and a
# test pins the two together -- **change a field, change that sentence.**
# --------------------------------------------------------------------------

#: Version of the uplink contract, sent with every batch so the server can tell old
#: clients apart. Any change bumps it (adding a field included), and the server-side
#: receive whitelist plus the format specs must be updated to match. A consumer meeting
#: a key it does not know must ignore it, not reject the batch.
UPLINK_CONTRACT_VERSION = "1"

UPLINK_FIELDS: dict[str, dict[str, tuple[str, str]]] = {
    "stage_start": {
        "stage": (_STAGE, "which gate it entered"),
        # The pack side reports the size once before the upload starts (hosted.py):
        # counts only, no names, no paths.
        "blobs_total": (_INT, "how many files this nest has"),
        "blobs_to_upload": (_INT, "how many of them still need uploading"),
        "declared_bytes": (_INT, "how many bytes they add up to"),
    },
    "progress": {
        "stage": (_STAGE, "which gate it is in"),
        "percent": (_NUM, "how far along"),
        "bytes_done": (_NUM, "bytes moved so far"),
        "bytes_total": (_NUM, "bytes to move in total"),
        "speed_mbps": (_NUM, "the speed that works out to"),
        # The pack side reports once per finished file
        "bytes": (_NUM, "bytes in the file just moved"),
        "seconds": (_NUM, "how long that took"),
        "mbps": (_NUM, "the speed that worked out to"),
    },
    "stage_done": {
        "stage": (_STAGE, "which gate finished"),
        "duration_s": (_NUM, "how long that gate took"),
        # The three counters of the pack-side spot check that lets files stay home.
        # They ride on ``stage_done`` rather than on a type of their own: an event type
        # outside the frozen vocabulary is silently dropped by the server.
        # All counts: no names, no paths.
        "challenge_verified": (_INT, "spot-checked files that stayed home"),
        "challenge_unproven": (_INT, "spot-checked files that must travel in full"),
        "challenge_bytes_saved": (_INT, "bytes the spot check saved from uploading"),
    },
    "error": {
        "stage": (_STAGE, "which gate it died in"),
        "error_class": (_ERROR_CLASS, "the failure category (e.g. NETWORK_INTERRUPTED)"),
        "exit_code": (_INT, "the exit code that goes with it"),
        "retryable": (_BOOL, "whether that failure was worth retrying"),
    },
    "result": {
        "ok": (_BOOL, "whether it succeeded"),
        "exit_code": (_INT, "the exit code it finished with"),
        "stages": (_STAGE_SECONDS, "how long each gate took"),
        "metrics": (_METRICS, "total bytes moved, and the seconds each part took"),
        "blobs": (_BLOBS, "how many files were downloaded, and how many were already there"),
        # The pack side's closing counters
        "uploaded_blobs": (_INT, "how many files went up"),
        "skipped_blobs": (_INT, "how many were already in storage"),
        "uploaded_bytes": (_INT, "how many bytes went up"),
        "seconds": (_NUM, "how long the whole upload took"),
    },
    # ``log`` is deliberately absent: **the whole type never goes up** (hard constraint 2).
}

#: These **never go up**. They are listed for people to read (the whitelist already rules
#: them out structurally), because what a user asks is "will you take my stuff", not
#: "is your implementation a whitelist or a blacklist".
NEVER_UPLINKED = (
    "your keys or any credential",
    "file names or paths on your machine",
    "the raw error text from other programs (uv, ComfyUI, the training script)",
    "which host the files came from — your bucket or CDN",
    "anything about the models, datasets or images themselves",
)


# --------------------------------------------------------------------------
# The gate itself
# --------------------------------------------------------------------------
def _is_number(value: Any) -> bool:
    # In Python a bool is a subclass of int; a numeric slot must not accept True.
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _num_map(value: Any, *, allowed_keys: frozenset[str] | None) -> dict[str, Any] | None:
    """A small {name: number} mapping. Keys are either limited to the given vocabulary,
    or must be stage codes."""
    if not isinstance(value, Mapping):
        return None
    keys = allowed_keys if allowed_keys is not None else _STAGE_VOCAB
    out = {k: v for k, v in value.items() if k in keys and _is_number(v)}
    return out or None


def _pass(kind: str, value: Any) -> Any | None:
    """Let a value through by shape; return ``None`` if the shape does not fit
    (= drop this field)."""
    if kind == _NUM:
        return value if _is_number(value) else None
    if kind == _INT:
        return value if isinstance(value, int) and not isinstance(value, bool) else None
    if kind == _BOOL:
        return value if isinstance(value, bool) else None
    if kind == _STAGE:
        return value if isinstance(value, str) and value in _STAGE_VOCAB else None
    if kind == _ERROR_CLASS:
        return value if isinstance(value, str) and value in _ERROR_CLASS_VOCAB else None
    if kind == _STAGE_SECONDS:
        return _num_map(value, allowed_keys=None)
    if kind == _METRICS:
        return _num_map(value, allowed_keys=_METRIC_KEYS)
    if kind == _BLOBS:
        return _num_map(value, allowed_keys=_BLOB_KEYS)
    return None


def scrub_event(event: Mapping[str, Any]) -> dict[str, Any] | None:
    """Pick an event down to what may go up; return ``None`` for a type that never goes up.

    **Picked in, not deleted out**: the result dict is assembled slot by slot from the
    whitelist, so any extra key in the source event cannot reach the return value --
    including keys somebody adds later.
    """
    if not isinstance(event, Mapping):
        return None
    etype = event.get("type")
    if not isinstance(etype, str):
        return None
    allowed = UPLINK_FIELDS.get(etype)
    if allowed is None:
        return None  # log and any unregistered type: the whole type never goes up
    out: dict[str, Any] = {"type": etype}
    ts = event.get("ts")
    if isinstance(ts, str) and _TS.match(ts):
        out["ts"] = ts
    for key, (kind, _why) in allowed.items():
        if key not in event:
            continue
        value = _pass(kind, event[key])
        if value is not None:
            out[key] = value
    return out


def scrub_events(events: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Run a whole batch through the gate; whatever is held back simply disappears
    (no placeholder left behind, no surface to probe)."""
    out: list[dict[str, Any]] = []
    for ev in events:
        try:
            kept = scrub_event(ev)
        except Exception:  # noqa: BLE001 - a fault in the gate must not affect real work
            kept = None
        if kept is not None:
            out.append(kept)
    return out


# --------------------------------------------------------------------------
# Machine facts snapshot: the half that can settle a diagnosis, and it contains
# not one character of user content
# --------------------------------------------------------------------------
#: What is collected, and why. Also a list meant for people to read
#: (:func:`disclosure` uses it).
MACHINE_FIELDS: dict[str, str] = {
    "os": "operating system and version",
    "arch": "CPU architecture",
    "python": "Python version",
    "gpu": "GPU model",
    "gpu_compute": "what compute level that GPU is",
    "vram_gb": "how much video memory it has",
    "driver": "GPU driver version",
    "driver_cuda": "the newest CUDA that driver can carry",
    "cpu_features": "which of the CPU instruction sets torch needs are present",
    "disk_free_gb": "free space where it is rebuilding (the amount, never the path)",
    "cloud": "which cloud it looks like, guessed from environment variables only",
}

#: The CPU instruction sets torch and kornia need; without them ComfyUI dies with
#: "Illegal instruction" the moment it starts. A fixed vocabulary -- what goes up is
#: "which of these few are present", never the raw lscpu text.
_CPU_FEATURES = ("avx", "avx2", "avx512f", "f16c")

#: Cloud markers: only these self-declaring environment variables are read,
#: **no network probing, no metadata service**.
_CLOUD_MARKERS = {
    "RUNPOD_POD_ID": "runpod",
    "VAST_CONTAINERLABEL": "vast",
    "PAPERSPACE_CLUSTER_ID": "paperspace",
}


def machine_facts(target: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Collect the facts about this machine -- **only** the entries in
    :data:`MACHINE_FIELDS`.

    These are the half that settles a diagnosis (which GPU, driver, video memory, Python)
    and they hold no user content. What they cannot settle is somebody else's program
    crashing on its own: that answer lives only in the crash text, which is user content,
    so it stays local under ``.renest/evidence/`` for the user to paste or not.

    Deliberately **not reusing** ``telemetry.machine_info()`` or ``fingerprint.collect()``:
    with a shared collector, a field added on either side would later flow out through
    somebody else's pipe. The few extra lines here are on purpose.

    **No hostname, user name, IP or network address** (a hostname is very often a person's
    name) and **no speed test** (tens of seconds, and the uplink does not get to slow a
    restore down). Whatever cannot be collected is left out, and **no exception may
    escape this function**.
    """
    import platform

    facts: dict[str, Any] = {}
    try:
        facts["os"] = f"{platform.system().lower()}-{platform.release().split('-')[0]}"
        facts["arch"] = platform.machine()
        facts["python"] = ".".join(platform.python_version_tuple()[:2])
    except Exception:  # noqa: BLE001
        pass

    # -- The GPU trio: model, compute level, video memory. One nvidia-smi call, not three.
    try:
        from .doctor import _run_cmd  # type: ignore[attr-defined]

        out = _run_cmd(
            [
                "nvidia-smi",
                "--query-gpu=name,compute_cap,memory.total,driver_version",
                "--format=csv,noheader,nounits",
            ],
            timeout=10,
        )
        line = out.strip().splitlines()[0] if out.strip() else ""
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 4:
            if parts[0]:
                facts["gpu"] = parts[0]
            if parts[1]:
                facts["gpu_compute"] = parts[1]
            try:
                facts["vram_gb"] = round(float(parts[2]) / 1024, 1)
            except ValueError:
                pass
            if parts[3]:
                facts["driver"] = parts[3]
    except Exception:  # noqa: BLE001 - no GPU and no driver are both normal cases
        pass

    try:
        from .doctor import collect_driver_cuda_version

        cuda = collect_driver_cuda_version()
        if cuda:
            facts["driver_cuda"] = cuda
    except Exception:  # noqa: BLE001
        pass

    # -- CPU instructions: report which of the fixed few are present, never the raw text
    try:
        from .doctor import collect_cpu_flags

        blob = collect_cpu_flags().lower()
        if blob:
            facts["cpu_features"] = [f for f in _CPU_FEATURES if re.search(rf"\b{f}\b", blob)]
    except Exception:  # noqa: BLE001
        pass

    # -- How much disk is left. **The amount only, never which directory** --
    try:
        from .doctor import collect_disk_free

        free = collect_disk_free(target if target is not None else "/")
        if free:
            facts["disk_free_gb"] = round(free / 2**30, 1)
    except Exception:  # noqa: BLE001
        pass

    for key, name in _CLOUD_MARKERS.items():
        if os.environ.get(key):
            facts["cloud"] = name
            break

    return facts


# --------------------------------------------------------------------------
# The list meant for people to read
# --------------------------------------------------------------------------
def disclosure_brief() -> str:
    """The four lines a person actually reads while waiting for a rebuild.

    **Why a short form exists at all.** The full list below is deliberately printed in the
    terminal rather than hidden behind a website link -- its whole credibility is being
    readable on the spot. But at ~35 lines it filled the screen on every run and pushed the
    thing the user was waiting for (progress) out of view; watched live on 2026-08-10, the
    disclosure scrolled past and the founder could not tell whether the command was working.
    A wall of text nobody finishes is not disclosure either.

    So: four lines every time, and the complete field-by-field list one flag away and still
    **inside the tool** (``--verbose``) -- never "see our website".
    """
    return (
        "Progress goes back to your drive so you can watch it there, and so we can help "
        "if it fails.\n"
        "  Sent: which step it is on, how many bytes moved and how fast, and this "
        "machine's hardware and versions.\n"
        "  Never sent: credentials, your file names or paths, or anything about the "
        "models, data or images themselves.\n"
        "  Turn it off with --no-report; see every single field with --verbose.\n"
    )


def disclosure() -> str:
    """A note short enough to finish on the spot: what goes up, what never goes up,
    and how to switch it off.

    Never replaced by "see the link on our website" -- all of its credibility is in
    being readable right here.
    """
    sends: list[str] = []
    seen: set[str] = set()
    for fields in UPLINK_FIELDS.values():
        for _key, (_kind, why) in fields.items():
            if why not in seen:
                seen.add(why)
                sends.append(f"    - {why}")
    machine = ", ".join(MACHINE_FIELDS.values())
    never = "\n".join(f"    - {what}" for what in NEVER_UPLINKED)
    return (
        "While this runs, progress goes back to your drive so you can watch it there,\n"
        "and so we can help if it fails.\n"
        "\n"
        "  What goes back:\n"
        + "\n".join(sends)
        + "\n"
        f"    - about the machine: {machine}\n"
        "\n"
        "  What never goes back:\n"
        f"{never}\n"
        "\n"
        "  To turn it off for this run, add --no-report.\n"
    )
