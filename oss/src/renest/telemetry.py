"""Anonymous usage data: off by default, asked once, contents frozen in the code.

Three hard constraints, read them before changing this file:
1. Build with a whitelist, never a blacklist. The event body is assembled field by
   field out of :data:`EVENT_FIELDS`. A blacklist fails **silently** -- the day
   upstream puts one more ``source_path`` into a result it goes straight out. A
   whitelist fails as "a new field is missing from the report": visible, and harmless.
2. **Never included**: file names, paths, the nest id, bucket name or endpoint, any
   credential, model names, anything about the content. **Included**: a random install
   id, the CLI version, success/failure and which stage failed, per-stage durations,
   total bytes, the transfer speed, and os/python/gpu/cloud guess.
   :func:`disclosure` prints exactly this list -- change a field and you must change
   that sentence; a test pins the two together.
3. Never block the main flow: 3s timeout, failures dropped, no retry, no queue.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Mapping

from .config import Config, ConfigError, is_pod_environment, user_config_path

__all__ = [
    "EVENT_SCHEMA",
    "EVENT_FIELDS",
    "ENV_FIELDS",
    "DEFAULT_ENDPOINT",
    "disclosure",
    "should_ask",
    "ask_once",
    "record_answer",
    "build_event",
    "send_event",
]

EVENT_SCHEMA = "renest-telemetry/1"

#: Where events go. Configurable through ``telemetry.endpoint``, so anyone self-hosting
#: can point it at their own server instead.
DEFAULT_ENDPOINT = "https://api.renest.ai/api/v1/telemetry/events"

_TIMEOUT_S = 3.0

#: **The reporting field whitelist (top level)**. A key that is not in this table cannot
#: get into the event body at all -- see hard constraint 1 in the module docstring.
#: The sentence next to each entry is the promise we make to the user, and
#: ``disclosure()`` turns it into the human-readable list.
EVENT_FIELDS: dict[str, str] = {
    "event": "which command finished (restore / pack / verify)",
    "ok": "whether it succeeded",
    "stage_reached": "which stage it got to (S1…S5)",
    "error_class": "the failure category, if it failed (e.g. NETWORK_INTERRUPTED)",
    "retryable": "whether that failure was worth retrying",
    "durations_s": "how long each stage took",
    "nest_size_bytes": "total size moved",
    "download_mbps": "the transfer speed that worked out to",
    "doctor_verdict": "the pre-check verdict (ok / warning / blocked)",
}

#: **The environment field whitelist**. The GPU model and the cloud guess count as
#: feature statistics, and are deliberately part of this list.
ENV_FIELDS: dict[str, str] = {
    "os": "operating system",
    "python": "Python version",
    "gpu": "GPU model",
    "cloud_guess": "which cloud it looks like",
    "arch": "CPU architecture",
}

#: **Never reported.** The whitelist already rules these out structurally; the list
#: exists to be read, because the user's question is "will you take my stuff".
NEVER_SENT = (
    "your keys or any credential",
    "file names or paths",
    "the nest id, bucket name, or endpoint",
    "anything about the models or images themselves",
)


def disclosure(*, endpoint: str | None = None, path: Path | None = None) -> str:
    """The **complete list** shown to the user -- say what would be taken before asking.

    Never a link to a web page: the credibility of asking once is in the note being
    readable right here. The "change your mind" line must give the real path and the
    real line to write; a switch nobody can find is a switch that cannot be turned off.
    """
    where = path or user_config_path()
    sends = "\n".join(f"    - {why}" for why in EVENT_FIELDS.values())
    env = ", ".join(ENV_FIELDS.values())
    never = "\n".join(f"    - {what}" for what in NEVER_SENT)
    return (
        "Renest can send anonymous usage data. It is OFF unless you turn it on.\n"
        "\n"
        "  What it would send, after a command finishes:\n"
        f"{sends}\n"
        f"    - your machine: {env}\n"
        "    - a random install id (not tied to you or any account)\n"
        "\n"
        "  What it never sends:\n"
        f"{never}\n"
        "\n"
        f"  Where it goes: {endpoint or DEFAULT_ENDPOINT}\n"
        "\n"
        "  To change your mind later, or send it to your own server instead,\n"
        f"  edit {where} :\n"
        "    [telemetry]\n"
        "    enabled = false\n"
    )


def _is_interactive(stdin: Any, stderr: Any) -> bool:
    for stream in (stdin, stderr):
        try:
            if not stream.isatty():
                return False
        except (AttributeError, ValueError):  # detached/captured streams
            return False
    return True


def should_ask(
    config: Config,
    *,
    stdin: Any,
    stderr: Any,
    json_mode: bool,
    command: str,
    env: Mapping[str, str] | None = None,
) -> bool:
    """Whether to ask at all -- the default is not to ask, and every veto is named.

    Baseline: never ask in a non-interactive environment. Two more vetoes, because an
    ssh session has a tty and isatty alone would not stop them. Never inside a pod: the
    user is waiting on a machine billed by the hour, and the answer dies with the pod,
    so it would mean asking once per pod. Never in CI: it lands in someone's build log.
    """
    env = os.environ if env is None else env
    if json_mode or command == "serve":
        return False
    if config.telemetry_asked:
        return False
    # Someone who stated their choice through the environment (RENEST_TELEMETRY=on/off)
    # has already answered; do not ask again.
    if "RENEST_TELEMETRY" in env:
        return False
    if env.get("CI"):
        return False
    if is_pod_environment(env):
        return False
    return _is_interactive(stdin, stderr)


def ask_once(
    config: Config,
    *,
    stdin: Any,
    stderr: Any,
    json_mode: bool,
    command: str,
    config_path: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> bool | None:
    """Ask once and record the answer. Returns the answer, or ``None`` if not asked.

    **The default is no**: a bare Enter means off. Someone hitting Enter in a hurry has
    not consented, and reading that Enter as a yes is theft.
    """
    if not should_ask(
        config, stdin=stdin, stderr=stderr, json_mode=json_mode, command=command, env=env
    ):
        return None
    print(
        disclosure(endpoint=config.telemetry_endpoint, path=config_path or user_config_path()),
        file=stderr,
    )
    try:
        answer = input("Turn anonymous usage data on? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        # Ctrl-C is not an answer. Write nothing and ask again next time: recording
        # "interrupted" as "declined" would close the door on turning it on forever.
        print("", file=stderr)
        return None
    enabled = answer in {"y", "yes"}
    record_answer(enabled, path=config_path)
    print(
        "Thanks — it's on. Turn it off any time in your config file."
        if enabled
        else "Left off. Nothing will be sent.",
        file=stderr,
    )
    return enabled


#: The small block written into the config. ``asked`` is **the third state of three**:
#: ``enabled`` has only true and false, which cannot tell "switched off" apart from
#: "not asked yet"; without it, the question would come back on every start.
_SECTION = "telemetry"


def record_answer(enabled: bool, *, path: Path | None = None) -> Path | None:
    """Write the answer into the user config file. If the write goes wrong, restore the
    file as it was and give up -- return None.

    This file may hold the user's bucket credentials, so a usage-data switch must never
    risk mangling it: write, read back, roll back on disagreement, fail silently.
    """
    target = path or user_config_path()
    # Bind it first: the read below can raise, and then `original` in the except clause
    # is an UnboundLocalError -- which this except does not catch.
    original: str | None = None
    try:
        original = target.read_text(encoding="utf-8") if target.exists() else None
        patched = _patched_toml(original, enabled=enabled)
        target.parent.mkdir(parents=True, exist_ok=True)
        if original is None:
            # Created 0600 straight away: this file will hold bucket credentials later,
            # so never leave a window where it carries the default permissions.
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(patched)
        else:
            target.write_text(patched, encoding="utf-8")
        if _readback(target) != enabled:
            raise ConfigError("telemetry answer did not read back")
        return target
    except (OSError, ConfigError, ValueError):
        try:
            if original is None:
                target.unlink(missing_ok=True)
            else:
                target.write_text(original, encoding="utf-8")
        except OSError:
            pass
        return None


def _readback(path: Path) -> bool | None:
    import tomllib

    with path.open("rb") as fh:
        data = tomllib.load(fh)
    section = data.get(_SECTION)
    if not isinstance(section, Mapping):
        return None
    value = section.get("enabled")
    return value if isinstance(value, bool) else None


def _patched_toml(original: str | None, *, enabled: bool) -> str:
    """Touch only the two boolean keys inside ``[telemetry]``, not one character else.

    Hand-patching TOML is only safe because the blast radius is two bools: no quote
    escaping, no multi-line values, no arrays. The caller still reads the result back.
    """
    block = f"enabled = {'true' if enabled else 'false'}\nasked = true\n"
    if original is None:
        return f"[{_SECTION}]\n{block}"
    lines = original.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip() == f"[{_SECTION}]":
            start = i
            break
    if start is None:
        sep = "" if original.endswith("\n") or not original else "\n"
        return f"{original}{sep}\n[{_SECTION}]\n{block}"
    end = len(lines)
    for i in range(start + 1, len(lines)):
        stripped = lines[i].strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            end = i
            break
    kept = [
        line
        for line in lines[start + 1 : end]
        if line.split("=")[0].strip() not in {"enabled", "asked"}
    ]
    body = block.splitlines() + kept
    return "\n".join(lines[: start + 1] + body + lines[end:]) + "\n"


def install_id(config: Config) -> str:
    """A random install id: tied to no account, no machine and no user; delete it and a
    new one takes its place."""
    return config.telemetry_install_id or str(uuid.uuid4())


def build_event(
    config: Config, *, event: str, result: Mapping[str, Any], env_info: Mapping[str, Any]
) -> dict[str, Any]:
    """Assemble the event body from the whitelist -- **picked in**, not **deleted out**
    (hard constraint 1 in the module docstring)."""
    from . import __version__

    payload: dict[str, Any] = {
        "schema": EVENT_SCHEMA,
        "install_id": install_id(config),
        "cli_version": __version__,
        "event": event,
    }
    for key in EVENT_FIELDS:
        if key == "event":
            continue
        if key in result:
            payload[key] = result[key]
    payload["env"] = {k: env_info[k] for k in ENV_FIELDS if k in env_info}
    return payload


def send_event(config: Config, payload: Mapping[str, Any]) -> bool:
    """Send once; if it cannot be sent, let it go. **No exception may escape this
    function.**"""
    if not config.telemetry_enabled:
        return False
    endpoint = config.telemetry_endpoint or DEFAULT_ENDPOINT
    try:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S):
            return True
    except (urllib.error.URLError, OSError, ValueError, TypeError):
        return False


# --------------------------------------------------------------------------
# Wiring: report one event when a restore finishes
# --------------------------------------------------------------------------
def machine_info() -> dict[str, str]:
    """Collect this machine's info per :data:`ENV_FIELDS` -- **only those five entries**.

    Deliberately not ``fingerprint.collect()``: that field list will grow (it already
    carries the whole of ``/etc/os-release``), and sharing one collector would let a
    future fingerprint field flow straight out through this pipe.

    **No hostname, user name, IP or MAC**: a hostname is very often a person's name.
    """
    import platform

    info = {
        "os": f"{platform.system().lower()}-{platform.release().split('-')[0]}",
        "python": ".".join(platform.python_version_tuple()[:2]),
        "arch": platform.machine(),
    }
    try:
        from .fingerprint import _query_nvidia_smi  # type: ignore[attr-defined]

        # It returns the first CSV line of `nvidia-smi --query-gpu=name,compute_cap` as
        # a string, not a dict. Reading it as a dict leaves this slot silently empty --
        # green tests, nothing collected. Take the model segment.
        line = _query_nvidia_smi()
        if isinstance(line, str) and line.strip():
            info["gpu"] = line.split(",")[0].strip()
    except Exception:  # noqa: BLE001 - if it cannot be collected, leave it out
        pass
    guess = _cloud_guess()
    if guess:
        info["cloud_guess"] = guess
    return info


def _cloud_guess() -> str | None:
    """Guess the cloud: only the few self-declaring markers in the environment are read;
    no network probing, no metadata service."""
    markers = {"RUNPOD_POD_ID": "runpod", "VAST_CONTAINERLABEL": "vast", "PAPERSPACE_CLUSTER_ID": "paperspace"}
    for key, name in markers.items():
        if os.environ.get(key):
            return name
    return None


def restore_sink(config: Config):
    """Return an observer to hang on the restore event stream; ``None`` when reporting
    is off (zero side effects).

    It **must** go through :func:`build_event`: a restore result carries ``nest_id``,
    ``evidence_dir`` and ``redactions``, all pointing at the user's own files. Sending
    it verbatim would void the promise invisibly -- the event stream looks innocent.
    """
    if not config.telemetry_enabled:
        return None

    def observe(event: Mapping[str, Any]) -> None:
        if event.get("type") != "result":
            return
        try:
            metrics = event.get("metrics") if isinstance(event.get("metrics"), Mapping) else {}
            result = {
                "ok": bool(event.get("ok")),
                "durations_s": event.get("stages"),
                "nest_size_bytes": metrics.get("bytes_total"),
                "download_mbps": metrics.get("mbps"),
            }
            send_event(
                config,
                build_event(
                    config,
                    event="restore_finished",
                    result={k: v for k, v in result.items() if v is not None},
                    env_info=machine_info(),
                ),
            )
        except Exception:  # noqa: BLE001 - reporting is a side path; the restore is not
            return

    return observe
