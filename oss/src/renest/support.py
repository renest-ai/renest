"""``renest support`` -- turn a failed run into text the user can read, then paste.

The automatic uplink carries classification and machine facts only; user content stays
on the machine. But one class of failure is only diagnosable from the original text --
somebody else's program crashed. So the user is asked to paste it: this command turns
the evidence on disk into a redacted, truncated block and prints it. No network, no
upload, no file written; what the user sees is exactly what they would send.
Attachments are deliberately not offered -- accepting them means hosting arbitrary
files, and people would end up sending models, datasets, photos of their ID.

Redaction reuses ``secrets._PATTERNS`` plus three local rules (home path becomes ``~``,
signed-link signatures dropped, ``Bearer`` values dropped). It only catches distinctive
shapes -- a homegrown password reading like an ordinary word slips through, which is
why the user must read the text before pasting. That warning is printed too.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

__all__ = [
    "BLOCK_START",
    "BLOCK_END",
    "MAX_BLOCK_BYTES",
    "LOG_TAIL_LINES",
    "redact",
    "build_block",
    "add_arguments",
    "run_from_args",
]

#: Markers around the block that gets pasted. The server locates the block by these two
#: lines so it can wipe the pasted text once the retention window is up while keeping the
#: conversation, so these literals are a contract -- do not change them casually.
BLOCK_START = "----- renest diagnostics (redacted — read it before you paste it) -----"
BLOCK_END = "----- end renest diagnostics -----"

#: Cap on the whole block. Hardcoded here as a guardrail, deliberately not an option.
MAX_BLOCK_BYTES = 16 * 1024

#: Only this many trailing lines of each log are taken -- the crash is at the end, the
#: first few hundred lines are just loading chatter.
LOG_TAIL_LINES = 120

_SIG_PARAMS = re.compile(
    r"([?&](?:X-Amz-Signature|X-Amz-Credential|X-Amz-Security-Token|Signature|sig|token|"
    r"access_token|api_key)=)[^&\s\"']+",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(Bearer\s+)\S+", re.IGNORECASE)
#: Assignments whose name alone gives them away as credentials: ``SOMETHING_KEY=value``
#: or ``SOMETHING_TOKEN: value``.
_KEYISH_ASSIGN = re.compile(
    r"\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)"
    r"(\s*[=:]\s*)(\S+)"
)


def redact(text: str, *, home: str | None = None) -> str:
    """Swap sensitive content we can recognise by shape for a visible marker.

    A marker, never a deletion: deleting leaves no sign that anything was touched.
    """
    from .secrets import _PATTERNS  # type: ignore[attr-defined]

    out = text
    for what, pattern in _PATTERNS:
        out = pattern.sub(f"[removed: {what}]", out)
    out = _SIG_PARAMS.sub(r"\1[removed: a signed-link signature]", out)
    out = _BEARER.sub(r"\1[removed: a token]", out)
    out = _KEYISH_ASSIGN.sub(r"\1\2[removed: looks like a credential]", out)
    if home is None:
        home = str(Path.home())
    if home and home not in ("/", ""):
        out = out.replace(home, "~")
    return out


def _tail(path: Path, lines: int = LOG_TAIL_LINES) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return "\n".join(text.splitlines()[-lines:])


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def build_block(evidence_dir: Path, *, home: str | None = None) -> str:
    """Turn one evidence directory into a block of text that can be pasted.

    Order follows what the reader needs: the machine (can it run at all), the outcome
    (where it died), then the crash text (why). Most cases close before section three.
    """
    from . import __version__
    from .uplink import machine_facts

    parts: list[str] = [BLOCK_START, f"renest {__version__}"]

    facts = machine_facts(evidence_dir if evidence_dir.exists() else None)
    if facts:
        parts.append("")
        parts.append("machine:")
        for key, val in facts.items():
            parts.append(f"  {key}: {val}")

    metrics = _load_json(evidence_dir / "restore-metrics.json")
    if isinstance(metrics, dict):
        parts.append("")
        parts.append("timings:")
        for key, val in metrics.items():
            if key != "_note":
                parts.append(f"  {key}: {val}")

    error = _load_json(evidence_dir / "error.json")
    if isinstance(error, dict):
        parts.append("")
        parts.append("how it failed:")
        for key in ("stage", "error_class", "exit_code", "retryable"):
            if key in error:
                parts.append(f"  {key}: {error[key]}")
        for key in ("human", "detail"):
            body = error.get(key)
            if isinstance(body, str) and body.strip():
                parts.append(f"  {key}: {redact(body.strip(), home=home)}")

    for name in ("entrypoint.log", "app-launch.log", "comfy.log"):
        tail = _tail(evidence_dir / name)
        if tail.strip():
            parts.append("")
            parts.append(f"last {LOG_TAIL_LINES} lines of {name}:")
            parts.append(redact(tail, home=home))

    parts.append(BLOCK_END)
    block = "\n".join(parts)
    if len(block.encode("utf-8")) > MAX_BLOCK_BYTES:
        # Cut from the middle: the head holds the machine and the failure attribution
        # (most useful), the tail holds the crash itself (second most useful), so what
        # goes is the log in between. Truncation must be visible, never silent.
        keep = MAX_BLOCK_BYTES // 2
        raw = block.encode("utf-8")
        head = raw[:keep].decode("utf-8", errors="ignore")
        tail = raw[-keep:].decode("utf-8", errors="ignore")
        block = (
            head
            + "\n\n[… the middle was cut to keep this under "
            + f"{MAX_BLOCK_BYTES // 1024} KB …]\n\n"
            + tail
        )
        if not block.endswith(BLOCK_END):
            block += "\n" + BLOCK_END
    return block


# --------------------------------------------------------------------------
# CLI adapter
# --------------------------------------------------------------------------
def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--dir",
        required=True,
        help="the folder you were rebuilding into (its .renest/evidence holds the run records)",
    )
    parser.add_argument(
        "--run",
        default="",
        help="which run — the folder name under .renest/evidence (default: the newest)",
    )


def _latest_run(evidence_root: Path) -> Path | None:
    try:
        runs = sorted((p for p in evidence_root.iterdir() if p.is_dir()), key=lambda p: p.name)
    except OSError:
        return None
    return runs[-1] if runs else None


def run_from_args(args: argparse.Namespace, emitter) -> int:
    import sys

    from .errors import ExitCode
    from .restore import EVIDENCE_REL

    root = Path(args.dir).expanduser() / EVIDENCE_REL
    run_dir = (root / args.run) if args.run else _latest_run(root)
    if run_dir is None or not run_dir.is_dir():
        print(
            f"✗ No run records under {root}. That folder appears after a restore runs here.",
            file=sys.stderr,
        )
        return int(ExitCode.USAGE)

    block = build_block(run_dir)
    # The instructions go to stderr and the block itself to stdout, so that
    # `renest support --dir ... | pbcopy` copies just the block, not the instructions.
    print(
        "Below is what happened, with the credential shapes we can recognise taken out.\n"
        "READ IT, then paste it into your support ticket if you are happy with it.\n"
        "Nothing has been sent anywhere — this command does not go online.\n"
        "We can only spot secrets that have a recognisable shape; anything else in there\n"
        "is still yours to check.\n",
        file=sys.stderr,
    )
    print(block)
    return int(ExitCode.OK)
