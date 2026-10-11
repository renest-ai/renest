"""What a nest knowingly does not carry, as data rather than prose.

Packing has always said these things in warnings: a data file a node names that sits
outside everything packed (probe G2, 2026-10-08), a node that keeps first-use downloads
under ``~/.cache`` (probe J), packages whose GPU build targets were never read before
the time budget ran out, files a node fetched while the working run went and that were
not carried (batch 24 U1: 13 files, 0.88 GB, fetched again on restore without a word).
A warning scrolls away on the packing machine; the person restoring never sees it.
Each one is recorded here in one shape, so the pack can print it, ``--json`` can carry
it, and a restore can say it again on the machine where it matters.

One entry: ``{"kind", "subject", "detail", "required"}``.

- ``subject``: a path (relative to the environment root, or ``~/...`` for the home
  folder -- never an absolute path on the packing machine) or a package name.
- ``detail``: a short English sentence.
- ``required``: ``"yes"`` (the run needs it; nothing produces this today),
  ``"maybe"`` (the run may need it), ``"cache"`` (a cache the app rebuilds by itself
  when the source is still reachable).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

__all__ = [
    "KINDS",
    "REQUIRED",
    "gap",
    "gap_line",
    "has_required",
    "valid_gaps",
]

#: Every kind a writer may use. A reader meets kinds it does not know with the same
#: line as any other -- the list grows; a new kind is not a reason to refuse a nest.
KINDS = (
    "data_outside_node",
    "runtime_download",
    "native_arch_unread",
    "home_config",
    "home_cache_not_carried",
)

REQUIRED = ("yes", "maybe", "cache")


def gap(kind: str, subject: str, detail: str, required: str = "maybe") -> dict:
    """One entry, checked on the way in so a writer cannot invent a shape."""
    if kind not in KINDS:
        raise ValueError(f"unknown gap kind {kind!r}")
    if required not in REQUIRED:
        raise ValueError(f"unknown required value {required!r}")
    return {"kind": kind, "subject": str(subject), "detail": str(detail), "required": required}


def valid_gaps(raw: object) -> list[dict]:
    """The entries of a manifest's ``capture_gaps`` a reader can print. Anything not
    shaped like an entry is skipped rather than raised on: a hand-edited nest must not
    stop a restore over a line of prose."""
    if not isinstance(raw, list):
        return []
    out = []
    for g in raw:
        if not isinstance(g, Mapping):
            continue
        subject = g.get("subject")
        if not isinstance(subject, str) or not subject:
            continue
        kind, req, detail = g.get("kind"), g.get("required"), g.get("detail")
        # Same reading as restore.sh's jq (test_both_legs_agree_on_capture_gaps): a value
        # of the wrong type reads as absent, never as its text.
        out.append({"kind": kind if isinstance(kind, str) and kind else "unknown",
                    "subject": subject,
                    "detail": detail if isinstance(detail, str) else "",
                    "required": req if isinstance(req, str) and req else "maybe"})
    return out


def has_required(gaps: Iterable[Mapping]) -> bool:
    """True when at least one entry says the run needs it (``required: "yes"``)."""
    return any(str(g.get("required")) == "yes" for g in gaps)


_LABEL = {"yes": "needed", "maybe": "may be needed", "cache": "cache"}


def gap_line(g: Mapping) -> str:
    """One line for a person: ``subject (may be needed): detail``."""
    req = _LABEL.get(str(g.get("required")), str(g.get("required")))
    detail = str(g.get("detail") or "")
    line = f"{g.get('subject')} ({req}){': ' + detail if detail else ''}"
    # One line per gap on both legs: tabs and line breaks in hand-written text become spaces.
    return line.replace("\t", " ").replace("\r", " ").replace("\n", " ")
