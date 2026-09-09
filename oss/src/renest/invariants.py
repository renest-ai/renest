"""Nest invariants: one judgment, every consumer (2026-09-06 ruling).

Five record-level truths about a nest, each judged in exactly one place — this
module — so the pack exit and ``renest lint`` can never drift apart on what
counts as a violation. Pack is **not the police** (packing preserves the
scene, it does not police it): nothing here adds a new hard failure to pack.
The one error-level invariant, I-2, was *already* a hard refusal in pack
before this module existed — the judgment moved here, the behavior did not
change.

The first batch:

* **I-1** (``local-version-not-pinned``) — a package pinned to a vendor-only
  local version (``torch==2.11.0+cu128``) must carry a direct wheel URL, or no
  index can serve it back. **Record level, never a failure** (2026-09-06
  ruling). The judgment is ``envlock.vendor_only_locals()``, which owns the
  family split — distro ``+ubuntu*`` and image-only ``a0+git…`` builds are
  exempted inside it, not re-exempted here. ``renest lint`` voices this
  through its own ``local-version-not-pinned`` finding on the same predicate.
* **I-2** (``code-bytes-never-downloaded``) — ``code_deps[].archive`` must hold
  real bytes: no Git LFS pointer text, no empty submodule folders. Error level;
  pack has always hard-refused this (``pack._refuse_undownloaded_code`` now
  calls here).
* **I-3** (``workflow-ref-missing``) — files the packed recipe references must
  be listed in ``files[]``.
* **I-4** (``model-license-missing``) — a model-weight entry in ``files[]``
  must carry a ``license`` block.
* **I-5** (``base-image-missing``) — a manifest with no ``base_image`` must say
  so out loud (absence is legal; *silent* absence is not).

Inputs are always the same triple — ``(manifest, lock_text, archive_dirs)`` —
plus an optional ``workflow`` (the recipe JSON, when the caller has its bytes;
only I-3 reads it). A judgment whose input is missing returns no violations:
"could not check" is not a violation.

Consumers today: ``pack`` (I-2 at archive time, I-3/I-4/I-5 as exit-time
records; I-1 is voiced by pack's own family-split lock warnings, which carry
family-specific advice) and ``renest lint`` (I-3/I-4/I-5 always; I-3 needs
``--blobs`` to reach the recipe bytes). ``Violation.code`` is the lint finding
code, so both sides say the same name for the same problem. The consistency
gate ``tests/consistency/test_invariants_single_source.py`` pins both consumers
to this module and turns red if any invariant function disappears.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "ArchiveDir",
    "INVARIANTS",
    "Violation",
    "check_all",
    "i1_local_version_needs_direct_url",
    "i2_code_bytes_never_downloaded",
    "i3_workflow_references_travel",
    "i4_model_entries_carry_licence",
    "i5_base_image_absence_is_recorded",
]


@dataclass(frozen=True)
class Violation:
    """One invariant broken once.

    ``level`` is ``"warn"`` (record) or ``"error"`` (hard). ``code`` is the
    finding code consumers show (``renest lint`` uses it verbatim), stable per
    invariant — see the module docstring for the code ↔ invariant table.
    """

    level: str
    code: str
    message: str


@dataclass(frozen=True)
class ArchiveDir:
    """A code_deps source directory as pack is about to archive it.

    ``excludes`` are the spec's own exclude patterns — the same ones the tar
    step honours, so this judgment sees exactly what the archive will hold.
    """

    install_path: str
    path: Path
    excludes: tuple[str, ...] = ()


def i1_local_version_needs_direct_url(
    manifest: dict,
    lock_text: str,
    archive_dirs: Sequence[ArchiveDir] = (),
    *,
    workflow: dict | None = None,
) -> list[Violation]:
    """I-1: a vendor-only local-version pin must carry a direct wheel URL.

    Record level, never a failure (2026-09-06 ruling: pack preserves the
    scene; the resolvability stop lives at restore S0 and at hand-off signing,
    not here). The judgment is ``envlock.vendor_only_locals()`` — it returns
    the offending raw lines with the distro/image-build exemptions already
    applied, and nothing may re-implement that split here. ``renest lint``
    already voices this judgment through its own ``local-version-not-pinned``
    finding (same predicate, artifact side), so this invariant is *not* wired
    into lint a second time — one judgment, but also one voice per consumer.
    """
    from .envlock import vendor_only_locals

    lines = [str(ln).strip() for ln in vendor_only_locals(lock_text) if str(ln).strip()]
    if not lines:
        return []
    shown = ", ".join(lines[:3]) + (f" and {len(lines) - 3} more" if len(lines) > 3 else "")
    return [
        Violation(
            "warn",
            "local-version-not-pinned",
            f"{len(lines)} package(s) pin a vendor-only build with no direct download "
            f"address recorded ({shown}). No public index serves those exact builds, so "
            f"this dependency list cannot be installed back as written — a rebuild stops "
            f"at the dependency step on any machine. Pack again with --pin-wheels while "
            f"the environment still exists, so each of those lines records a direct "
            f"address.",
        )
    ]


def i2_code_bytes_never_downloaded(
    manifest: dict,
    lock_text: str,
    archive_dirs: Sequence[ArchiveDir] = (),
    *,
    workflow: dict | None = None,
) -> list[Violation]:
    """I-2: a code archive must hold real bytes, not stand-ins.

    tar happily archives Git LFS pointer text and empty submodule folders,
    sha256 matches on restore, and the rebuilt environment is missing the code.
    Error level — pack has always hard-refused this; the messages below are the
    exact text pack raised before the judgment moved here (behavior unchanged).

    Judged from the directories about to be archived, so only callers that have
    them (pack) can check it; a manifest alone cannot say.
    """
    # Lazy import: pack imports this module at its archive step, so a top-level
    # import back into pack would be a cycle. The walkers stay in pack — they are
    # archive plumbing shared with the size preview — the *judgment* lives here.
    from .pack import _empty_submodule_dirs, _lfs_pointer_files

    out: list[Violation] = []
    for d in archive_dirs:
        pointers = _lfs_pointer_files(d.path, d.excludes)
        if pointers:
            out.append(
                Violation(
                    "error",
                    "code-bytes-never-downloaded",
                    f"{d.install_path} has {len(pointers)} file(s) that are only Git LFS "
                    f"pointer text, not the real files — this copy never downloaded them, "
                    f"so the nest would verify fine and rebuild with the code missing.\n"
                    f"  For example: {', '.join(pointers[:3])}\n"
                    f"  Run `git lfs pull` inside {d.install_path}, then pack again.",
                )
            )
            # Same order as the original refusal: pointers first, and a directory
            # that has pointers is reported for those alone (the submodule walk
            # never ran before either).
            continue
        empty_subs = _empty_submodule_dirs(d.path)
        if empty_subs:
            out.append(
                Violation(
                    "error",
                    "code-bytes-never-downloaded",
                    f"{d.install_path} declares {len(empty_subs)} sub-project folder(s) "
                    f"that are empty — that code was never downloaded, so the nest would "
                    f"verify fine and rebuild without it.\n"
                    f"  Empty: {', '.join(empty_subs[:3])}\n"
                    f"  Run `git submodule update --init --recursive` inside "
                    f"{d.install_path}, then pack again.",
                )
            )
    return out


def i3_workflow_references_travel(
    manifest: dict,
    lock_text: str,
    archive_dirs: Sequence[ArchiveDir] = (),
    *,
    workflow: dict | None = None,
) -> list[Violation]:
    """I-3: every file the packed recipe references must be listed in ``files[]``.

    Judged only when the caller has the recipe's bytes (``workflow``), and only
    for what can be judged without guessing: references made through the known
    loader table (``capture.MODEL_REF_MAP``) whose value names a weight file by
    extension. A UI-format export, an unknown node class, or a value that is a
    choice rather than a filename are all skipped — a warn-level check must not
    manufacture noise about a perfectly good nest. Capture-built manifests hold
    this by construction; this catches hand-edited ones.
    """
    if not isinstance(workflow, dict):
        return []
    from .capture import _WEIGHT_SUFFIXES, MODEL_REF_MAP, _normalize_workflow

    try:
        nodes = _normalize_workflow(workflow)
    except ValueError:
        return []  # UI export or shapeless: cannot check, which is not a violation
    listed = [
        str(f.get("path") or "").replace("\\", "/")
        for f in (manifest.get("files") or [])
        if isinstance(f, dict)
    ]
    out: list[Violation] = []
    seen: set[str] = set()
    for _node_id, node in sorted(nodes.items()):
        cls = node.get("class_type")
        inputs = node.get("inputs", {}) if isinstance(node.get("inputs"), dict) else {}
        for input_name, _category in MODEL_REF_MAP.get(cls, []):
            value = inputs.get(input_name)
            if not (isinstance(value, str) and value.lower().endswith(_WEIGHT_SUFFIXES)):
                continue
            ref = value.replace("\\", "/")
            if ref in seen:
                continue
            seen.add(ref)
            if not any(p == ref or p.endswith("/" + ref) for p in listed):
                out.append(
                    Violation(
                        "warn",
                        "workflow-ref-missing",
                        f"the recipe this nest carries asks for {value!r} "
                        f"({cls}.{input_name}) and files[] lists no file by that name — "
                        f"a rebuild comes back complete and then stops at that node the "
                        f"first time the recipe runs. Pack again from the environment "
                        f"that ran it, or add the file to files[].",
                    )
                )
    return out


def i4_model_entries_carry_licence(
    manifest: dict,
    lock_text: str,
    archive_dirs: Sequence[ArchiveDir] = (),
    *,
    workflow: dict | None = None,
) -> list[Violation]:
    """I-4: a model-weight entry must carry a ``license`` block.

    "Model entry" is judged by the same open list of weight-file extensions
    capture uses (``capture._WEIGHT_SUFFIXES``) — no new vocabulary. Absence is
    not illegal (the default-deny routing covers it), but it should be said:
    an entry with no block is treated as restricted on hand-off, and the person
    who can still fix that is the one packing. Warn level. Pack-built manifests
    hold this by construction (``_license_of`` writes a block for every entry);
    this catches manifests built by anything else.
    """
    from .capture import _WEIGHT_SUFFIXES

    out: list[Violation] = []
    for f in manifest.get("files") or []:
        if not isinstance(f, dict):
            continue
        path = str(f.get("path") or "")
        if not path.lower().endswith(_WEIGHT_SUFFIXES):
            continue
        lic = f.get("license")
        if not (isinstance(lic, dict) and lic):
            out.append(
                Violation(
                    "warn",
                    "model-license-missing",
                    f"{path} looks like model weights and carries no license block, so "
                    f"it is treated as restricted: its bytes are never passed on in a "
                    f"hand-off, and whoever receives this nest must find the file "
                    f"themselves. Record what you know under files[].license.",
                )
            )
    return out


def i5_base_image_absence_is_recorded(
    manifest: dict,
    lock_text: str,
    archive_dirs: Sequence[ArchiveDir] = (),
    *,
    workflow: dict | None = None,
) -> list[Violation]:
    """I-5: a manifest with no ``base_image`` must say so out loud.

    Absence is legal — a container often cannot see its own image name — and a
    rebuild never needed it. What is not legal is silence: the block is the one
    clue about the system layer underneath, and every missing-library remedy
    prefers "boot the recorded image" when there is one. Warn level; the text
    is the one ``renest lint`` has always used.
    """
    if manifest.get("base_image"):
        return []
    return [
        Violation(
            "warn",
            "base-image-missing",
            "this nest doesn't say which container image it was built on. That is "
            "allowed (a container often cannot see its own image name) and rebuilding "
            "never needed it — but whoever rebuilds loses the one clue about the "
            "system layer underneath.",
        )
    ]


#: The registry: (invariant id, finding code, judgment). The anti-drift gate
#: iterates this, so deleting an invariant function turns at least one test red
#: instead of going quietly.
INVARIANTS: tuple[tuple[str, str, object], ...] = (
    ("I-1", "local-version-not-pinned", i1_local_version_needs_direct_url),
    ("I-2", "code-bytes-never-downloaded", i2_code_bytes_never_downloaded),
    ("I-3", "workflow-ref-missing", i3_workflow_references_travel),
    ("I-4", "model-license-missing", i4_model_entries_carry_licence),
    ("I-5", "base-image-missing", i5_base_image_absence_is_recorded),
)


def check_all(
    manifest: dict,
    lock_text: str,
    archive_dirs: Sequence[ArchiveDir] = (),
    *,
    workflow: dict | None = None,
) -> list[Violation]:
    """Run every invariant over the same inputs, in registry order."""
    out: list[Violation] = []
    for _id, _code, fn in INVARIANTS:
        out.extend(fn(manifest, lock_text, archive_dirs, workflow=workflow))
    return out
