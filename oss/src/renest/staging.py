"""Let go of the local staging of a nest the drive has confirmed (ruled 2026-10-19).

A pack lands its manifest under ``<out>/nests/<id>/`` and its bytes under
``<out>/blobs/sha256/xx/<sha>`` -- model files as **hard links** to the originals. That
is why "I saved it to the drive, now I delete the original to free disk" freed nothing
(measured 2026-10-19 on the house machine: deleting the original gave back 0 bytes while
the staging still held the link). So once the drive has checked a nest, the panel path
removes the nest's own staging here: its manifest folder, and every blob **no other nest
in the same folder still references**.

Three rules, each with a test:

* only after the drive said ``committed`` (the caller decides; this module never asks);
* only under ``<out>`` -- never a file of the person's own (a hard link's other name is
  theirs; unlinking ours leaves theirs untouched);
* a blob shared with another nest in ``<out>/nests/`` stays, by reference count read
  off the manifests on disk, not off memory.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

__all__ = ["release_local_staging"]


def _blob_shas(manifest: object) -> set[str]:
    """Every content-addressed reference in a manifest: ``{"sha256": …, "size_bytes": …}``."""
    out: set[str] = set()

    def walk(o: object) -> None:
        if isinstance(o, dict):
            sha = o.get("sha256")
            if isinstance(sha, str) and len(sha) == 64 and "size_bytes" in o:
                out.add(sha.lower())
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(manifest)
    return out


def release_local_staging(manifest_path: str | os.PathLike[str]) -> dict:
    """Remove this nest's staging under its ``<out>`` folder. Returns what happened.

    ``manifest_path`` is ``<out>/nests/<id>/manifest.json`` as pack reported it. Anything
    that does not look like that layout is left alone and reported as ``skipped``.
    """
    mp = Path(manifest_path).resolve()
    nest_dir = mp.parent
    nests_dir = nest_dir.parent
    out = nests_dir.parent
    report: dict = {"released": False, "blobs_removed": 0, "bytes_freed": 0,
                    "blobs_kept_shared": 0, "nest_dir": str(nest_dir)}
    if mp.name != "manifest.json" or nests_dir.name != "nests" or not (out / "blobs").is_dir():
        report["skipped"] = "not a nests/ + blobs/ layout"
        return report
    try:
        mine = _blob_shas(json.loads(mp.read_text(encoding="utf-8")))
    except (OSError, ValueError) as e:
        report["skipped"] = f"manifest unreadable: {type(e).__name__}"
        return report
    others: set[str] = set()
    for other in nests_dir.iterdir():
        if other == nest_dir or not other.is_dir():
            continue
        om = other / "manifest.json"
        try:
            others |= _blob_shas(json.loads(om.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            # An unreadable neighbour might reference anything: keep every blob, to be safe.
            report["skipped"] = f"another nest's manifest is unreadable ({other.name}); nothing removed"
            return report
    blobs = out / "blobs" / "sha256"
    for sha in sorted(mine):
        if sha in others:
            report["blobs_kept_shared"] += 1
            continue
        p = blobs / sha[:2] / sha
        try:
            size = p.stat().st_size
            p.unlink()
        except FileNotFoundError:
            continue
        except OSError:
            continue
        report["blobs_removed"] += 1
        report["bytes_freed"] += size
        with os.scandir(p.parent) as it:
            if next(it, None) is None:
                os.rmdir(p.parent)
    shutil.rmtree(nest_dir, ignore_errors=True)
    report["released"] = not nest_dir.exists()
    return report
