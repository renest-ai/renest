"""Files under an environment root that the nest does not list.

Why this exists (batch 24, 2026-10-09): a face-swap node fetched 8 model files
(about 0.88 GB) the first time it ran on the restore machine. The rebuild's own test
render was online, so it produced its images and the restore said nothing -- the nest
was short of those files, and only a machine with internet access hid it.

One reusable question, kept apart from where it is asked: **which files are here that
the nest does not carry, and how big are they**. A restore asks it around the app's
start and test render (files that appeared while the app ran); a pack can ask the
same question later to record the same facts at pack time.

What it never counts: what an app writes as its own output or bookkeeping (output/,
temp/, user/ in ComfyUI), Python caches, the environment's own virtualenv, and our own
``.renest`` folder. The list comes from what the batch-24 restore machines actually
showed after a run -- not from a guess about what apps might write.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

__all__ = [
    "NOTABLE_FOLDER_BYTES",
    "UnlistedFile",
    "group_by_folder",
    "notable_folders",
    "snapshot",
    "unlisted_files",
]

#: Folders never walked: caches, environments and our own records. Matched against any
#: path part. ``output`` / ``temp`` / ``user`` are where ComfyUI writes its renders, its
#: preview images and its settings database; every batch-24 restore showed files there
#: after a run and none of them was something the nest should carry.
SKIP_DIRS = frozenset({
    ".git", "__pycache__", ".venv", "venv", "node_modules", ".renest",
    "output", "temp", "user", ".cache", ".ipynb_checkpoints",
})

#: Files an app writes for itself while running (byte-code, logs, lock and database
#: files). Not something a nest is short of.
SKIP_SUFFIXES = (".pyc", ".pyo", ".log", ".lock", ".db", ".db-wal", ".db-shm",
                 ".sqlite", ".sqlite-journal", ".tmp")

#: Below this per-folder total, new files are bookkeeping, not a missing download. Read
#: off batch 24: the face-swap restore's three folders held 195 MB to 344 MB each; the
#: only other new files under a restore root were a plugin's side-car notes beside a
#: checkpoint (`.civitai.info`, `.metadata.json`, `.sha256`; 27 KB together).
NOTABLE_FOLDER_BYTES = 1 << 20


@dataclass(frozen=True)
class UnlistedFile:
    path: str        # relative to the root, forward slashes
    size_bytes: int


def _skipped(rel: PurePosixPath) -> bool:
    if SKIP_DIRS.intersection(rel.parts[:-1]):
        return True
    return rel.name.endswith(SKIP_SUFFIXES)


def _walk(root: Path) -> Iterable[tuple[str, int]]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            rel = PurePosixPath(p.relative_to(root).as_posix())
            if _skipped(rel):
                continue
            try:
                if p.is_symlink() or not p.is_file():
                    continue
                size = p.stat().st_size
            except OSError:
                continue
            yield rel.as_posix(), size


def snapshot(root: str | os.PathLike[str]) -> frozenset[str]:
    """Every file under ``root`` that :func:`unlisted_files` would look at, by path.

    Taken before the app starts, so a later call can tell what appeared since."""
    r = Path(root)
    if not r.is_dir():
        return frozenset()
    return frozenset(path for path, _ in _walk(r))


def _listed(manifest: Mapping, *, with_code_dirs: bool) -> tuple[set[str], list[str]]:
    files = {str(f.get("path")).strip("/") for f in manifest.get("files") or []
             if isinstance(f, Mapping) and f.get("path")}
    dirs: list[str] = []
    if with_code_dirs:
        dirs = [str(d.get("install_path")).strip("/") for d in manifest.get("code_deps") or []
                if isinstance(d, Mapping) and d.get("install_path")]
    return files, [d for d in dirs if d]


def unlisted_files(
    root: str | os.PathLike[str],
    manifest: Mapping,
    *,
    before: frozenset[str] | set[str] | None = None,
) -> list[UnlistedFile]:
    """Files under ``root`` the nest does not list, with their sizes, sorted by path.

    ``before``: a :func:`snapshot` taken earlier. Given one, only files that appeared
    since then count (the restore case: what the app added while it ran), and the code
    folders count as not listed -- whatever a node writes into its own folder after it
    was unpacked did not come out of its archive. Without one, files inside the code
    folders the nest packs as archives count as listed (the pack case).
    """
    r = Path(root)
    if not r.is_dir():
        return []
    files, code_dirs = _listed(manifest, with_code_dirs=before is None)
    out: list[UnlistedFile] = []
    for path, size in _walk(r):
        if before is not None and path in before:
            continue
        if path in files or any(path.startswith(d + "/") for d in code_dirs):
            continue
        out.append(UnlistedFile(path, size))
    return sorted(out, key=lambda f: f.path)


def group_by_folder(found: Iterable[UnlistedFile]) -> dict[str, list[UnlistedFile]]:
    """``{folder: files}`` -- the folder each file sits in, relative to the root."""
    out: dict[str, list[UnlistedFile]] = {}
    for f in found:
        out.setdefault(str(PurePosixPath(f.path).parent), []).append(f)
    return out


def notable_folders(found: Iterable[UnlistedFile],
                    min_bytes: int = NOTABLE_FOLDER_BYTES) -> list[dict]:
    """The folders worth telling a person about: ``[{folder, files, size_bytes, paths}]``,
    largest first. A folder whose new files add up to less than ``min_bytes`` is left
    out (see :data:`NOTABLE_FOLDER_BYTES`)."""
    rows = []
    for folder, group in group_by_folder(found).items():
        total = sum(f.size_bytes for f in group)
        if total < min_bytes:
            continue
        rows.append({"folder": folder, "files": len(group), "size_bytes": total,
                     "paths": [f.path for f in group]})
    return sorted(rows, key=lambda r: (-r["size_bytes"], r["folder"]))
