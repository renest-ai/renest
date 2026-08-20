"""Evidence a successful run leaves behind, read after the fact.

Renest is never present while a run happens (2026-08-11 ruling): it only reads
what a finished run already left on disk. ComfyUI writes the exact workflow it
ran into the picture it produced, as a PNG text chunk named ``prompt`` — that
chunk is the only thing read here, and the picture itself is never opened as an
image (no decode call appears on this path; a consistency test greps for it).
A training framework instead leaves its step count in ``trainer_state.json``
and its output weights on disk, once training actually progressed past zero.

Finding evidence is a yes/no question, never a "which one" question: every
recipe found is kept (see :func:`scan_comfyui_output`), and picking one to
drive the file-completeness check is an internal detail, never a choice put
to the user.
"""

from __future__ import annotations

import json
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "ComfyUIEvidence",
    "RecipeEvidence",
    "TrainingEvidence",
    "png_text_chunks",
    "scan_comfyui_output",
    "scan_saved_workflows",
    "training_verified_run",
]


#: Most a single text chunk may be read. A damaged or hostile PNG is free to
#: declare a 4 GB chunk length, and we must not believe it.
_MAX_TEXT_CHUNK = 32 * 1024 * 1024


def png_text_chunks(path: Path) -> dict[str, str]:
    """Every tEXt/iTXt chunk of a PNG, keyed by chunk name.

    Walks the byte structure only — never Pillow, never any image decode.
    ComfyUI writes the workflow that produced this file into the chunk named
    ``prompt``. A file that is not a well-formed PNG returns an empty dict
    rather than raising: a corrupt or foreign file is "no evidence", not a
    crash.
    """
    out: dict[str, str] = {}
    try:
        with path.open("rb") as fh:
            if fh.read(8) != b"\x89PNG\r\n\x1a\n":
                return {}
            while True:
                head = fh.read(8)
                if len(head) < 8:
                    break
                (ln,) = struct.unpack(">I", head[:4])
                typ = head[4:8]
                if typ == b"IEND":
                    break
                if typ in (b"tEXt", b"iTXt") and ln <= _MAX_TEXT_CHUNK:
                    body = fh.read(ln)
                    if len(body) < ln:
                        break
                else:
                    # **Skip the picture data outright; it never enters memory.**
                    # A render is several MB and all we want is a few hundred bytes
                    # of text, and the scan walks the whole output tree.
                    fh.seek(ln, 1)
                    fh.seek(4, 1)  # CRC
                    continue
                fh.seek(4, 1)  # CRC
                if typ == b"tEXt":
                    k, _, v = body.partition(b"\x00")
                    out[k.decode("latin1")] = v.decode("utf-8", "replace")
                else:
                    k, _, rest = body.partition(b"\x00")
                    comp = rest[0:1]
                    rest = rest[1:]
                    _, _, rest = rest.partition(b"\x00")  # compression method
                    _, _, rest = rest.partition(b"\x00")  # language tag
                    _, _, val = rest.partition(b"\x00")  # translated keyword
                    try:
                        out[k.decode("latin1")] = (
                            zlib.decompress(val) if comp == b"\x01" else val
                        ).decode("utf-8", "replace")
                    except (zlib.error, OSError):
                        continue
    except OSError:
        return {}
    return out


@dataclass
class RecipeEvidence:
    """One recipe found on disk, plus where it came from."""

    workflow: dict
    mtime: float
    source_path: Path | None  # None for a PNG-recovered recipe: no standalone file exists
    origin: str  # "output_image" or "saved_workflow", for the disclosure text


@dataclass
class ComfyUIEvidence:
    """Whether this environment has ever produced a picture with its recipe
    attached, and every recipe found while looking (never just one)."""

    recipes: list[RecipeEvidence] = field(default_factory=list)
    unreadable: list[Path] = field(default_factory=list)  # PNGs with no usable recipe block

    @property
    def verified(self) -> bool:
        return bool(self.recipes)

    @property
    def most_recent(self) -> RecipeEvidence | None:
        return self.recipes[0] if self.recipes else None


def scan_comfyui_output(output_dir: Path) -> ComfyUIEvidence:
    """Read every PNG under ``output_dir`` for its recipe chunk.

    **Subfolders count.** This used to look only in the top folder, on the idea that
    a subfolder is a user sorting their own pictures. That idea is wrong: ComfyUI
    itself writes into ``output/<sub>/`` whenever the save node's filename prefix
    contains a slash, which is an ordinary thing to set. The cost of being wrong is
    heavy and silent -- an environment that really has produced pictures packs as
    "nothing here is confirmed to have worked yet", and every restore of it then
    skips the one check worth most (does the recipe still run?), forever.
    Measured 2026-08-20: a picture one folder down was invisible, and did not even
    show up as unreadable, so nothing on screen hinted anything had been skipped.

    Sorting a user's own pictures in is not a danger: evidence is "this PNG carries
    a ComfyUI ``prompt`` block", which holiday photos do not have. A PNG with no
    ``prompt`` chunk, or one that fails to parse as JSON, is reported as unreadable
    and skipped -- never guessed at.
    """
    recipes: list[RecipeEvidence] = []
    unreadable: list[Path] = []
    if output_dir.is_dir():
        for p in sorted(output_dir.rglob("*.png")):
            raw = png_text_chunks(p).get("prompt")
            if not raw:
                unreadable.append(p)
                continue
            try:
                wf = json.loads(raw)
            except json.JSONDecodeError:
                unreadable.append(p)
                continue
            if not isinstance(wf, dict) or not wf:
                unreadable.append(p)
                continue
            try:
                mtime = p.stat().st_mtime
            except OSError:
                mtime = 0.0
            recipes.append(
                RecipeEvidence(workflow=wf, mtime=mtime, source_path=None, origin="output_image")
            )
    recipes.sort(key=lambda r: r.mtime, reverse=True)
    return ComfyUIEvidence(recipes=recipes, unreadable=unreadable)


def scan_saved_workflows(comfyui_dir: Path) -> list[RecipeEvidence]:
    """Workflow files the user (or ComfyUI) saved under ``user/*/workflows/``.

    These are not evidence of a successful run — a saved-but-never-executed
    workflow is exactly the "debugging, not there yet" case this format must
    not lose. They are read so their bytes can be preserved byte-for-byte
    alongside whatever *is* verified, not to decide verified/not.
    """
    found: list[RecipeEvidence] = []
    base = comfyui_dir / "user"
    if not base.is_dir():
        return found
    for p in sorted(base.glob("*/workflows/**/*.json")):
        if not p.is_file():
            continue
        try:
            wf = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(wf, dict) or not wf:
            continue
        try:
            mtime = p.stat().st_mtime
        except OSError:
            mtime = 0.0
        found.append(RecipeEvidence(workflow=wf, mtime=mtime, source_path=p, origin="saved_workflow"))
    found.sort(key=lambda r: r.mtime, reverse=True)
    return found


#: Training-side output artefacts that only appear once a run actually
#: progressed. Mirrors the never-pack list in training.py — read-only here.
_ADAPTER_ARTIFACT_SUFFIXES = (".safetensors", ".ckpt", ".pt", ".bin")


@dataclass
class TrainingEvidence:
    verified: bool
    steps: int | None = None
    artifact: Path | None = None
    note: str = ""


def training_verified_run(output_dir: Path) -> TrainingEvidence:
    """Has training in ``output_dir`` actually progressed past zero steps?

    Two facts, both required, matching what the constitution's kohya lesson
    demands: an adapter/checkpoint file was written, **and**
    ``trainer_state.json`` (when present) reports more than zero steps — an
    exit code of 0 alone does not mean training happened (kohya prints an
    error and still exits 0 when it cannot find its data).
    """
    if not output_dir.is_dir():
        return TrainingEvidence(verified=False, note="no such output directory")
    artifact = next(
        (p for p in sorted(output_dir.rglob("*"))
         if p.is_file() and p.suffix in _ADAPTER_ARTIFACT_SUFFIXES),
        None,
    )
    if artifact is None:
        return TrainingEvidence(verified=False, note="no adapter/checkpoint file was produced")
    state_path = output_dir / "trainer_state.json"
    if not state_path.is_file():
        state_path = next(iter(output_dir.rglob("trainer_state.json")), None)
    steps = None
    if state_path and state_path.is_file():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            steps = int(state.get("global_step") or 0)
        except (OSError, ValueError, json.JSONDecodeError):
            steps = None
        if steps is not None and steps <= 0:
            return TrainingEvidence(
                verified=False, steps=steps, artifact=artifact,
                note="trainer_state.json reports 0 steps — it started but never trained",
            )
    return TrainingEvidence(verified=True, steps=steps, artifact=artifact)
