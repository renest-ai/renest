"""Static capture: a known-good ComfyUI workflow (API format) + its directory tree
-> a pack-spec draft and a capture report.

Not a second packing mode: pack's only output form stays "whole directory + exclude
list". Capture feeds the ``dry_run`` preview and the unreferenced-large-file advisory.

v1 boundary: registers only what the workflow references, never judges node
compatibility; pure static parse, never needs a running ComfyUI. Inputs of unknown
node classes are reported, not interpreted -- bar a string ending in a weights suffix,
which is looked up under ``models/`` and packed, flagged inferred. **Say "I don't
know", never miss in silence**: a nest that passes sha256 yet cannot draw is worse.

GPL isolation: ComfyUI is read only as a data format; custom-node repos are inspected
via subprocess ``git`` -- never imported, never vendored.
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .integrity import dirty_gap, git_identity, probe_model_bytes, registry_identity
from .syslibs import read_run_record, record_search_roots
from .verified import scan_comfyui_output

__all__ = [
    "api_forwarding_nodes",
    "recorded_node_owners",
    "resolve_image_digest",
    "CAPTURE_VERSION",
    "CATEGORIES",
    "MODEL_REF_MAP",
    "BUILTIN_CLASSES",
    "COMFYUI_CORE_EXCLUDE",
    "LARGE_FILE_BYTES",
    "CaptureResult",
    "capture",
]

CAPTURE_VERSION = f"{__version__}-capture"

#: A "big file worth flagging" default: models are hundreds of MiB; source and
#: config never are. Used only for the "unreferenced large file" advisory hint.
LARGE_FILE_BYTES = 128 << 20

# ------------------------------------------------------------ lookup tables --
# Node class -> which of its inputs are file references, and which category each
# belongs to. Explicit, never heuristic: a string input not in the table is never
# guessed at (unknown classes' inputs go to the "unrecognized references" list).
# Category -> (search directories relative to the ComfyUI root; manifest files[].kind).
# The first directory is where ComfyUI puts that kind of file today; the rest are
# historical aliases (unet was renamed to diffusion_models).

#: Registry address for image lookups -- a fact about the outside world, so the
#: source of truth is the world-rules file (`image_registry`); these are only the
#: fallback values shipped with the package.
_REGISTRY_FALLBACK = {
    "token_url": "https://auth.docker.io/token",
    "manifest_url": "https://registry-1.docker.io/v2/{repo}/manifests/{tag}",
    "service": "registry.docker.io",
}


def _world_registry() -> dict:
    try:
        from .rules import WORLD_RULES, load_rules

        got = load_rules(WORLD_RULES).get("image_registry") or {}
        return {**_REGISTRY_FALLBACK, **{k: v for k, v in got.items() if isinstance(v, str)}}
    # The rules file is a side channel: it must never block the real work.
    except Exception:  # noqa: BLE001
        return _REGISTRY_FALLBACK


def _world_vocab() -> tuple[dict, dict] | None:
    """The two ComfyUI vocabulary tables from the world-rules file.

    Returns ``None`` when they cannot be read; the caller then uses the tables shipped
    with the package. They live in the rules file because a stale entry after an
    upstream rename **raises no error** -- it just quietly stops collecting one model.

    **They only change what we can recognize, never what we are willing to collect**:
    the "only what this workflow referenced" boundary lives in the code, so editing
    these tables remotely cannot widen the collection scope.
    """
    try:
        from .rules import WORLD_RULES, load_rules

        v = load_rules(WORLD_RULES).get("comfyui_vocab") or {}
        cats = {k: (tuple(x["dirs"]), x["kind"]) for k, x in (v.get("categories") or {}).items()}
        refs = {k: [(i["input"], i["category"]) for i in v]
                for k, v in (v.get("model_ref_map") or {}).items()}
        return (cats, refs) if cats and refs else None
    except Exception:  # noqa: BLE001
        return None


_FACTORY_CATEGORIES: dict[str, tuple[tuple[str, ...], str]] = {
    "checkpoint":      (("models/checkpoints",), "checkpoint"),
    "config":          (("models/configs",), "other"),
    "diffusion_model": (("models/diffusion_models", "models/unet"), "checkpoint"),
    "vae":             (("models/vae",), "vae"),
    "lora":            (("models/loras",), "lora"),
    "text_encoder":    (("models/text_encoders", "models/clip"), "clip"),
    "clip_vision":     (("models/clip_vision",), "clip"),
    "controlnet":      (("models/controlnet",), "controlnet"),
    "upscale_model":   (("models/upscale_models",), "upscaler"),
    "style_model":     (("models/style_models",), "other"),
    "embedding":       (("models/embeddings",), "embedding"),
    "input_asset":     (("input",), "input_asset"),
    # Read off the extension's own source, 2026-08-20: it registers this folder itself
    # (`os.path.join(folder_paths.models_dir, "ipadapter")`), so the weights live outside
    # every folder above and a workflow using them packed nothing at all.
    "ipadapter":       (("models/ipadapter",), "ipadapter"),
    # Added after measuring again, 2026-08-14: manifest.schema.json 2.7 opened
    # files[].kind into a free string (see the schema's own field description),
    # so a new asset family no longer needs a format version bump -- only a
    # new row here.
    "audio_encoder":             (("models/audio_encoders",), "audio_encoder"),
    "frame_interpolation_model": (("models/frame_interpolation",), "frame_interpolation_model"),
    "gligen":                    (("models/gligen",), "gligen"),
    "hypernetwork":              (("models/hypernetworks",), "hypernetwork"),
    "latent_upscale_model":      (("models/latent_upscale_models",), "latent_upscale_model"),
    "geometry_estimation_model": (("models/geometry_estimation",), "geometry_estimation_model"),
    "detection_model":           (("models/detection",), "detection_model"),
    "model_patch":               (("models/model_patches",), "model_patch"),
    "optical_flow_model":        (("models/optical_flow",), "optical_flow_model"),
    "photomaker_model":          (("models/photomaker",), "photomaker_model"),
}

_FACTORY_MODEL_REF_MAP: dict[str, list[tuple[str, str]]] = {
    # class_type -> [(input name, category)]
    "CheckpointLoaderSimple": [("ckpt_name", "checkpoint")],
    "CheckpointLoader":       [("config_name", "config"), ("ckpt_name", "checkpoint")],
    "UNETLoader":             [("unet_name", "diffusion_model")],
    "VAELoader":              [("vae_name", "vae")],
    "LoraLoader":             [("lora_name", "lora")],
    "LoraLoaderModelOnly":    [("lora_name", "lora")],
    "CLIPLoader":             [("clip_name", "text_encoder")],
    "DualCLIPLoader":         [("clip_name1", "text_encoder"), ("clip_name2", "text_encoder")],
    "CLIPVisionLoader":       [("clip_name", "clip_vision")],
    "ControlNetLoader":       [("control_net_name", "controlnet")],
    "DiffControlNetLoader":   [("control_net_name", "controlnet")],
    "UpscaleModelLoader":     [("model_name", "upscale_model")],
    "StyleModelLoader":       [("style_model_name", "style_model")],
    # The one loader in that extension that names a file. Its two siblings cannot be
    # mapped and are left out on purpose: `IPAdapterUnifiedLoader` takes a preset
    # string ("PLUS (high strength)") and resolves it to a file at run time, and
    # `IPAdapterInsightFaceLoader` takes a name from a fixed list in another folder.
    # A workflow built on either still packs nothing -- naming them here with a made-up
    # input would be worse than the gap, because it would look answered.
    "IPAdapterModelLoader":   [("ipadapter_file", "ipadapter")],
    # Added after measuring, 2026-08-13: across 475 official workflow templates (101 of
    # which load a model), 31 load points named a class missing from this table -- and
    # every one of them was an official loader, not a third-party node. The table had
    # fallen behind upstream. These two fit existing categories and cover 25 of the 31.
    "QuadrupleCLIPLoader":    [("clip_name1", "text_encoder"), ("clip_name2", "text_encoder"),
                               ("clip_name3", "text_encoder"), ("clip_name4", "text_encoder")],
    "ImageOnlyCheckpointLoader": [("ckpt_name", "checkpoint")],
    "LoadImage":              [("image", "input_asset")],
    "LoadImageMask":          [("image", "input_asset")],
    # Video and audio, added 2026-08-22. Field names read off a running ComfyUI's
    # /object_info, not guessed. The VHS_*Path variants are deliberately absent:
    # they carry an absolute path, not a name under input/, and that has its own
    # path already. Across 14 real user workflows the video loaders appear 12 times.
    "LoadVideo":              [("file", "input_asset")],
    "LoadAudio":              [("audio", "input_asset")],
    "VHS_LoadVideo":          [("video", "input_asset")],
    # Added after measuring again, 2026-08-14: upstream had grown to 35 loader
    # classes against our 17. These ten fit categories already in the table above.
    "CreateHookLora":         [("lora_name", "lora")],
    "CreateHookLoraModelOnly": [("lora_name", "lora")],
    "CreateHookModelAsLora":  [("ckpt_name", "checkpoint")],
    "CreateHookModelAsLoraModelOnly": [("ckpt_name", "checkpoint")],
    "LTXAVTextEncoderLoader": [("text_encoder", "text_encoder"), ("ckpt_name", "checkpoint")],
    "LTXVAudioVAELoader":     [("ckpt_name", "checkpoint")],
    "LoraLoaderBypass":       [("lora_name", "lora")],
    "LoraLoaderBypassModelOnly": [("lora_name", "lora")],
    "TripleCLIPLoader":       [("clip_name1", "text_encoder"), ("clip_name2", "text_encoder"),
                                ("clip_name3", "text_encoder")],
    "unCLIPCheckpointLoader": [("ckpt_name", "checkpoint")],
    # These eleven needed a new category first (see _FACTORY_CATEGORIES above).
    "AudioEncoderLoader":     [("audio_encoder_name", "audio_encoder")],
    "FrameInterpolationModelLoader": [("model_name", "frame_interpolation_model")],
    "GLIGENLoader":           [("gligen_name", "gligen")],
    "HypernetworkLoader":     [("hypernetwork_name", "hypernetwork")],
    "LatentUpscaleModelLoader": [("model_name", "latent_upscale_model")],
    "LoadDA3Model":           [("model_name", "geometry_estimation_model")],
    "LoadMediaPipeFaceLandmarker": [("model_name", "detection_model")],
    "LoadMoGeModel":          [("model_name", "geometry_estimation_model")],
    "ModelPatchLoader":       [("name", "model_patch")],
    "OpticalFlowLoader":      [("model_name", "optical_flow_model")],
    "PhotoMakerLoader":       [("photomaker_model_name", "photomaker_model")],
}

#: The tables actually in force: **use the rules file when it has them, and the
#: ones shipped with the package otherwise** (see _world_vocab).
_vocab = _world_vocab()


def _merge_vocab(factory: dict, world: dict | None) -> dict:
    """Rules may ADD or OVERRIDE an entry; they can never REMOVE one.

    It used to be a wholesale swap, which meant the first published table silently
    became the whole world: anything the shipped table knew and the published one did
    not was simply no longer recognized -- and an unrecognized loader does not raise,
    it just stops collecting that model. Merging makes the shipped table a floor, so a
    rules file can only ever widen what we recognize. Removing a loader would need a
    release, which is the right amount of friction for the one direction that loses
    data.
    """
    out = dict(factory)
    out.update(world or {})
    return out


CATEGORIES = _merge_vocab(_FACTORY_CATEGORIES, _vocab[0] if _vocab else None)
MODEL_REF_MAP = _merge_vocab(_FACTORY_MODEL_REF_MAP, _vocab[1] if _vocab else None)

# Hand-maintained set of built-in node classes. Anything not listed is treated as a
# candidate custom node, and if nothing under custom_nodes/ defines it either we say so
# plainly instead of swallowing it. Erring short is deliberate: a missing built-in costs
# one report line for a human to check, a wrong entry could hide a real dependency.

#: Loaders in MODEL_REF_MAP that upstream does not ship. Recognising their model is
#: right; calling them built-in is not -- that stops us looking for the pack that
#: defines them, and the nest then misses a code dependency without saying a word.
THIRD_PARTY_LOADERS: frozenset[str] = frozenset({
    "IPAdapterModelLoader",
    # Ships in ComfyUI-VideoHelperSuite, not upstream. Added to the loader table
    # 2026-08-22 without landing here, so a workflow whose only VHS node was this
    # one recorded no dependency on that pack and said nothing about it.
    "VHS_LoadVideo",
})

BUILTIN_CLASSES: frozenset[str] = frozenset({
    *(set(MODEL_REF_MAP) - THIRD_PARTY_LOADERS),
    # sampling / guidance
    "KSampler", "KSamplerAdvanced", "SamplerCustom", "BasicScheduler",
    # text / conditioning
    "CLIPTextEncode", "CLIPSetLastLayer", "CLIPVisionEncode",
    "ConditioningCombine", "ConditioningConcat", "ConditioningSetArea",
    "ControlNetApply", "ControlNetApplyAdvanced", "StyleModelApply",
    # latent / image
    "EmptyLatentImage", "EmptySD3LatentImage", "LatentUpscale", "LatentUpscaleBy",
    "VAEDecode", "VAEEncode", "ImageScale", "ImageScaleBy", "ImageUpscaleWithModel",
    "ImageInvert", "ImagePadForOutpaint",
    # output
    "SaveImage", "PreviewImage", "SaveAnimatedWEBP", "SaveAnimatedPNG", "SaveLatent",
    # video
    "WanImageToVideo",
})

COMFYUI_CORE_EXCLUDE = ["models", "output", "temp", "input", "user"]

#: Folder names packing never puts in an archive. A copy of ``pack.ARCHIVE_JUNK``
#: (importing it here would be a cycle -- pack imports this module); the two are
#: pinned together by ``test_two_trees.test_never_archived_mirrors_pack``. Read
#: here so the second-tree check below does not count a folder that would leave
#: the archive empty anyway.
_NEVER_ARCHIVED = frozenset({".git", "__pycache__", ".venv", "venv", "node_modules", ".renest"})


def _data_tree_leftovers(comfyui_dir: Path, exclude: Iterable[str]) -> list[str]:
    """Two-tree layout: what in the data tree nothing else in the spec carries.

    Once ``host`` reads from the program tree, the data tree is covered by the
    node folders (an entry each) and the models (``files[]`` each) -- and by
    nothing else. Whatever is left over (``extra_model_paths.yaml``, node folders
    this workflow never named) needs an entry of its own or it silently stops
    travelling. Returns the top-level names that are left, so the caller can skip
    emitting an entry whose archive would come out empty: an empty archive makes
    a rebuild stop and blame a symlink that does not exist.
    """
    ex = {str(e).strip("/") for e in exclude}

    def carried(rel: str) -> bool:
        return any(rel == e or rel.startswith(e + "/") for e in ex)

    left: list[str] = []
    try:
        top = sorted(comfyui_dir.iterdir())
    except OSError:
        return []
    for p in top:
        if p.name in _NEVER_ARCHIVED or p.name.endswith(".pyc") or carried(p.name):
            continue
        # `custom_nodes/` is the partly-carried case: some packs inside it have an
        # entry of their own, the rest do not. Name the ones that do not, so the
        # report says what actually travels here rather than "custom_nodes".
        if p.is_dir() and any(e.startswith(p.name + "/") for e in ex):
            try:
                kids = sorted(p.iterdir())
            except OSError:
                continue
            left += [f"{p.name}/{k.name}" for k in kids
                     if k.name not in _NEVER_ARCHIVED and not carried(f"{p.name}/{k.name}")]
            continue
        left.append(p.name)
    return left


def _sha256_file(path: Path, cache: Any = None) -> tuple[str, int]:
    # Same read window as pack: a file written while we hash it (ComfyUI still
    # running, a download unfinished) yields a fingerprint that is void the moment
    # we write it down, and the bill lands days later on the restore side as a byte
    # check that reads like a broken transfer. Fail loudly here instead.
    before = path.stat()
    if cache is not None:
        # The record pack keeps of what it has already hashed, handed in so one
        # weight is read once per pack and not once here and again there. An
        # unchanged size, time and inode also means nothing is writing to it, so
        # the guard below loses nothing.
        known = cache.lookup(path, before)
        if known is not None:
            return known, before.st_size
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 22):
            h.update(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError(
            f"This file changed while we were reading it: {path} "
            f"(size {before.st_size} → {after.st_size} bytes). Something is still "
            "writing to it — most likely ComfyUI itself, or a download that hasn't "
            "finished. Stop the application and pack again."
        )
    digest = h.hexdigest()
    if cache is not None:
        cache.remember(path, after, digest)
    return digest, after.st_size


# ----------------------------------------------------------------- parsing --

def _normalize_workflow(raw: dict) -> dict[str, dict]:
    """Pull the node table out of an API-format workflow.

    The UI export format (``{"nodes": [...]}``) is rejected outright rather
    than converted by guesswork.
    """
    if isinstance(raw.get("nodes"), list):
        raise ValueError("This workflow is the UI export format. Use the API format — "
                         "in ComfyUI that's Export (API).")
    body = raw.get("prompt") if isinstance(raw.get("prompt"), dict) else raw
    nodes = {}
    for node_id, node in body.items():
        if node_id.startswith("_"):
            continue  # comment fields such as _comment
        if isinstance(node, dict) and isinstance(node.get("class_type"), str):
            nodes[node_id] = node
    if not nodes:
        raise ValueError("No nodes with a class_type in this workflow — is it really the "
                         "API format?")
    return nodes


#: File endings that name model weights. Open on purpose: a new quantisation format
#: ships every few months, and the cost of one extra ending is a lookup that finds
#: nothing, while the cost of a missing one is a nest that cannot draw.
_WEIGHT_SUFFIXES = (".safetensors", ".sft", ".ckpt", ".pt", ".pth", ".bin", ".gguf", ".onnx")


def _names_weights(value: str) -> bool:
    return value.lower().endswith(_WEIGHT_SUFFIXES) and ".." not in value


def _clean_asset_name(value: str) -> str:
    """Strip the annotation suffix LoadImage adds ('photo.png [input]') so the
    real file name is left."""
    if value.endswith("]") and " [" in value:
        return value.rsplit(" [", 1)[0]
    return value


def _expand_path_vars(value: str) -> str:
    """``~/shared`` and ``$MODELS/loras`` the way ComfyUI expands them when it reads
    the same file.

    Without this a ``~`` is treated as a folder name, so the path becomes
    ``ComfyUI/~/shared``, which cannot exist -- the models kept out there are then
    reported missing and never travel.
    """
    return os.path.expandvars(os.path.expanduser(value)) if value else value


def _parse_extra_model_paths(comfyui_dir: Path) -> dict[str, list[Path]]:
    """Parse ComfyUI/extra_model_paths.yaml -> {category key: [existing
    absolute directories]}.

    The category key is ComfyUI's own folder name (checkpoints, loras, vae,
    unet, ...), which is exactly the basename of the search_dir entries in
    CATEGORIES. Needs pyyaml; without it we return {} and the caller warns.
    """
    p = next((comfyui_dir / fn for fn in ("extra_model_paths.yaml", "extra_model_paths.yml")
              if (comfyui_dir / fn).is_file()), None)
    if p is None:
        return {}
    try:
        # A ComfyUI environment always ships pyyaml; if it is missing we fall
        # back to the "found the file but could not follow it" warning.
        import yaml
    except ImportError:
        return {}
    try:
        data = yaml.safe_load(p.read_text()) or {}
    except Exception:
        return {}
    out: dict[str, list[Path]] = {}
    for cfg in (data.values() if isinstance(data, dict) else []):
        if not isinstance(cfg, dict):
            continue
        base = _expand_path_vars(str(cfg.get("base_path", "") or ""))
        base_p = Path(base) if Path(base).is_absolute() else (comfyui_dir / base).resolve() if base else None
        for key, val in cfg.items():
            if key in ("base_path", "is_default") or not isinstance(val, str):
                continue
            for line in val.splitlines():        # one line, or a | block list
                sub = _expand_path_vars(line.strip())
                if not sub:
                    continue
                d = Path(sub) if Path(sub).is_absolute() else (base_p / sub if base_p else comfyui_dir / sub)
                if d.is_dir():
                    out.setdefault(key, []).append(d.resolve())
    return out


def _locate(comfyui_dir: Path, relname: str, search_dirs: tuple[str, ...],
            extra_dirs: tuple[Path, ...] = ()) -> tuple[Path | None, str]:
    """Look in the expected directories, then the extra_model_paths ones, then fall
    back to a whole-tree search by file name.

    Returns (absolute path or None, note). A reference containing ``..`` is refused
    outright -- that is a path escape. A hit in an external directory is normalized by
    the caller back onto the standard directory: follow the file wherever it lives,
    but always record it in the standard place.
    """
    rel = Path(relname.replace("\\", "/"))
    if ".." in rel.parts or rel.is_absolute():
        return None, "This reference points outside the folder (.. or an absolute path); we won't follow it"
    for sub in search_dirs:
        cand = comfyui_dir / sub / rel
        if cand.is_file():
            return cand, ""
    # External directories declared in extra_model_paths: exact match, and
    # like ComfyUI itself we take the first hit.
    for ed in extra_dirs:
        cand = ed / rel
        if cand.is_file():
            return cand, f"Found in the extra_model_paths folder {ed} — recorded under the standard models folder"
    # Last resort: search the whole tree for a file of that name, but only
    # under the top level of the first search directory (models/ or input/).
    scan_root = comfyui_dir / Path(search_dirs[0]).parts[0]
    if scan_root.is_dir():
        hits = sorted(p for p in scan_root.rglob(rel.name) if p.is_file()
                      and p.as_posix().endswith(rel.as_posix()))
        if hits:
            note = f"Not in the expected folder {list(search_dirs)}; found in {hits[0].parent}"
            if len(hits) > 1:
                note += f" ({len(hits)} files carry this name; we took the first, please check the rest)"
            return hits[0], note
    return None, ""


#: A textual inversion is named inside the prompt text, not by any loader input:
#: ``embedding:badhands``, normally with the file suffix left off. No node class
#: mentions it, so the loader table above can never see one.
_EMBEDDING_REF = re.compile(r"(?<!\w)embedding:([\w\-./\\]+)")


def _locate_embedding(comfyui_dir: Path, name: str) -> Path | None:
    """The file behind ``embedding:<name>``, trying each weights suffix in turn."""
    rel = Path(name.replace("\\", "/").rstrip("."))
    if ".." in rel.parts or rel.is_absolute() or not rel.name:
        return None
    base = comfyui_dir / "models" / "embeddings"
    cands = [base / rel, *(base / f"{rel.as_posix()}{s}" for s in _WEIGHT_SUFFIXES)]
    return next((c for c in cands if c.is_file()), None)


def _looks_like_comfyui_source(d: Path) -> bool:
    """Does this directory actually hold the ComfyUI **program itself**?

    Tests for the two things the program always has and a data directory never has:
    ``main.py`` and ``comfy/``. It lets the call site split "can't read git here" into
    two very different cases: the program is not here at all, versus it is here but
    has no git history.
    """
    return (d / "main.py").is_file() or (d / "comfy").is_dir()


def _scan_custom_node_dirs(comfyui_dir: Path) -> list[Path]:
    cn = comfyui_dir / "custom_nodes"
    if not cn.is_dir():
        return []
    return sorted(d for d in cn.iterdir()
                  if d.is_dir() and not d.name.startswith((".", "__")))


def _scan_custom_node_files(comfyui_dir: Path) -> list[Path]:
    """Loose ``.py`` files sitting directly in custom_nodes/.

    ComfyUI loads those as nodes just like a folder, so a class defined in one is
    installed here -- reporting it as "no folder defines it, add that folder by
    hand" sends the reader looking for a folder that does not exist.
    """
    cn = comfyui_dir / "custom_nodes"
    if not cn.is_dir():
        return []
    return sorted(p for p in cn.iterdir()
                  if p.is_file() and p.suffix == ".py" and not p.name.startswith((".", "__")))


def _file_defines_class(py: Path, cls: str) -> bool:
    """Does this source file mention that node class name (a quoted occurrence first,
    otherwise a word-boundary match)?

    Text is only ever read, never imported — that is the GPL isolation rule.
    """
    try:
        if py.stat().st_size > (2 << 20):
            return False
        text = py.read_text(errors="ignore")
    except OSError:
        return False
    return any(q in text for q in (f'"{cls}"', f"'{cls}'")) or bool(
        re.search(rf"\b{re.escape(cls)}\b", text)
    )


def _dir_defines_class(node_dir: Path, cls: str) -> bool:
    """Static match against every .py source in this directory."""
    return any(_file_defines_class(py, cls) for py in node_dir.rglob("*.py"))


#: A node name put together when the pack starts: the source says
#: ``NAME = get_name('Image Inset Crop')`` and the suffix is appended at registration,
#: so ``Image Inset Crop (rgthree)`` is in no file and matching the full name never
#: hits -- the nest then records no dependency on that folder at all.
_NAME_WITH_SUFFIX = re.compile(r"^(?P<base>.+?)\s*\((?P<tag>[^()]+)\)$")


def _dirs_defining_a_suffixed_class(node_dirs: list[Path], cls: str) -> list[Path]:
    """Locate ``Base (tag)`` by its base name, in folders whose own name carries the tag.

    Both halves are read off the disk, so this stays a static parse and stays a
    sighting rather than a guess.

    **The folder condition is the whole defence, not a belt-and-braces.** Measured
    across twelve node packs installed side by side, 5 of 24 suffixed names collide on
    their base name alone: ``Context`` and ``Seed`` each appear in six different packs,
    ``Image Resize`` in three. On the base name alone those five pick the wrong pack;
    with the folder condition all five come out unique and right. Naming the wrong pack
    is worse than naming none -- an unmatched node prints a line the user can act on, a
    wrong one says nothing. A fixture with two or three packs will not show you this.
    """
    m = _NAME_WITH_SUFFIX.match(cls)
    if not m:
        return []
    base, tag = m.group("base").strip(), m.group("tag").strip().lower()
    if not base or not tag:
        return []
    return [d for d in node_dirs if tag in d.name.lower() and _dir_defines_class(d, base)]


#: "The record has nothing to say about this node type" -- told apart from "the record
#: says it is one of ComfyUI's own", which is ``None`` and is an answer.
NOT_RECORDED = object()


def recorded_node_owners(comfyui_dir: Path, node_dirs: list[Path],
                         program_dir: Path | None = None) -> dict[str, Any]:
    """Which pack each node type came from, as the run that worked reported it.

    The panel writes this from inside the running app, so it names the folder ComfyUI
    really loaded the class from. Searching folders for the class name as text cannot
    do that: a pack that assembles its node names at start-up spells the name in no
    file, and two packs using the same name are indistinguishable from outside.

    It writes beside ComfyUI's own source, so on a two-tree install the record is in
    ``program_dir`` and not under the data folder at all -- looking only there reads
    exactly like "the run said nothing about this node".

    **Only what this machine can still show is kept.** A record that travelled here
    from another machine names folders that are not on this disk, so a name that
    cannot be pointed at a folder here is dropped rather than believed. ``None`` as
    the value means the record says it is one of ComfyUI's own nodes.
    """
    owners = None
    for root in record_search_roots(program_dir or comfyui_dir, [comfyui_dir]):
        cand = (read_run_record(root) or {}).get("node_owners")
        if isinstance(cand, dict):
            owners = cand
            break
    if not isinstance(owners, dict):
        return {}
    here = {d.name for d in node_dirs}
    out: dict[str, Any] = {}
    for cls, info in owners.items():
        if not isinstance(cls, str) or not isinstance(info, dict):
            continue
        name = info.get("dir")
        if isinstance(name, str) and name in here:
            out[cls] = name
        elif not name and info.get("builtin") is True:
            out[cls] = None
    return out


def _record_dir_identity(hits: list[Path], cls: str, matched_dirs: dict[str, dict],
                         dirs_without_git: list[str], gaps: list[str]) -> None:
    """Establish where each matched folder came from, and say so when we cannot.

    One copy on purpose: both routes into it -- the run record and the text search --
    have to answer this the same way, and two copies drift.
    """
    for d in hits:
        if d.name in matched_dirs or d.name in dirs_without_git:
            continue
        # Two ways to establish identity, git first: a commit pins the version too.
        # Without git, fall back to the node's own pyproject.toml -- that is how
        # registry-installed nodes look, and in real environments it is the common
        # case, not the exception.
        ident = git_identity(d)
        if ident is None:
            ident = registry_identity(d)
            if ident is not None:
                gaps.append(
                    f"custom_nodes/{d.name} has no .git (nodes installed from the ComfyUI "
                    f"Registry usually don't). We took its origin from its own "
                    f"pyproject.toml instead: {ident['repo_url']} — no commit to pin, so "
                    f"the nest carries its files byte-for-byte rather than a revision to "
                    f"fetch again"
                )
        if ident is None:
            dirs_without_git.append(d.name)
            # The files of such a node still travel inside the ComfyUI archive and
            # come back on restore; what is lost is its **identity**, so it cannot
            # be listed, updated on its own, or swapped out later. Word it that way:
            # the older "stays out of code_deps" wording read as "not in the nest at
            # all" and pushed users into reinstalling by hand for nothing.
            gaps.append(f"custom_nodes/{d.name} defines node type {cls}, but it has neither "
                        f"a readable git remote/HEAD nor a pyproject.toml saying where it "
                        f"came from. Its files still travel inside the ComfyUI archive and "
                        f"come back byte-for-byte — what's missing is its identity: we "
                        f"can't say which version it is or where it came from, so it can't "
                        f"be listed or updated on its own")
        else:
            matched_dirs[d.name] = ident
            # Hand-edited node code is not in the commit, so a rebuild that
            # clones a clean copy would make those edits vanish silently.
            dg = dirty_gap(f"custom_nodes/{d.name}", d)
            if dg:
                gaps.append(dg)


#: Where the host app keeps the nodes that hand work to an outside service.
_API_NODE_PKG = "comfy_api_nodes"

#: Same three shapes as the parse below, for a file too new for this Python to parse.
#: Anchored the same way, so prose still cannot match: a ``class`` in column zero,
#: a ``node_id=`` argument, a quoted key inside the mapping block.
_FALLBACK_CLASS = re.compile(r"^class[ \t]+([A-Za-z_]\w*)", re.M)
_FALLBACK_NODE_ID = re.compile(r"""node_id[ \t]*=[ \t]*["']([^"'\n]+)["']""")
_FALLBACK_MAP_KEY = re.compile(r"""["']([^"'\n]+)["'][ \t]*:""")
_MAPPING_NAME = "NODE_CLASS_MAPPINGS"


def _fallback_node_names(text: str, *, package_root: bool) -> set[str]:
    """Structural shapes read off unparseable source, by anchored pattern."""
    names = set(_FALLBACK_NODE_ID.findall(text))
    if package_root:
        names.update(_FALLBACK_CLASS.findall(text))
    start = text.find(_MAPPING_NAME)
    if start != -1:
        opened = text.find("{", start)
        closed = text.find("}", opened) if opened != -1 else -1
        if opened != -1 and closed != -1:
            names.update(_FALLBACK_MAP_KEY.findall(text[opened:closed]))
    return names


def _api_node_names(py: Path, *, package_root: bool) -> set[str]:
    """The node names this file puts on offer, read from its structure, not its text.

    Three shapes, every one of them a place a name can only be *declared*: the keys of
    ``NODE_CLASS_MAPPINGS``, a ``node_id=`` argument (the schema API's registered id),
    and -- only for the package's own node modules -- a ``class`` at the top level.

    The last one is a net for a registration form we have not met, and it stops at the
    package's own files on purpose. Measured against ComfyUI v0.34.2: its generated
    request/response models under ``apis/`` add 1042 further class names, two of which
    (``Image``, ``Video``) are ordinary node names that no cloud service is behind.
    """
    try:
        if py.stat().st_size > (2 << 20):
            return set()
        text = py.read_text(errors="ignore")
    except OSError:
        return set()
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return _fallback_node_names(text, package_root=package_root)
    names: set[str] = set()
    if package_root:
        names.update(n.name for n in tree.body if isinstance(n, ast.ClassDef))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict) and any(
                isinstance(t, ast.Name) and t.id == _MAPPING_NAME for t in node.targets):
            names.update(k.value for k in node.value.keys
                         if isinstance(k, ast.Constant) and isinstance(k.value, str))
        elif isinstance(node, ast.Call):
            names.update(kw.value.value for kw in node.keywords
                         if kw.arg == "node_id" and isinstance(kw.value, ast.Constant)
                         and isinstance(kw.value.value, str))
    return names


def api_forwarding_nodes(comfyui_dir: Path, classes: Iterable[str]) -> list[dict]:
    """Which of these nodes hand the work to somebody else's servers.

    **Recognised from the code on this machine, never from a list of names we keep.**
    The host app keeps its service-calling nodes in one package, so a node *declared*
    there is one of them, and the file declaring it names the service. When that
    package is not present, the answer is silence — a guessed entry here would be worse
    than none, because this list is the format's honest boundary: the byte-for-byte
    promise does not cover anything that runs on someone else's servers.

    **Declared, not mentioned.** Asking whether the name occurs in the text put every
    nest through 2026-08 on record as calling out to a cloud service for ``LoadImage``,
    which reads a file off the local disk: three lines of prose in ``nodes_bytedance.py``
    say "1 = transparent, LoadImage convention", and a word match cannot tell a
    tooltip from a declaration.

    **Known limit, stated rather than hidden**: a third-party node that forwards to a
    service is not caught by this — it lives in its own folder like any other."""
    pkg = Path(comfyui_dir) / _API_NODE_PKG
    if not pkg.is_dir():
        return []
    declared: dict[str, Path] = {}
    for py in sorted(pkg.rglob("*.py")):
        for name in _api_node_names(py, package_root=py.parent == pkg):
            declared.setdefault(name, py)
    out: list[dict] = []
    for cls in sorted(set(classes)):
        hit = declared.get(cls)
        if hit is None:
            continue
        stem = hit.stem.removeprefix("nodes_")
        out.append({
            "node_name": cls,
            "service": stem if stem and stem != "nodes" else hit.parent.name,
            "note": "Recognised because the app declares this node in its own "
                    "service-calling package; what it sends is not archived.",
        })
    return out


def resolve_image_digest(ref: str, *, timeout: float = 30.0) -> str | None:
    """Ask a container registry for an image's digest, given the image name.

    Returns None when it cannot be obtained -- **it never invents one**.

    Why it exists: a container cannot see its own image name, so ``base_image.ref`` has
    to come from the cloud provider's API or from the user. The **digest** is not like
    that -- once the name is known the registry can be asked -- so a placeholder there
    is never justified: the schema requires ``sha256:`` plus 64 hex characters, which a
    "fill this in" placeholder can never match, so such a nest fails our own verifier.

    Only Docker Hub is supported; any other registry returns None so the caller asks
    the user rather than guessing.

    **What comes back is always the index digest**, never the per-architecture one:
    the request asks for the index media types and nothing else. Callers must record
    that as ``digest_kind: "index"`` rather than leave a reader to guess which layer
    they are looking at -- the schema treats the two as different things.
    """
    import httpx

    ref = (ref or "").strip()
    if not ref or ref.startswith("<") or "@sha256:" in ref:
        return None
    repo, _, tag = ref.partition(":")
    tag = tag or "latest"
    if "/" not in repo:
        repo = f"library/{repo}"
    if repo.count("/") > 1:            # private or third-party registry: no guessing
        return None
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as c:
            reg = _world_registry()
            tok = c.get(reg["token_url"],
                        params={"service": reg["service"],
                                "scope": f"repository:{repo}:pull"})
            if tok.status_code != 200:
                return None
            r = c.head(
                reg["manifest_url"].format(repo=repo, tag=tag),
                headers={
                    "Authorization": f"Bearer {tok.json().get('token', '')}",
                    "Accept": "application/vnd.docker.distribution.manifest.list.v2+json,"
                              "application/vnd.oci.image.index.v1+json",
                })
    except (httpx.HTTPError, ValueError):
        return None
    dig = r.headers.get("docker-content-digest", "")
    return dig if dig.startswith("sha256:") and len(dig) == 71 else None


def _scan_unreferenced_large_files(
    comfyui_dir: Path, prefix: str, referenced: set[str], threshold: int
) -> list[dict]:
    """Which files under models/ of at least ``threshold`` bytes are not
    referenced by this workflow.

    This only informs; it never blocks packing, because "the whole directory
    plus an exclude list" stays the one and only output form.
    """
    models = comfyui_dir / "models"
    if not models.is_dir():
        return []
    out: list[dict] = []
    for p in sorted(models.rglob("*")):
        if not p.is_file():
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size < threshold:
            continue
        rel = f"{prefix}/{p.relative_to(comfyui_dir).as_posix()}"
        if rel not in referenced:
            out.append({"path": rel, "size_bytes": size})
    return out


# ------------------------------------------------------------- main flow ----

@dataclass
class CaptureResult:
    pack_spec: dict
    report: dict



def _comfyui_adapter(comfyui_dir: Path, workflow_relpath: str | None) -> dict:
    """The comfyui adapter section, **including whether this environment ever
    produced a picture** (``verified_run``).

    Why it has to be written here and not only in ``pack``'s own flow: a pack-spec
    built by this function is a **supported user path** (``renest pack --spec``), and
    on that path nothing else ever looks at the output folder -- ``pack`` merely copies
    ``verified_run`` through if the incoming spec already carries it. So every nest
    packed from a captured spec claimed "nothing here is confirmed to have worked yet",
    even when the environment had been producing pictures all along; restoring such a
    nest then skips the one check worth most (does the recipe still run?), forever.
    Found 2026-08-20 while diagnosing a 22.73 GB nest that had exactly this hole.
    """
    adapter: dict = {"workflow_path": workflow_relpath}
    with contextlib.suppress(Exception):
        evidence = scan_comfyui_output(comfyui_dir / "output")
        if evidence.verified and evidence.most_recent is not None:
            adapter["verified_run"] = {
                "queue_completed_at": _iso_utc_mtime(evidence.most_recent.mtime)
            }
    return adapter


def _iso_utc_mtime(mtime: float) -> str:
    return datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def capture(workflow: dict, comfyui_dir: Path,
            workflow_relpath: str | None = None,
            large_file_bytes: int | None = None,
            hash_cache: Any = None,
            program_dir: Path | None = None) -> CaptureResult:
    """Static capture: a workflow (API-format dict) plus a ComfyUI directory ->
    a pack-spec draft and a report.

    Paths inside the pack-spec are relative to the environment root (the parent
    of ``comfyui_dir``), matching ``pack --root``. When ``large_file_bytes`` is
    omitted the module-level ``LARGE_FILE_BYTES`` is read at call time, which
    keeps it overridable from tests.

    ``hash_cache`` is pack's record of what it has already hashed. Handing it in
    is what stops a first pack reading every weight twice -- once to work out
    what to pack, once to pack it.

    ``program_dir`` is for an installation that keeps ComfyUI's program in a
    different tree from its nodes and models (the ComfyUI desktop build). It
    supplies ComfyUI's identity and files, ``comfyui_dir`` still supplies the
    nodes and models, and the nest is an ordinary single-tree install. Left
    out, everything below behaves exactly as before.
    """
    if large_file_bytes is None:
        large_file_bytes = LARGE_FILE_BYTES
    comfyui_dir = comfyui_dir.resolve()
    if program_dir is not None:
        program_dir = Path(program_dir).resolve()
        if program_dir == comfyui_dir:
            program_dir = None  # one tree after all; say nothing, change nothing
    prefix = comfyui_dir.name           # usually "ComfyUI"
    nodes = _normalize_workflow(workflow)
    gaps: list[str] = []

    # ---- 1. scan the workflow: file references + non-built-in classes ----
    refs: list[dict] = []               # file references, per the lookup table
    unknown_classes: dict[str, list[str]] = {}   # class -> [node_id]
    # String inputs of unknown classes: never guessed at, always reported.
    # Reported verbatim and never interpreted -- do not add "this looks like a
    # server address / it will not follow you". Quoting a value back is
    # bookkeeping; explaining what it means reads as inspecting the user's work,
    # which is not how a moving tool should feel. Deliberate, so keep it.
    unrecognized_inputs: list[dict] = []
    for node_id, node in sorted(nodes.items()):
        cls = node["class_type"]
        inputs = node.get("inputs", {}) if isinstance(node.get("inputs"), dict) else {}
        for input_name, category in MODEL_REF_MAP.get(cls, []):
            value = inputs.get(input_name)
            if isinstance(value, str) and value:
                refs.append({"node_id": node_id, "class_type": cls,
                             "input": input_name, "value": value, "category": category})
        if cls not in BUILTIN_CLASSES:
            unknown_classes.setdefault(cls, []).append(node_id)
            for input_name, value in inputs.items():
                if isinstance(value, str):
                    # A table of node classes can never keep up with upstream, so this
                    # second route needs no table: if the string names a file that is
                    # really sitting in input/, list it as the user's own material.
                    # That is not a guess about an unknown node -- we looked, and it
                    # is there. Anything else stays reported-verbatim as before.
                    if (comfyui_dir / "input" / _clean_asset_name(value)).is_file():
                        refs.append({"node_id": node_id, "class_type": cls,
                                     "input": input_name, "value": value,
                                     "category": "input_asset"})
                        continue
                    unrecognized_inputs.append(
                        {"node_id": node_id, "class_type": cls,
                         "input": input_name, "value": value})

    # ---- 2. locate each file in the directory tree: found -> hash it;
    #         not found -> report it as missing, truthfully (not a crash) ----
    recognized: list[dict] = []
    missing: list[dict] = []
    seen_paths: set[str] = set()
    # Follow extra_model_paths: models living outside are gathered back into
    # the standard directories.
    emp = _parse_extra_model_paths(comfyui_dir)
    for ref in refs:
        search_dirs, kind = CATEGORIES[ref["category"]]
        name = _clean_asset_name(ref["value"]) if ref["category"] == "input_asset" \
            else ref["value"]
        # The external directories this category maps to in extra_model_paths
        # (the yaml key equals the basename of the standard search_dir).
        ext_dirs = tuple(d for sd in search_dirs for d in emp.get(Path(sd).name, []))
        found, note = _locate(comfyui_dir, name, search_dirs, ext_dirs)
        if found is None:
            missing.append({**ref, "searched_dirs": [f"{prefix}/{d}" for d in search_dirs],
                            **({"note": note} if note else {})})
            continue
        try:
            rel_to_root = f"{prefix}/{found.relative_to(comfyui_dir).as_posix()}"
        except ValueError:
            # Hit in an external extra_model_paths directory: normalize it onto
            # the standard directory, which is where ComfyUI looks after a
            # restore anyway.
            rel_to_root = f"{prefix}/{search_dirs[0]}/{found.name}"
        if rel_to_root in seen_paths:
            continue                    # several nodes, one file: register once
        seen_paths.add(rel_to_root)
        sha, size = _sha256_file(found, hash_cache)
        entry = {**ref, "path": rel_to_root, "size_bytes": size,
                 "sha256": sha, "kind": kind}
        if note:
            entry["note"] = note
        # Bad-bytes check: sha256 only proves the bytes did not change, not
        # that the bytes are a complete set of weights in the first place. The
        # probe picks its own work by file extension, so input material (.png
        # and friends) is never wrongly flagged as "too small".
        bad = probe_model_bytes(found, size)
        if bad:
            entry["integrity_warning"] = bad
            gaps.append(f"Doesn't look like a complete file: {bad}")
        recognized.append(entry)

    # ---- 2b. weights named by a node class we don't know ----
    # The v1 boundary stands: we still don't interpret an unknown node. But it was
    # never a licence to lose a file. 2026-08-13, on a real bundle: nunchaku's own
    # loader named a 6.3 GB model in `model_path`, its class wasn't in our table, and
    # the model left the nest without one line of output -- restores clean, then can't
    # draw. So a string ending in a weights suffix gets looked up under models/ and
    # packed, marked inferred; one we can't find is reported. Never dropped in silence.
    dir_kind = {sd: kind for sds, kind in CATEGORIES.values() for sd in sds}
    for u in unrecognized_inputs:
        if not _names_weights(u["value"]):
            continue
        found, note = _locate(comfyui_dir, u["value"], ("models",))
        if found is None:
            # A full path from another machine is refused, and then saying "no such
            # file is under models/" is false: it is usually sitting right there.
            here = None
            if "points outside the folder" in note:
                here, _ = _locate(comfyui_dir, Path(u["value"].replace("\\", "/")).name,
                                  ("models",))
            if here is not None:
                gaps.append(
                    f"{u['class_type']}.{u['input']} names a full path from another machine: "
                    f"{u['value']}. We do not follow paths out of the folder being packed, so "
                    f"this model is **not in the nest** — but the file itself is right here, at "
                    f"{prefix}/{here.relative_to(comfyui_dir).as_posix()}. Point that node at "
                    f"the file by name and pack again")
            else:
                gaps.append(
                    f"{u['class_type']}.{u['input']} = {u['value']} names a model file, but that "
                    f"node type isn't one we know and no such file is under {prefix}/models. "
                    f"Add it to the pack list by hand — without it the nest can't run this recipe")
            continue
        rel_to_root = f"{prefix}/{found.relative_to(comfyui_dir).as_posix()}"
        if rel_to_root in seen_paths:
            continue
        seen_paths.add(rel_to_root)
        parent = found.parent.relative_to(comfyui_dir).as_posix()
        kind = dir_kind.get(parent) or (found.parent.name if parent != "models" else "other")
        sha, size = _sha256_file(found, hash_cache)
        entry = {**u, "category": "inferred", "path": rel_to_root, "size_bytes": size,
                 "sha256": sha, "kind": kind, "inferred": True}
        if note:
            entry["note"] = note
        bad = probe_model_bytes(found, size)
        if bad:
            entry["integrity_warning"] = bad
            gaps.append(f"Doesn't look like a complete file: {bad}")
        recognized.append(entry)
        gaps.append(
            f"{rel_to_root} is packed because {u['class_type']}.{u['input']} names it, but "
            f"that node type isn't one we know — we went by the file name alone. Check it is "
            f"the right file, and that this node needs nothing else")

    # ---- 2c. textual inversions written into the prompt text ----
    # Nothing above can reach these: no loader input names them, so before this
    # they left the nest without one line of output -- the rebuilt recipe reads
    # the word as plain text and draws something else.
    for node_id, node in sorted(nodes.items()):
        _inputs = node.get("inputs", {}) if isinstance(node.get("inputs"), dict) else {}
        for input_name, value in _inputs.items():
            if not isinstance(value, str) or "embedding:" not in value:
                continue
            for name in _EMBEDDING_REF.findall(value):
                found = _locate_embedding(comfyui_dir, name)
                if found is None:
                    gaps.append(
                        f"The text in node {node_id} uses embedding:{name}, but no such file is "
                        f"under {prefix}/models/embeddings. Without it the rebuilt recipe reads "
                        f"that word as ordinary text and draws something else — put the "
                        f"embedding back before you pack")
                    continue
                rel_to_root = f"{prefix}/{found.relative_to(comfyui_dir).as_posix()}"
                if rel_to_root in seen_paths:
                    continue
                seen_paths.add(rel_to_root)
                sha, size = _sha256_file(found, hash_cache)
                entry = {"node_id": node_id, "class_type": node["class_type"],
                         "input": input_name, "value": name, "category": "embedding",
                         "path": rel_to_root, "size_bytes": size, "sha256": sha,
                         "kind": "embedding"}
                bad = probe_model_bytes(found, size)
                if bad:
                    entry["integrity_warning"] = bad
                    gaps.append(f"Doesn't look like a complete file: {bad}")
                recognized.append(entry)

    for m in missing:
        # ComfyUI's picker writes the folder it read from into the value itself
        # ("photo.png [output]"). Finished pictures and scratch files are kept out
        # of a nest deliberately, so "put the file back" is the wrong instruction:
        # nothing is missing, it is simply somewhere we never pack from.
        _raw = str(m["value"])
        _ann = _raw.rsplit(" [", 1)[1][:-1] if _raw.endswith("]") and " [" in _raw else ""
        _base = _clean_asset_name(_raw)
        if _ann in ("output", "temp") and (comfyui_dir / _ann / _base).is_file():
            gaps.append(
                f"{m['class_type']}.{m['input']} = {_raw} reads a picture out of "
                f"{prefix}/{_ann}/, not {prefix}/input/. Finished pictures and scratch files "
                f"never travel with a nest, so this one won't either and the recipe won't run "
                f"as it stands. Copy {_base} into {prefix}/input/, point the node at it there, "
                f"and pack again")
            continue
        # **"Missing" is the wrong word when the workflow named a full path.** The file
        # is usually sitting in the standard folder under that same name; what we refused
        # to follow is a path from the machine the workflow was built on. Telling someone
        # to "put the file back" sends them looking for something that never left.
        outside = "points outside the folder" in (m.get("note") or "")
        here = ""
        if outside:
            base = Path(str(m["value"]).replace("\\", "/")).name
            for sub in (CATEGORIES.get(str(m.get("category")), ((), ""))[0] or ()):
                if (comfyui_dir / sub / base).is_file():
                    here = f"{sub}/{base}"
                    break
        if outside:
            gaps.append(
                f"{m['class_type']}.{m['input']} names a full path from another machine: "
                f"{m['value']}. We do not follow paths out of the folder being packed, so "
                f"this model is **not in the nest**."
                + (f" The file itself is right here, at {here} — nothing is lost; the "
                   f"workflow just addresses it the long way. Point that node at the file "
                   f"by name and pack again."
                   if here else
                   " Put the file in the standard folder for its kind, point the node at "
                   "it by name, and pack again.")
            )
        else:
            gaps.append(f"Missing file: {m['class_type']}.{m['input']} = {m['value']} "
                        f"(looked in {m['searched_dirs']}). Without it the nest is "
                        f"incomplete — put the file back before you pack")

    # extra_model_paths.yaml: models kept outside the standard directories are followed
    # by _locate above and recorded under the standard models/ directory, so a restored
    # ComfyUI finds them without reproducing the external paths or carrying the yaml.
    # What follows is only the fallback warning for when that could not be done.
    _emp_yaml = next((y for y in ("extra_model_paths.yaml", "extra_model_paths.yml")
                      if (comfyui_dir / y).is_file()), None)
    # There is a yaml file, but no usable external directory came out of it:
    # pyyaml missing, parse failure, or the directory does not exist.
    if _emp_yaml and not emp:
        gaps.append(
            f"Found {_emp_yaml} but couldn't read a single usable model folder out of it "
            f"(this environment may be missing pyyaml, or base_path points at a folder that "
            f"isn't there). Models kept outside the standard folders could be left out, giving "
            f"you an incomplete nest. Pack again in an environment that has pyyaml, or make "
            f"sure every model this workflow uses sits in the standard models/ folder.")

    # ---- 3. custom_nodes: match non-built-in classes statically, then read
    #         url + commit through a git subprocess ----
    node_dirs = _scan_custom_node_dirs(comfyui_dir)
    node_files = _scan_custom_node_files(comfyui_dir)
    class_match: dict[str, dict] = {}   # class -> match result
    matched_dirs: dict[str, dict] = {}  # dir name -> git identity (into code_deps)
    dirs_without_git: list[str] = []
    by_suffix: dict[str, list[str]] = {}  # dir name -> classes matched the second way
    # What the run that worked said about where each node came from. It beats every
    # route below it -- those read files from outside and infer, this one was written
    # by the app that had the class loaded.
    recorded = recorded_node_owners(comfyui_dir, node_dirs, program_dir)
    for cls, node_ids in sorted(unknown_classes.items()):
        owner = recorded.get(cls, NOT_RECORDED)
        if owner is None:
            class_match[cls] = {"status": "matched", "node_ids": node_ids, "dirs": [],
                                "source": "run_record_builtin"}
            gaps.append(
                f"Node type {cls} isn't in our list of ComfyUI's own nodes, but your "
                f"working run reported it as one of them — so nothing extra has to be "
                f"packed for it. Our list is behind ComfyUI, that is all")
            continue
        if isinstance(owner, str):
            hits = [d for d in node_dirs if d.name == owner]
            class_match[cls] = {"status": "matched", "node_ids": node_ids,
                                "dirs": [owner], "source": "run_record"}
            _record_dir_identity(hits, cls, matched_dirs, dirs_without_git, gaps)
            continue
        hits = [d for d in node_dirs if _dir_defines_class(d, cls)]
        # Only when the full name found nothing, so a folder that really does spell the
        # name out always wins over one matched through its suffix.
        if not hits:
            hits = _dirs_defining_a_suffixed_class(node_dirs, cls)
            for d in hits:
                by_suffix.setdefault(d.name, []).append(cls)
        if not hits:
            solo = [f for f in node_files if _file_defines_class(f, cls)]
            if solo:
                class_match[cls] = {"status": "matched", "node_ids": node_ids, "dirs": [],
                                    "files": [f.name for f in solo]}
                gaps.append(
                    f"Node type {cls} comes from custom_nodes/{solo[0].name}, a single file "
                    f"rather than a folder. Its bytes travel inside the {prefix} archive and "
                    f"come back as they are; what we can't record is where it came from or "
                    f"which version it is, because one loose file carries no git history")
                continue
            class_match[cls] = {"status": "unmatched", "node_ids": node_ids}
            # Name the three things this can mean and how to tell them apart. Saying
            # only "we cannot say where it comes from" leaves the reader with no next
            # move, and leaning on "probably a built-in we have not listed" points at
            # the harmless reading while the expensive one -- an installed pack we
            # failed to recognise, whose absence shows up only on rebuild -- reads the
            # same from here. Checking in a running ComfyUI is advice to the reader,
            # not something this module does: the static-parse rule at the top governs
            # what capture touches, not what its report may suggest you go and look at.
            gaps.append(f"Node type {cls} is not in our list of ComfyUI built-ins, and no "
                        f"folder under custom_nodes/ defines it either. Either it is a "
                        f"built-in we have not listed, or it comes from a node pack — and "
                        f"if that pack is installed here, this nest will not record it, "
                        f"which is the reading that costs you a rebuild. To settle it: "
                        f"install the Renest panel in ComfyUI, run this workflow once and "
                        f"capture again — a finished run reports which pack every node came "
                        f"from, and that answer beats anything we can read from outside")
            continue
        if len(hits) > 1:
            gaps.append(f"Node type {cls} shows up in more than one custom_nodes folder "
                        f"({[d.name for d in hits]}). We record all of them — please check "
                        f"which one it really comes from")
        class_match[cls] = {"status": "matched", "node_ids": node_ids,
                            "dirs": [d.name for d in hits]}
        _record_dir_identity(hits, cls, matched_dirs, dirs_without_git, gaps)
    # One line per folder rather than per node type: a pack of this shape brings dozens
    # of node types at once, and a line each would bury everything else in the report.
    for _dirname, _classes in sorted(by_suffix.items()):
        _shown = ", ".join(sorted(_classes)[:3]) + ("…" if len(_classes) > 3 else "")
        gaps.append(f"Matched {len(_classes)} node type(s) to custom_nodes/{_dirname} through "
                    f"the suffix in their names rather than the names themselves ({_shown}). "
                    f"That pack puts its node names together when it starts, so the full name "
                    f"is in none of its files. It is recorded as the source and its files "
                    f"travel with the nest; worth a glance if it isn't the right pack")
    referenced = {n for m in class_match.values() for n in m.get("dirs", [])}
    dirs_not_referenced = [d.name for d in node_dirs if d.name not in referenced]

    # ---- 4. git identity of ComfyUI itself ----
    # Whichever tree holds the program is the one that answers "which ComfyUI is
    # this". On a one-tree install that is the same directory as the nodes and
    # models; on the desktop build it is the separate program tree.
    core_dir = program_dir or comfyui_dir
    core = git_identity(core_dir)
    if core is None:
        core = {"repo_url": "<fill in the ComfyUI repo, e.g. https://github.com/comfyanonymous/ComfyUI>",
                "commit": "<fill in the full 40 characters from git -C ComfyUI rev-parse HEAD>"}
        # Separate the two kinds of "cannot read git": the program is not in this
        # directory at all (the desktop app hands us its data directory only), versus
        # it is here but has no git history. A hint pointing the wrong way costs more
        # than no hint -- the first case means the nest has no ComfyUI in it.
        if not _looks_like_comfyui_source(core_dir):
            if program_dir is None:
                gaps.append(
                    f"There's no ComfyUI program in {comfyui_dir} — no main.py, no comfy/ folder. "
                    f"This is what the ComfyUI desktop app looks like: it hands us its **data** "
                    f"folder (custom nodes, models, workflows) while the program itself lives "
                    f"somewhere else. This nest will carry your nodes, models and workflow, but "
                    f"NOT ComfyUI itself — whoever rebuilds it has to install ComfyUI first. "
                    f"Packing both trees as one environment is not supported yet"
                )
            else:
                # Told, not refused: the rest of the environment still packs, and the
                # one thing this costs is exactly the thing the program tree was for.
                gaps.append(
                    f"There's no ComfyUI program in {program_dir} — no main.py, no comfy/ "
                    f"folder — and that is the folder named as where the program lives. "
                    f"This nest will carry your nodes, models and workflow, but NOT ComfyUI "
                    f"itself. Check that path and pack again"
                )
        else:
            where = str(program_dir) if program_dir is not None else f"{prefix}/"
            gaps.append(f"Can't read git remote/HEAD in {where} — fill in where ComfyUI itself "
                        f"came from by hand")
    else:
        core_dirty = dirty_gap(f"{prefix}/ (ComfyUI itself)", core_dir)
        if core_dirty:
            gaps.append(core_dirty)
    if program_dir is not None and _looks_like_comfyui_source(comfyui_dir):
        # Both folders hold a program, so the version this nest records comes from one
        # of them and the bytes that land last come from the other -- a manifest whose
        # recorded version and packed files disagree. Said, never guessed at.
        gaps.append(
            f"Two ComfyUI programs here: the version this nest records is the one in "
            f"{program_dir}, but {comfyui_dir} has a main.py and a comfy/ folder too and "
            f"its files are packed on top. The recorded version would then not match the "
            f"files. Point --program-dir at the folder your nodes and models actually run "
            f"against, or pack that folder on its own"
        )

    # ---- 5. assemble the pack-spec draft (shaped like pack's input; the measured
    #         hash travels only as a cross-check, never as the packer's source) ----
    # role (required from format v2.0 on): capture already knows which is which, so
    # emitting it here saves every consumer from inferring it back out of the path.
    core_exclude = COMFYUI_CORE_EXCLUDE + [f"custom_nodes/{n}" for n in sorted(matched_dirs)]
    host: dict = {"name": prefix, "role": "host", **core, "install_path": prefix}
    if program_dir is not None:
        # pack-spec 1.3: read the program's bytes over there, still land them at the
        # standard-layout spot. install_path is untouched, so the nest is an ordinary
        # single-tree install however scattered the machine it was packed from.
        host["source_path"] = str(program_dir)
    host["exclude"] = core_exclude
    code_deps = [host]
    if program_dir is not None:
        # The data tree used to ride inside the host archive; now that host reads the
        # program tree, everything in it that is not a node folder and not a model has
        # nobody to carry it. Give it an entry of its own, landing at the same standard
        # spot -- both archives unpack into it, and neither restore leg clears the
        # directory first. Skipped when nothing is left, because an empty archive makes
        # the rebuild stop and blame a symlink that does not exist.
        leftovers = _data_tree_leftovers(comfyui_dir, core_exclude)
        if leftovers:
            code_deps.append({"name": f"{prefix}-data", "role": "user_code",
                              "install_path": prefix, "source_path": str(comfyui_dir),
                              "exclude": core_exclude})
            shown = ", ".join(leftovers[:5]) + ("…" if len(leftovers) > 5 else "")
            gaps.append(f"ComfyUI's program and your nodes and models live in two separate "
                        f"folders here, and the nest merges them into one standard install. "
                        f"{len(leftovers)} item(s) that sit beside your nodes and models "
                        f"travel too ({shown}); everything under models/, output/, temp/, "
                        f"input/ and user/ is left out as usual")
    for name in sorted(matched_dirs):
        code_deps.append({"name": name, "role": "extension", **matched_dirs[name],
                          "install_path": f"{prefix}/custom_nodes/{name}"})

    files = []
    for r in recognized:
        if r["kind"] == "input_asset":
            lic = {"shareable": True, "serving_scope": "private", "tag": "unknown",
                   "note": "Input material for the workflow, treated as yours. If it isn't "
                           "yours, change this entry by hand"}
        else:
            lic = {"shareable": False, "serving_scope": "gated", "tag": "unknown",
                   "note": "We couldn't confirm the license, so it defaults to gated "
                           "(restricted). Check the license and add origin_url before you pack."}
            # The bytes ARE packed -- restricted only stops them being supplied to
            # somebody you hand the nest to (pack.py says the same thing in the same
            # words). Reading this as "not in the nest" sends people re-downloading
            # models they already have.
            gaps.append(f"{r['path']}: license unknown, so it's restricted by default and has "
                        f"no origin_url. The bytes are in the nest and your own rebuilds work; "
                        f"what they won't do is travel to anyone you hand this nest to, and "
                        f"without an origin_url that person has nowhere to fetch it from. Add "
                        f"the licence and origin_url before you pack.")
        # Hand the hash we just measured to the packer as `expected_sha256`. It is a
        # cross-check, not a source — packing hashes the file again and refuses to
        # continue if it has changed since capture. The hash that reaches the nest is
        # always the one packing measured, so no hash is ever "filled in by hand".
        files.append({"path": r["path"], "license": lic, "kind": r["kind"],
                      "expected_sha256": r["sha256"]})

    if workflow_relpath is None:
        workflow_relpath = "<fill in the path to the workflow JSON you ran, relative to the environment root>"
        gaps.append("The workflow file isn't inside the environment root (or no path was "
                    "given) — fill workflow_path in by hand")

    # ---- 6. advisory: big models are installed that this workflow never uses
    #         (informs, never blocks) ----
    unreferenced_large = _scan_unreferenced_large_files(
        comfyui_dir, prefix, seen_paths, large_file_bytes)
    for u in unreferenced_large:
        # The old wording here said "we pack the whole folder either way". It was
        # simply untrue -- this scan only looks under models/, and models/ is on the
        # exclude list, so none of these travel. Someone deleting a 11 GB model on the
        # strength of that sentence would have been told the opposite of the truth.
        gaps.append(f"{u['path']} ({u['size_bytes']} bytes) is a big model this recipe "
                    f"never loads, so it is NOT packed — only the models the recipe "
                    f"names travel with the nest. If you want it in there anyway, list "
                    f"it under files[] in a pack-spec and pack with --spec")

    # A container cannot answer these about itself (it cannot even see its own image
    # name), so they have to come from outside. **The digest is not on this list** --
    # once the image name is known it can be looked up; see resolve_image_digest.
    needs_manual = ["base_image.ref", "runtime.python_version", "python_lock.lockfile_path"]
    pack_spec = {
        "name": "<give it a name, e.g. My SDXL workflow>",
        "base_image": {
            "ref": "<fill in the image this pod actually runs, e.g. runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04>",
            "digest": "sha256:<fill in the image digest>",
        },
        "runtime": {"python_version": "<fill in python --version, e.g. 3.11.9>"},
        "code_deps": code_deps,
        "python_lock": {"tool": "uv",
                        "lockfile_path": "<fill in the path to the uv lock file, e.g. requirements.lock>"},
        "files": files,
        # entrypoint (format v2.0): "how to start this thing" is data in the nest, not
        # hard-coded logic on the restore side. The port is only known at rebuild time,
        # so argv carries no --port and the restore side appends a free one.
        "entrypoint": {
            "kind": "service",
            "cwd": prefix,
            "argv": ["python", "main.py", "--listen", "127.0.0.1"],
            "ready_probe": {
                "http_get": "/system_stats",
                "smoke_get": "/object_info",
                "timeout_s": 300,
            },
        },
        "adapters": {"comfyui": _comfyui_adapter(comfyui_dir, workflow_relpath)},
        "creation": {"agent_version": CAPTURE_VERSION},
    }
    # Nodes that hand the work to somebody else's servers. The format calls this an
    # honest boundary: whatever runs over there is not in the nest and will keep
    # working only as long as that service does. Defined and never written until now,
    # which is the worst of both — it read as "we checked, there are none".
    # Read from the tree that holds the program: `comfy_api_nodes/` is ComfyUI's own
    # package, so on a two-tree install it is not under the data folder at all, and
    # looking there finds nothing -- which reads exactly like "we checked, there are
    # none", the very failure the paragraph above was written for.
    _api = api_forwarding_nodes(core_dir, [n["class_type"] for n in nodes.values()])
    if _api:
        pack_spec["api_deps"] = _api
        gaps.append(
            f"{len(_api)} node(s) in this workflow call an outside service "
            f"({', '.join(a['node_name'] for a in _api[:5])}). Those calls are not part "
            f"of what a rebuild restores — they work for as long as that service does, "
            f"and whoever receives this nest needs their own account for it.")

    report = {
        "capture_version": CAPTURE_VERSION,
        "workflow_nodes": len(nodes),
        "models": {"recognized": recognized, "missing": missing},
        "custom_nodes": {
            "class_match": class_match,
            "packed_dirs": {n: matched_dirs[n] for n in sorted(matched_dirs)},
            "dirs_without_git": dirs_without_git,
            "dirs_not_referenced": dirs_not_referenced,
        },
        "unrecognized_string_inputs": unrecognized_inputs,
        "unreferenced_large_files": unreferenced_large,
        "needs_manual_fill": needs_manual,
        "gaps": gaps,
    }
    return CaptureResult(pack_spec=pack_spec, report=report)
