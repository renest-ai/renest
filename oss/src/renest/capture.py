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

import contextlib
import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .integrity import dirty_gap, git_identity, probe_model_bytes, registry_identity
from .verified import scan_comfyui_output

__all__ = [
    "api_forwarding_nodes",
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
BUILTIN_CLASSES: frozenset[str] = frozenset({
    *MODEL_REF_MAP,
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


def _sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 22):
            h.update(chunk)
    return h.hexdigest(), path.stat().st_size


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
        base = str(cfg.get("base_path", "") or "")
        base_p = Path(base) if Path(base).is_absolute() else (comfyui_dir / base).resolve() if base else None
        for key, val in cfg.items():
            if key in ("base_path", "is_default") or not isinstance(val, str):
                continue
            for line in val.splitlines():        # one line, or a | block list
                sub = line.strip()
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


#: Where the host app keeps the nodes that hand work to an outside service.
_API_NODE_PKG = "comfy_api_nodes"


def api_forwarding_nodes(comfyui_dir: Path, classes: Iterable[str]) -> list[dict]:
    """Which of these nodes hand the work to somebody else's servers.

    **Recognised from the code on this machine, never from a list of names we keep.**
    The host app keeps its service-calling nodes in one package, so a class defined
    there is one of them, and the file that defines it names the service. When that
    package is not present, the answer is silence — a guessed entry here would be worse
    than none, because this list is the format's honest boundary: the byte-for-byte
    promise does not cover anything that runs on someone else's servers.

    **Known limit, stated rather than hidden**: a third-party node that forwards to a
    service is not caught by this — it lives in its own folder like any other."""
    pkg = Path(comfyui_dir) / _API_NODE_PKG
    if not pkg.is_dir():
        return []
    sources = sorted(pkg.rglob("*.py"))
    out: list[dict] = []
    for cls in sorted(set(classes)):
        hit = next((py for py in sources if _file_defines_class(py, cls)), None)
        if hit is None:
            continue
        stem = hit.stem.removeprefix("nodes_")
        out.append({
            "node_name": cls,
            "service": stem if stem and stem != "nodes" else hit.parent.name,
            "note": "Recognised because the app defines this node in its own "
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
            large_file_bytes: int | None = None) -> CaptureResult:
    """Static capture: a workflow (API-format dict) plus a ComfyUI directory ->
    a pack-spec draft and a report.

    Paths inside the pack-spec are relative to the environment root (the parent
    of ``comfyui_dir``), matching ``pack --root``. When ``large_file_bytes`` is
    omitted the module-level ``LARGE_FILE_BYTES`` is read at call time, which
    keeps it overridable from tests.
    """
    if large_file_bytes is None:
        large_file_bytes = LARGE_FILE_BYTES
    comfyui_dir = comfyui_dir.resolve()
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
        sha, size = _sha256_file(found)
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
        sha, size = _sha256_file(found)
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

    for m in missing:
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
    class_match: dict[str, dict] = {}   # class -> match result
    matched_dirs: dict[str, dict] = {}  # dir name -> git identity (into code_deps)
    dirs_without_git: list[str] = []
    for cls, node_ids in sorted(unknown_classes.items()):
        hits = [d for d in node_dirs if _dir_defines_class(d, cls)]
        if not hits:
            class_match[cls] = {"status": "unmatched", "node_ids": node_ids}
            gaps.append(f"Node type {cls} isn't one of the built-ins and no folder in "
                        f"custom_nodes/ defines it — we can't tell where it comes from. Either "
                        f"our built-in list doesn't cover it, or that node pack really is "
                        f"missing here")
            continue
        if len(hits) > 1:
            gaps.append(f"Node type {cls} shows up in more than one custom_nodes folder "
                        f"({[d.name for d in hits]}). We record all of them — please check "
                        f"which one it really comes from")
        class_match[cls] = {"status": "matched", "node_ids": node_ids,
                            "dirs": [d.name for d in hits]}
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
    referenced = {n for m in class_match.values() for n in m.get("dirs", [])}
    dirs_not_referenced = [d.name for d in node_dirs if d.name not in referenced]

    # ---- 4. git identity of ComfyUI itself ----
    core = git_identity(comfyui_dir)
    if core is None:
        core = {"repo_url": "<fill in the ComfyUI repo, e.g. https://github.com/comfyanonymous/ComfyUI>",
                "commit": "<fill in the full 40 characters from git -C ComfyUI rev-parse HEAD>"}
        # Separate the two kinds of "cannot read git": the program is not in this
        # directory at all (the desktop app hands us its data directory only), versus
        # it is here but has no git history. A hint pointing the wrong way costs more
        # than no hint -- the first case means the nest has no ComfyUI in it.
        if not _looks_like_comfyui_source(comfyui_dir):
            gaps.append(
                f"There's no ComfyUI program in {comfyui_dir} — no main.py, no comfy/ folder. "
                f"This is what the ComfyUI desktop app looks like: it hands us its **data** "
                f"folder (custom nodes, models, workflows) while the program itself lives "
                f"somewhere else. This nest will carry your nodes, models and workflow, but "
                f"NOT ComfyUI itself — whoever rebuilds it has to install ComfyUI first. "
                f"Packing both trees as one environment is not supported yet"
            )
        else:
            gaps.append(f"Can't read git remote/HEAD in {prefix}/ — fill in where ComfyUI itself "
                        f"came from by hand")
    else:
        core_dirty = dirty_gap(f"{prefix}/ (ComfyUI itself)", comfyui_dir)
        if core_dirty:
            gaps.append(core_dirty)

    # ---- 5. assemble the pack-spec draft (shaped like pack's input; hash and
    #         size are never filled in by hand) ----
    # role (required from format v2.0 on): capture already knows which is which, so
    # emitting it here saves every consumer from inferring it back out of the path.
    core_exclude = COMFYUI_CORE_EXCLUDE + [f"custom_nodes/{n}" for n in sorted(matched_dirs)]
    code_deps = [{"name": prefix, "role": "host", **core, "install_path": prefix,
                  "exclude": core_exclude}]
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
            gaps.append(f"{r['path']}: license unknown (defaulting to gated) and no origin_url. "
                        f"Gated files don't travel with the nest — whoever restores it fetches "
                        f"them from origin_url, so add one before you pack.")
        files.append({"path": r["path"], "license": lic, "kind": r["kind"]})

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
    _api = api_forwarding_nodes(comfyui_dir, [n["class_type"] for n in nodes.values()])
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
