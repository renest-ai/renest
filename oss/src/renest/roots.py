"""Landing roots and the home-directory allowlist (format v2.0) -- the one and only
definition, shared by the packing end and the rebuild end.

Two copies would drift, and drift here means **uploading the user's dataset to the
cloud** on one side and **writing into the user's home directory** on the other. Two
mirrors are deliberate -- the pattern in `oss/specs/manifest.schema.json` and
`scripts/restore.sh` (the escape hatch may import no code from this project); change
this and you must change them together. `renest lint` and
`oss/tests/consistency/test_restore_sh_landing_gate.py` pin them to each other.

**Allowlist, never a denylist**: miss an allowlist entry and a file is missing at rebuild
time, which the user notices; miss a denylist entry and the user's dataset (training
writes it to `~/.cache/huggingface/datasets/`) goes to the cloud and nobody notices.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

__all__ = [
    "FILE_ROOTS",
    "MAX_MANIFEST_FILES",
    "ROOT_PATH_PATTERNS",
    "ENV_PATH_KEYS",
    "ENV_PATH_LIST_KEYS",
    "resolve_file_root",
    "unsafe_relpath",
    "bad_root_entry",
    "bad_entrypoint_env",
    "ENV_PASSTHROUGH_KEYS",
    "materialise_entrypoint_env",
    "ENV_ROOT_TOKEN",
    "tokenise_env_root",
    "resolve_env_root_token",
    "HOME_ROOT_DIR",
    "HOME_CACHE_PREFIXES",
    "HOME_WRITE_PREFIXES",
    "HOME_CACHE_ENV",
    "HOME_NEVER_CARRY",
    "carries_hf_hub",
    "home_paths",
    "home_cache_env",
    "home_cache_env_rel",
    "home_writes",
]

FILE_ROOTS = ("env", "hf_hub", "hf_home", "home")

#: How many files one nest may hold at most: 50,000.
#: The 32 MB size ceiling (`config.JSON_SOURCE_MAX_BYTES`) still leaves room for a hundred
#: thousand entries, and the escape hatch **starts two jq processes per file** -- so the
#: entry count alone can keep a recipient's machine spinning all night without a single
#: oversized byte. Hard-coded as a guard rail, deliberately not a tunable knob.
#: Not in the schema: adding maxItems is a format change and needs a version bump, so this
#: lives in the three consumers (rebuild end / check tool / escape hatch) until then.
MAX_MANIFEST_FILES = 50_000

# The path allowlist for each root. Word for word the same as the allOf
# branches of files[] in manifest.schema.json.
ROOT_PATH_PATTERNS: dict[str, re.Pattern[str]] = {
    "hf_hub": re.compile(r"^models--[^/]+/(refs/[^/]+|snapshots/[0-9a-f]{40}/.+)$"),
    "hf_home": re.compile(r"^accelerate/[^/]+\.yaml$"),
    # Format 2.14: model caches some nodes keep under the home folder (see HOME_CACHE_PREFIXES
    # below; this pattern is the same list, spelled out once more for the schema mirror).
    # ``.no_exist/<commit>/...``: Hugging Face's own record of a file it asked for and the
    # repository does not have (empty files). Without them a restored cache asks the
    # network again for every optional file on the first load (U7, 2026-10-11).
    "home": re.compile(r"^(\.cache/huggingface/hub/models--[^/]+/"
                       r"(refs/[^/]+|snapshots/[0-9a-f]{40}/.+|\.no_exist/[0-9a-f]{40}/.+)"
                       r"|\.rembg/.+|\.transparent-background/.+|\.insightface/.+)$"),
}


def resolve_file_root(root: str, env_root: Path, env: Mapping[str, str] | None = None) -> Path:
    """Work out the real directory of a landing root.

    The resolution order follows the official HF docs (how ``HF_HOME`` and
    ``HF_HUB_CACHE`` override each other) and the wording of the accelerate
    CLI docs; ``env`` is the environment root itself, its old meaning
    unchanged to the letter.
    """
    e = os.environ if env is None else env
    # The default branch reads HOME **out of the same mapping**, not out of this
    # process. Both fallbacks used to call Path.home(), so a caller that handed in
    # an environment got that environment for the two overrides and this machine's
    # home directory for the default -- and the default is the usual case.
    home = Path(e["HOME"]) if e.get("HOME") else Path.home()
    if root == "hf_hub":
        if e.get("HF_HUB_CACHE"):
            return Path(e["HF_HUB_CACHE"])
        if e.get("HF_HOME"):
            return Path(e["HF_HOME"]) / "hub"
        return home / ".cache" / "huggingface" / "hub"
    if root == "hf_home":
        if e.get("HF_HOME"):
            return Path(e["HF_HOME"])
        return home / ".cache" / "huggingface"
    if root == "home":
        # Inside the restore target, never the restoring user's home folder: the app is
        # started with each library's own setting pointed here (home_cache_env).
        return env_root / HOME_ROOT_DIR
    return env_root


def unsafe_relpath(p: object) -> bool:
    """A path must be a relative path inside the landing root it belongs to.

    An absolute path displaces that root entirely in ``root / p`` (pathlib
    semantics), and ``..`` can climb out of it.
    **This applies to every root without exception**, including the two home
    directory roots: the tail of the ``hf_hub`` allowlist is
    ``snapshots/<40hex>/.+``, and that ``.+`` **swallows `..`**
    (for example ``snapshots/<40hex>/../../../../etc/passwd``), so the
    pattern would wave it straight through.
    **The allowlist alone cannot stop this; this separate refusal has to stay
    in place forever.**
    """
    if not isinstance(p, str) or not p:
        return True
    pp = PurePosixPath(p.replace("\\", "/"))
    return pp.is_absolute() or ".." in pp.parts or p.startswith("~")


#: Directory names: anything landing inside one of these **gets run as
#: code**, not read as data.
#: - ``.venv`` / ``site-packages``: installed Python packages live here. Put
#:   one ``.pth`` file into site-packages and **the interpreter executes it on
#:   every start** -- nobody has to import it.
#: - ``bin``: executables on PATH.
#: Compared in lower case: a case-insensitive disk (Windows, the default on macOS)
#: lands ``.VENV/.../Site-Packages/evil.pth`` in the real site-packages (independent
#: security review, 2026-10-19). ``dist-packages`` is Debian's site folder;
#: ``__pycache__`` holds compiled code; ``startup-scripts`` is where ComfyUI-Manager
#: keeps scripts it runs at start-up.
_CODE_DIRS = frozenset({".venv", "venv", "site-packages", "dist-packages", "__pycache__",
                        "startup-scripts"})
#: Folders that hold executables on PATH: refused for anything that is not plainly a
#: data file. Weights under a folder that happens to be called ``bin``
#: (``models/clip_vision/bin/model.safetensors``) are data and pass.
_EXEC_DIRS = frozenset({"bin", "scripts"})
#: Files ComfyUI or its node manager read at start-up and that can add a code path or
#: redirect where things are fetched from: never carried as an asset, whatever the
#: suffix (independent security review, fourth round, 2026-10-19:
#: ``extra_model_paths.yaml`` has a ``custom_nodes:`` key that ComfyUI loads from its
#: own folder on every start). Compared in lower case.
_STARTUP_CONFIG_NAMES = frozenset({
    "extra_model_paths.yaml", "extra_model_paths.yml", "comfy.settings.json",
    "config.ini", "channels.list", "custom-node-list.json", "model-list.json",
    "alter-list.json", "extension-node-map.json", "github-stats.json",
})
#: A folder whose contents the node manager reads as its own data (lists, snapshots,
#: settings, ``pip_overrides.json``, cached catalogues under hashed names): nothing a
#: nest carries belongs in it. Judged by **prefix**, in lower case: the manager's
#: current version keeps its data in ``user/__manager/`` (fifth review round,
#: 2026-10-19, read off the source on the house machine), and a manual install lands
#: the code folder as ``ComfyUI-Manager-main``.
_MANAGER_DIR_PREFIXES = ("comfyui-manager", "__manager")
#: Files an installer reads as instructions wherever they sit: one line in a
#: ``requirements.txt`` is a pip install or a git clone the moment the node manager (or
#: "Update ComfyUI") runs; a ``pyproject.toml`` / ``uv.toml`` redirects uv's package
#: index and, under ``[tool.comfy]``, can point the app at a browser-script folder
#: anywhere on disk. These names are refused under the whole env root because the
#: trainer frameworks keep their own run configs (``sft.yaml``, ``train/dataset.toml``)
#: at the root, so a location rule alone cannot tell the two apart. Lower case; the
#: ``requirements*`` / ``constraints*`` families are matched by prefix.
_INSTALLER_INPUT_NAMES = frozenset({
    "pyproject.toml", "uv.toml", "uv.lock", "setup.cfg", "pip.conf", "pip.ini",
    "pipfile", "pipfile.lock", "poetry.lock", "package.json", "package-lock.json",
})
_INSTALLER_INPUT_PREFIXES = ("requirements", "constraints")
#: Text and config suffixes: fine as assets under the model folders and at the root,
#: but inside a node's folder they are the node's own code configuration (its
#: ``requirements.txt``, its ``pyproject.toml``, the lists it reads), and under the
#: app's ``user/`` folder they are app and manager settings -- except a workflow in a
#: ``workflows`` folder, which is what a nest exists to carry. Weights and media stay
#: allowed everywhere, and so does a file with no suffix (nodes keep extensionless
#: weights under their own folder; the suffix-less installer files, ``Pipfile``, are
#: refused by name above).
_TEXT_SUFFIXES = frozenset({
    ".json", ".jsonl", ".txt", ".yaml", ".yml", ".toml", ".lock", ".md", ".csv", ".tsv",
    ".xml", ".vocab", ".merges",
})
_NODE_DIRS = frozenset({"custom_nodes"})
_USER_DIRS = frozenset({"user"})
_WORKFLOW_DIRS = frozenset({"workflows"})
#: Windows reserved device names: a file by that name cannot be created there.
_WINDOWS_DEVICES = frozenset({"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)}
                             | {f"lpt{i}" for i in range(1, 10)})
#: Suffixes: the file is code in itself -- a ``.py`` landing in the host app's
#: or an extension's directory runs as soon as the app imports it at startup.
#: ``.pth`` is **not** here: Python only executes ``.pth`` files that sit in a
#: site directory, which the folder rule above already refuses. Anywhere else a
#: ``.pth`` is PyTorch weights (SAM, upscalers, face models); refusing it by
#: suffix left those models out of every nest (measured 2026-10-07: a SAM
#: model a workflow loaded was dropped as "program code", and the restore could
#: not run the workflow).
#: Also code in itself (independent security review, 2026-10-19): a native extension
#: (``.so`` / ``.dylib`` / ``.dll``, and the ``.cpython-*`` / ``.abi3`` spellings) is
#: imported like a ``.py``; a browser script under the app's ``web/`` runs in the
#: owner's browser, where it can call the panel's own routes; shell and batch files run
#: when something calls them. Model formats (``.pth`` outside a site folder,
#: ``.safetensors``, ``.ckpt``, ``.bin``, ``.onnx``, ``.gguf``, ``.pt``) are not here and
#: must never be -- see the 2026-10-07 note above.
_CODE_SUFFIXES = (".py", ".pyc", ".pyd", ".pyo", ".pyw", ".so", ".dylib", ".dll",
                  ".js", ".mjs", ".cjs", ".sh", ".bat", ".cmd", ".ps1", ".exe")
#: Marks anywhere in a file name that mean a compiled Python extension whatever the
#: final suffix (``x.cpython-311-x86_64-linux-gnu.so``, ``x.abi3.so``).
_CODE_NAME_MARKS = (".cpython-", ".abi3.")
#: The reserved in-nest path of the escape hatch (manifest spec §5.4), the only shell
#: script a nest may carry under files[].
ESCAPE_HATCH_REL = ".renest/escape/restore.sh"
#: What a files[] entry under the env root may be, by suffix: the data a nest carries
#: (weights, tokenizers, configs, media, fonts, archives). **An allowlist, not a
#: blocklist** (independent security review 2026-10-19, third round): every blocklist
#: was one case behind -- trailing dots and spaces a Windows disk strips, ``::$DATA``,
#: git hooks, a manager's config.ini. Built from the 130 real manifests on hand (every
#: suffix they carry is here) plus the obvious neighbours of each family. A file with
#: no suffix at all passes (``put_blueprints_here``, ``LICENSE``); a suffix outside this
#: set is refused as "not something a nest carries as an asset".
ENV_DATA_SUFFIXES = frozenset({
    # weights and tensors
    ".safetensors", ".ckpt", ".pt", ".pth", ".bin", ".onnx", ".gguf", ".pkl", ".npy", ".npz",
    ".h5", ".msgpack", ".tflite", ".pb", ".params", ".model", ".task", ".vae", ".embedding",
    ".sft", ".engine",
    # text, configs, tokenizers
    ".json", ".jsonl", ".txt", ".yaml", ".yml", ".toml", ".lock", ".md", ".csv", ".tsv",
    ".xml", ".vocab", ".merges",
    # images, video, audio
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".svg",
    ".mp4", ".mov", ".webm", ".mkv", ".avi", ".wav", ".mp3", ".flac", ".ogg", ".m4a",
    # fonts, LUTs, archives (data until somebody unpacks them)
    ".ttf", ".otf", ".woff", ".woff2", ".cube", ".zip", ".tar", ".gz", ".tgz", ".7z",
})
#: Hidden folders that are data, not a place tools keep hooks or settings they run.
_HIDDEN_DIRS_THAT_ARE_DATA = frozenset({".cache"})


def code_position(p: str, *, env_root: bool = True) -> str | None:
    """Is this path a position that **gets executed as code**? If so, return
    the one plain-language reason.

    **[SECURITY-REVIEW - hand-off disclosure]** :func:`unsafe_relpath` blocks writing
    *outside* the rebuild directory; this gate blocks **executable positions inside
    it**. Two different holes -- doing only the first leaves the second wide open.

    Judged by **intent** ("will this asset be executed?"), not by the literal "must not
    overwrite where code_deps land": models live under ``ComfyUI/models/`` by nature, so
    the literal rule would reject well over half of all ordinary nests.

    **Applies to the ``env`` root only.** That root is the rebuild directory and carries
    ``sys.path``; the model cache roots are on no ``sys.path``, and the allowlist already
    pins their paths to a specific commit of a specific HF repository. Blocking them would
    make whole model families unpackable -- Qwen / Falcon / ChatGLM / DeepSeek / Phi ship
    ``modeling_*.py`` inside the snapshot, and the fine-tuning side uses those daily. The
    right answer there is **disclosure through ``files[].serialization``, not blocking**.
    """
    pp = PurePosixPath(p.replace("\\", "/"))
    if str(pp) == ESCAPE_HATCH_REL:
        # The one script every nest carries on purpose (format 2.3): the escape hatch
        # itself, at its reserved path. It is never run by a restore, only placed.
        return None
    # The three rules below are for the env root only: the home root's paths are
    # pinned by their own allowlist (``.rembg/…``, ``.insightface/…`` are hidden
    # folders by design), and the two model-cache roots sit on no execution path.
    if env_root:
        for part in pp.parts:
            # A Windows disk strips a trailing dot or space and reads ``::$DATA`` as the
            # file itself, so ``__init__.py.`` lands as ``__init__.py``. Judged on every
            # platform: a nest is the same bytes wherever it is restored.
            if part.endswith((".", " ")) or ":" in part:
                return f"a path with a name a Windows disk would rewrite: {p!r}"
    name = pp.name.lower()
    suffix = PurePosixPath(name).suffix
    plain_data = bool(suffix) and suffix in ENV_DATA_SUFFIXES and suffix != ".pth"
    for part in pp.parts[:-1]:
        low = part.lower()
        if low in _CODE_DIRS or (low in _EXEC_DIRS and not plain_data):
            return f"a path inside {part!r}, where files get run as code, not read as data: {p!r}"
        if env_root and low.startswith(_MANAGER_DIR_PREFIXES):
            return f"a path inside the node manager folder {part!r}, which it reads as its own data: {p!r}"
        if env_root and low.startswith(".") and low not in _HIDDEN_DIRS_THAT_ARE_DATA:
            # .git keeps hooks and a config that run commands whenever git runs (a node
            # manager runs git in these folders on update); other hidden folders are
            # where tools keep what they execute. Nothing a nest carries belongs there.
            return f"a path inside the hidden folder {part!r}, where tools keep what they run: {p!r}"
    if name.endswith(_CODE_SUFFIXES) or any(mark in name for mark in _CODE_NAME_MARKS):
        return f"a path that is program code, not an asset: {p!r}"
    if not env_root:
        return None
    if name.startswith("."):
        return f"a hidden file, which tools read as settings rather than data: {p!r}"
    if name in _STARTUP_CONFIG_NAMES:
        return f"a settings file the app reads at start-up, which can point it at code: {p!r}"
    if name.split(".", 1)[0] in _WINDOWS_DEVICES:
        return f"a Windows device name, which no disk there can hold: {p!r}"
    if name in _INSTALLER_INPUT_NAMES or (
        name.startswith(_INSTALLER_INPUT_PREFIXES) and suffix == ".txt"
    ):
        return f"a file an installer reads as instructions, which can install code: {p!r}"
    textual = suffix in _TEXT_SUFFIXES
    if textual:
        dirs = {part.lower() for part in pp.parts[:-1]}
        if dirs & _HIDDEN_DIRS_THAT_ARE_DATA:
            # A Hugging Face download cache a node keeps under its own folder carries
            # ``.lock`` and metadata files beside the weights; a cache is read back as
            # data, never as instructions.
            dirs = set()
        if dirs & _NODE_DIRS:
            return f"a text file inside a node folder, which the node or its manager reads as its own configuration: {p!r}"
        if dirs & _USER_DIRS and not dirs & _WORKFLOW_DIRS:
            return f"a text file inside the app's user folder, where it keeps its settings: {p!r}"
    if suffix and suffix not in ENV_DATA_SUFFIXES:
        return f"a file type a nest does not carry as an asset ({suffix}): {p!r}"
    return None


def bad_root_entry(f: object) -> str | None:
    """The reason a ``files[]`` entry fails the landing gate (``None`` if it
    passes).

    Four checks whose order must not change: (1) root must be inside the
    enum; (2) path must stay inside its root (applies to every root); (3) a
    root other than ``env`` must also match its own allowlist pattern;
    (4) path may not land in a position that gets executed as code
    (:func:`code_position`). What comes back is one sentence written for a
    human to read.
    """
    if not isinstance(f, dict):
        return "a files[] entry that is not an object"
    root = f.get("root", "env")
    if root not in FILE_ROOTS:
        return f"unknown place to put files: {root!r}"
    p = f.get("path")
    if unsafe_relpath(p):
        return f"a path that writes outside where it belongs: {p!r}"
    pat = ROOT_PATH_PATTERNS.get(root)
    if pat is not None and not pat.match(str(p)):
        return f"a path that is not allowed under {root}: {p!r}"
    if root == "home":
        # Never a credential, whatever folder it sits in (Hugging Face keeps the access
        # token beside the hub cache). And outside the Hugging Face snapshots -- which may
        # hold a model's own modeling_*.py, as the hf_hub root allows -- no program code.
        if PurePosixPath(str(p)).name in HOME_NEVER_CARRY:
            return f"a credential file, which never travels: {p!r}"
        if not str(p).startswith(".cache/huggingface/hub/"):
            return code_position(str(p), env_root=False)
        return None
    # Check four covers the env root only -- the two model cache roots are not
    # on any execution path, and the allowlist above already pins their shape
    # to a specific commit of a specific HF repository (full reasoning in the
    # docstring of code_position).
    return code_position(str(p)) if root == "env" else None


# -- Values of the path-shaped keys in entrypoint.env ------------------------
# An allowlist of keys is not enough: **the values must be confined to the rebuild
# directory as well.** Nothing reads these keys today, but the format permits them with
# arbitrary string values, and the day somebody exports `LD_LIBRARY_PATH` verbatim it
# becomes an entry point for **library hijacking** (point it at an `.so` inside the nest
# and it loads ahead of the system library). Pinning this while the field is unused costs
# nothing; once nests exist it is a breaking change. Same rule as $defs/env_path and
# $defs/env_path_list in manifest.schema.json, duplicated on purpose.
ENV_PATH_KEYS = ("VIRTUAL_ENV", "HF_HOME", "HF_HUB_CACHE")
ENV_PATH_LIST_KEYS = ("LD_LIBRARY_PATH",)


def bad_entrypoint_env(env: object) -> list[str]:
    """The list of reasons ``entrypoint.env`` fails the gate (an empty list if
    it passes).

    The value of a path-shaped key must be a relative path inside the rebuild
    directory; **every colon-separated segment** of ``LD_LIBRARY_PATH`` must
    satisfy that too. An empty segment (``a::b``, a leading or trailing
    colon) means "the current directory" to the dynamic linker -- the one
    search location that is easiest to overlook -- and is refused as well.

    **Any future consumer must pass this gate before exporting these
    values**, and must then join them under the rebuild root rather than
    exporting them as they are.
    """
    if env is None:
        return []
    if not isinstance(env, dict):
        return ["entrypoint.env is not an object"]
    bad: list[str] = []
    for key in ENV_PATH_KEYS:
        if key in env and unsafe_relpath(env[key]):
            bad.append(f"{key} points outside the folder being rebuilt: {env[key]!r}")
    for key in ENV_PATH_LIST_KEYS:
        if key not in env:
            continue
        value = env[key]
        if not isinstance(value, str) or not value:
            bad.append(f"{key} points outside the folder being rebuilt: {value!r}")
            continue
        for seg in value.split(":"):
            # An empty segment means the current directory, just as dangerous
            # as an absolute path that escapes the root
            if seg == "" or unsafe_relpath(seg):
                bad.append(
                    f"{key} has an entry that points outside the folder being rebuilt: "
                    f"{seg!r} (in {value!r})"
                )
                break
    return bad


ENV_PASSTHROUGH_KEYS = ("CUDA_VERSION", "FORCE_TORCHRUN")


def materialise_entrypoint_env(env: object, env_root: Path) -> dict[str, str]:
    """Turn ``entrypoint.env`` into environment variables that can really be
    exported.

    This is the duty laid on **consumers**, in three steps whose order must
    not change:
    (1) pass the gate first (:func:`bad_entrypoint_env`) -- an out-of-bounds
        value rejects the whole thing, **before anything is exported**;
    (2) path-shaped keys are **joined under the rebuild root** into absolute
        paths and are **never exported as they are** -- the nest stores a
        relative path, and exporting that verbatim would point at the current
        directory of the rebuilding machine, which is neither correct nor
        safe;
    (3) not one key outside the allowlist is carried over.

    Raises :class:`ValueError` when a value is out of bounds; the caller is
    responsible for translating that into a failure the user can understand.
    """
    if not env:
        return {}
    bad = bad_entrypoint_env(env)
    if bad:
        raise ValueError("; ".join(bad))
    out: dict[str, str] = {}
    for key in ENV_PATH_KEYS:
        if key in env:
            out[key] = str((env_root / env[key]).resolve())
    for key in ENV_PATH_LIST_KEYS:
        if key in env:
            out[key] = ":".join(
                str((env_root / seg).resolve()) for seg in str(env[key]).split(":")
            )
    for key in ENV_PASSTHROUGH_KEYS:
        if key in env:
            out[key] = str(env[key])
    return out


# -- Paths in the dependency lock that point at the environment itself -------
# Fine-tuning frameworks are often installed as an **editable install** (`pip install -e .`),
# which leaves the **packing machine's absolute path** in the dependency lock
# (`file:///workspace/LLaMA-Factory`). That path does not exist on the rebuilding machine,
# while the framework itself travels inside the nest -- it just lands in a different
# directory. So packing replaces the environment-root segment with a token and rebuilding
# swaps it back. The byte-for-byte promise is unaffected: the tokenised lock is what lands
# in the nest and what gets verified; uv is fed a working copy (as with the wheel fallback).
ENV_ROOT_TOKEN = "__RENEST_ENV_ROOT__"


def tokenise_env_root(lock_text: str, env_root: Path) -> tuple[str, int]:
    """Replace absolute paths in the lock that point at the environment root
    with the token. Returns (new text, how many were replaced)."""
    root = str(Path(env_root).resolve()).rstrip("/")
    if not root or root == "/":
        return lock_text, 0
    n = lock_text.count(root)
    return (lock_text.replace(root, ENV_ROOT_TOKEN), n) if n else (lock_text, 0)


def resolve_env_root_token(lock_text: str, env_root: Path) -> str:
    """Rebuild end: swap the token back for this machine's rebuild root."""
    return lock_text.replace(ENV_ROOT_TOKEN, str(Path(env_root).resolve()))


# -- The home-cache root (format 2.14) ----------------------------------------
# Some nodes keep the weights they download under the home folder, not in models/:
# Hugging Face's hub cache (CLIPSeg, grounding-dino), rembg (~/.rembg), the
# transparent-background package (~/.transparent-background), insightface
# (~/.insightface). Measured on Spark 2026-10-10 against current releases.
#
# **These files never land in the restoring user's home folder by default.** They land
# inside the restore target, at ``<target>/.renest/home/<the same relative path>``, and
# the app is started with each library's own setting pointed there. Only insightface has
# no such setting (its root is a function default); its files are copied into
# ``~/.insightface`` as a separate, named step -- asked about for a handed-on nest, never
# overwriting a different file -- see :func:`home_writes`.
HOME_ROOT_DIR = ".renest/home"

#: Path prefixes a ``home`` entry may have, relative to the home folder. An allowlist:
#: anything else (``.bashrc``, ``.ssh/...``) is refused by the product and needs an
#: explicit confirmation in the escape hatch.
HOME_CACHE_PREFIXES = (".cache/huggingface/hub/", ".rembg/", ".transparent-background/",
                       ".insightface/")

#: The prefixes whose files must also be written into the real home folder, because the
#: library reading them has no setting to look elsewhere.
HOME_WRITE_PREFIXES = (".insightface/",)

#: Which setting points each library at the copy inside the restore target. Values are
#: relative to the target. TRANSPARENT_BACKGROUND_FILE_PATH names the folder that holds
#: ``.transparent-background``; REMBG_HOME the rembg data folder itself (rembg 2.0.85,
#: ``sessions/base.py``; U2NET_HOME would switch it to the old flat layout, so it is not
#: used); HF_HUB_CACHE the hub cache itself.
HOME_CACHE_ENV = (
    (".cache/huggingface/hub/", "HF_HUB_CACHE", f"{HOME_ROOT_DIR}/.cache/huggingface/hub"),
    (".rembg/", "REMBG_HOME", f"{HOME_ROOT_DIR}/.rembg"),
    (".transparent-background/", "TRANSPARENT_BACKGROUND_FILE_PATH", HOME_ROOT_DIR),
)

#: Never carried from a home cache, whatever the run did: Hugging Face keeps the
#: user's access token(s) next to the hub cache.
HOME_NEVER_CARRY = frozenset({"token", "stored_tokens"})


def carries_hf_hub(manifest: Mapping) -> bool:
    """Does this nest carry anything from a Hugging Face hub cache (either root)?"""
    for f in manifest.get("files") or []:
        if not isinstance(f, Mapping) or not isinstance(f.get("path"), str):
            continue
        if f.get("root") == "hf_hub" or (
                f.get("root") == "home" and f["path"].startswith(".cache/huggingface/hub/")):
            return True
    return False


def home_paths(manifest: Mapping) -> list[str]:
    """The ``path`` of every ``files[]`` entry under the ``home`` root."""
    return [str(f.get("path")) for f in manifest.get("files") or []
            if isinstance(f, Mapping) and f.get("root") == "home"
            and isinstance(f.get("path"), str)]


def home_cache_env(manifest: Mapping, target: Path) -> dict[str, str]:
    """The settings to start the app with so each library finds its cache inside the
    restore target: only for the caches this nest carries."""
    return {var: str(Path(target) / rel) for var, rel in home_cache_env_rel(manifest).items()}


def home_cache_env_rel(manifest: Mapping) -> dict[str, str]:
    """:func:`home_cache_env` with each value relative to the restore target -- the form
    ``renest start`` keeps in its facts file, joined again when it starts the app."""
    paths = home_paths(manifest)
    return {var: rel for prefix, var, rel in HOME_CACHE_ENV
            if any(p.startswith(prefix) for p in paths)}


def home_writes(manifest: Mapping, target: Path, home: Path) -> list[tuple[Path, Path]]:
    """``(the copy inside the target, where it goes under the home folder)`` for each file
    that must also be written into the real home folder (insightface). Allowlist-checked
    again here, on the restoring machine -- never trusting that packing did it."""
    out: list[tuple[Path, Path]] = []
    for p in home_paths(manifest):
        if bad_root_entry({"root": "home", "path": p}) is not None:
            continue
        if not p.startswith(HOME_WRITE_PREFIXES):
            continue
        out.append((Path(target) / HOME_ROOT_DIR / p, Path(home) / p))
    return out
