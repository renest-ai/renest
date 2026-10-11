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
_CODE_DIRS = frozenset({".venv", "venv", "site-packages", "bin", "Scripts"})
#: Suffixes: the file is code in itself -- a ``.py`` landing in the host app's
#: or an extension's directory runs as soon as the app imports it at startup.
#: ``.pth`` is **not** here: Python only executes ``.pth`` files that sit in a
#: site directory, which the folder rule above already refuses. Anywhere else a
#: ``.pth`` is PyTorch weights (SAM, upscalers, face models); refusing it by
#: suffix left those models out of every nest (measured 2026-10-07: a SAM
#: model a workflow loaded was dropped as "program code", and the restore could
#: not run the workflow).
_CODE_SUFFIXES = (".py", ".pyc", ".pyd")


def code_position(p: str) -> str | None:
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
    hit = _CODE_DIRS.intersection(pp.parts[:-1])
    if hit:
        return f"a path inside {sorted(hit)[0]!r}, where files get run as code, not read as data: {p!r}"
    if pp.name.endswith(_CODE_SUFFIXES):
        return f"a path that is program code, not an asset: {p!r}"
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
            return code_position(str(p))
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
