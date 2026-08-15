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
]

FILE_ROOTS = ("env", "hf_hub", "hf_home")

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
}


def resolve_file_root(root: str, env_root: Path, env: Mapping[str, str] | None = None) -> Path:
    """Work out the real directory of a landing root.

    The resolution order follows the official HF docs (how ``HF_HOME`` and
    ``HF_HUB_CACHE`` override each other) and the wording of the accelerate
    CLI docs; ``env`` is the environment root itself, its old meaning
    unchanged to the letter.
    """
    e = os.environ if env is None else env
    if root == "hf_hub":
        if e.get("HF_HUB_CACHE"):
            return Path(e["HF_HUB_CACHE"])
        if e.get("HF_HOME"):
            return Path(e["HF_HOME"]) / "hub"
        return Path.home() / ".cache" / "huggingface" / "hub"
    if root == "hf_home":
        if e.get("HF_HOME"):
            return Path(e["HF_HOME"])
        return Path.home() / ".cache" / "huggingface"
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
#: Suffixes: the file is code in itself. ``.pth`` as above; a ``.py`` landing
#: in the host app's or an extension's directory runs as soon as the app
#: imports it at startup.
_CODE_SUFFIXES = (".py", ".pth", ".pyc", ".pyd")


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
