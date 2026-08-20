"""Capture adapters for fine-tuning: kohya_ss / sd-scripts and LLaMA-Factory.

**Named frameworks only**, one adapter each: admission needs a declarative record of the
successful run that parses statically into an asset list. Arbitrary Python training
environments are out of scope — open that up and the product degrades to "backup".

**Input = the execution record of the run that worked**: one JSON file holding ``cwd``,
``argv``, ``env`` and ``verified_run``. Not "some config file", because kohya's recipe
lives half on argv and half in dataset.toml while LLaMA-Factory keeps all of it in a
YAML; only the record covers both, and it is exactly the shape of `manifest.entrypoint`.

**Never packed**: checkpoints and LoRA weights produced by training, and datasets. They
are not dropped silently — each is recorded in `entrypoint.redactions` and reported.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .capture import CAPTURE_VERSION, CaptureResult
from .roots import ROOT_PATH_PATTERNS, resolve_file_root

__all__ = ["FRAMEWORKS", "capture_training", "load_run_record"]

FRAMEWORKS = ("kohya", "llamafactory")

# Minimum usable set of the HF cache: a model repo needs only the refs/ pointers and the real
# files under snapshots/. blobs/, .locks/, trees/, .no_exist/, xet/ and CACHEDIR.TAG stay out.
# The allow-list is backstopped by the schema's pattern as well.
_SNAPSHOT_RE = re.compile(r"^snapshots/[0-9a-f]{40}/")

# Training outputs: never packed.
_OUTPUT_NAMES = (
    "adapter_model.safetensors", "trainer_log.jsonl", "trainer_state.json",
    "all_results.json", "train_results.json", "adapter_config.json",
)


def load_run_record(path: str | Path) -> dict:
    """Read a run record, doing the shape check up front (name the missing key outright)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("a run record must be a JSON object")
    argv = data.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError(
            "a run record needs \"argv\": the command you actually ran, as a list of strings"
        )
    return data


# ---------------------------------------------------------------- helpers --
def _flag(argv: list[str], name: str) -> str | None:
    """Take ``--name=value`` or ``--name value``; return None when absent (never guess)."""
    for i, a in enumerate(argv):
        if a == name and i + 1 < len(argv):
            return argv[i + 1].strip("\"'")
        if a.startswith(name + "="):
            return a.split("=", 1)[1].strip("\"'")
    return None


def _rel_to(p: Path, root: Path) -> str | None:
    """Return the path relative to ``root`` when ``p`` is inside it, otherwise None."""
    try:
        return p.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return None


def _abs_from(value: str, anchor: Path) -> Path:
    """Resolve a path out of a config, which may be absolute or relative to the config."""
    p = Path(value)
    return p if p.is_absolute() else anchor / p


def _under(parent: Path, child: Path) -> str | None:
    """``child`` expressed relative to ``parent``, or None when it is not inside it.

    Both sides go through resolve() first: one symlinked folder on either side is enough
    to make a plain string compare answer "not inside" when it is.
    """
    try:
        return child.resolve().relative_to(parent.resolve()).as_posix()
    except (ValueError, OSError):
        return None


def _keep_user_data_out(install_path: str, root: Path, user_data: list[str],
                        gaps: list[str]) -> list[str] | None:
    """Excludes that keep the user's images and training results out of a code archive.

    Neither your images nor the weights a training run produced travel with a nest.
    Both are named in the config, and the config usually sits right beside them, so
    archiving that folder wholesale sweeps them in — measured 2026-08-18: a 3.1 GB
    dataset became a 3.2 GB "code" archive while the manifest still said the data
    stayed home. Returns None when the folder *is* the data.
    """
    top = root / install_path
    out: list[str] = []
    for value in user_data:
        rel = _under(top, Path(value))
        if rel is None:
            continue
        if rel == ".":
            gaps.append(
                f"Your images or training results sit at the top of {install_path}, the same "
                f"folder your config lives in — we pack the config on its own instead of "
                f"archiving that folder, because your data never travels with the nest.")
            return None
        out.append(rel)
    return sorted(set(out))


def _license_unknown(note: str) -> dict:
    """A licence we cannot confirm always defaults to gated (deny by default)."""
    return {
        "shareable": False,
        "serving_scope": "gated",
        "tag": "unknown",
        "note": note + " We couldn't confirm its licence, so it defaults to restricted — "
                       "check it and add origin_url before you hand this off.",
    }


def repo_id_of(repo_dir: str) -> str:
    """HF cache directory name ``models--org--name`` → repo id ``org/name``."""
    return repo_dir[len("models--"):].replace("--", "/") if repo_dir.startswith("models--") else repo_dir


def _hf_repo_dir(repo_id: str) -> str:
    """``org/name`` → the directory name in the HF cache, ``models--org--name``."""
    return "models--" + repo_id.replace("/", "--")


def _collect_hf_repo(hub_root: Path, repo_dir: str, gaps: list[str]) -> list[dict]:
    """Collect one model repo by allow-list: ``refs/<branch>`` + ``snapshots/<commit>/**``.

    **refs/ is load-bearing**: without it, loading a model by repo name fails on an offline
    machine and reports itself as "couldn't connect to huggingface.co", which misdirects
    badly. When we cannot collect it we say so instead of skipping silently.
    """
    base = hub_root / repo_dir
    if not base.is_dir():
        gaps.append(
            f"The model {repo_dir.replace('models--', '').replace('--', '/')} isn't in this "
            f"machine's model cache ({base}) — nothing to pack for it. If the run really used "
            f"it, pack again on the machine that ran it."
        )
        return []
    out: list[dict] = []
    pat = ROOT_PATH_PATTERNS["hf_hub"]
    for p in sorted(base.rglob("*")):
        # **Symlinks must not be skipped**: in a real HF cache every file under snapshots/ is
        # a symlink into blobs/, so skipping them packs the 40-byte refs/ entries and not one
        # byte of the model, while pack still exits 0. Dereference on placement instead: read
        # the real bytes and write a real file. is_file() follows links and returns False on a
        # broken one, which keeps broken links out as a bonus.
        if not p.is_file():
            continue
        rel = f"{repo_dir}/{p.relative_to(base).as_posix()}"
        if not pat.match(rel):          # allow-list: blobs/ .locks/ .no_exist/ cannot get in
            continue
        kind = "other"
        name = p.name
        if _SNAPSHOT_RE.match(p.relative_to(base).as_posix()):
            if name in ("config.json", "generation_config.json"):
                kind = "model_config"
            elif name in ("tokenizer.json", "tokenizer_config.json", "vocab.json",
                          "merges.txt", "special_tokens_map.json"):
                kind = "tokenizer"
            elif name.endswith((".safetensors", ".bin", ".pt", ".pth", ".ckpt")):
                kind = "checkpoint"
        entry: dict = {
            "path": rel,
            "root": "hf_hub",
            "kind": kind,
            "license": _license_unknown(f"From the model cache ({repo_dir})."),
        }
        # What lives in the cache **has a derivable origin** (repo id + revision + file name),
        # so the user should not have to fill it in. Gated bytes never cross users: the
        # recipient gets origin_url + sha256 and fetches with their own credentials, so this
        # address is their only way through.
        rest = p.relative_to(base).as_posix()
        if rest.startswith("snapshots/"):
            _, commit, fname = rest.split("/", 2)
            entry["origin_url"] = (
                f"https://huggingface.co/{repo_id_of(repo_dir)}/resolve/{commit}/{fname}"
            )
        elif rest.startswith("refs/"):
            entry["origin_url"] = f"https://huggingface.co/{repo_id_of(repo_dir)}"
        out.append(entry)
    if not any("/refs/" in f["path"] for f in out):
        gaps.append(
            f"{repo_dir} has model files but no refs/ pointer saying which version they are. "
            f"Anything that loads the model by name will fail offline — and it reports itself "
            f"as a network error, which is very hard to work out. Pack again after a run that "
            f"worked, so the pointer is there."
        )
    return out


def _collect_accelerate(hf_home: Path, gaps: list[str]) -> list[dict]:
    """The accelerate config (measured as required for training; it lives in the home dir)."""
    d = hf_home / "accelerate"
    if not d.is_dir():
        gaps.append(
            "No accelerate config on this machine — training setups normally need one "
            "(it is written by `accelerate config`). Rebuilds may not start without it."
        )
        return []
    return [
        {
            "path": f"accelerate/{p.name}",
            "root": "hf_home",
            "kind": "runtime_config",
            "license": {"shareable": True, "serving_scope": "private", "tag": "permissive",
                        "note": "Your accelerate settings — treated as yours."},
        }
        for p in sorted(d.glob("*.yaml")) if p.is_file()
    ]


# ------------------------------------------------------------- kohya_ss ----
def _capture_kohya(rec: dict, root: Path, hub_root: Path, hf_home: Path) -> tuple[dict, dict]:
    argv = rec["argv"]
    gaps: list[str] = []
    files: list[dict] = []
    redactions: list[dict] = []
    config_files: list[str] = []
    # Paths that must never end up inside a code archive, collected as we read the run.
    # Declaring them in redactions is not enough on its own: the folder holding the config
    # is archived whole further down, and it is usually the folder holding these too.
    user_data: list[str] = []
    for flag in ("--train_data_dir", "--reg_data_dir"):
        val = _flag(argv, flag)
        if val:
            user_data.append(str(_abs_from(val, root)))

    # ---- Outputs: never packed, but accounted for honestly (never dropped silently) ----
    for flag, role in (("--output_dir", "output_dir"), ("--output_name", "output_name"),
                       ("--logging_dir", "log_dir")):
        val = _flag(argv, flag)
        if val is None:
            continue
        if flag != "--output_name":
            user_data.append(str(_abs_from(val, root)))
        idx = next((i for i, a in enumerate(argv)
                    if a == val or a.endswith("=" + val)), None)
        redactions.append({
            "locator": {"argv_index": idx if idx is not None else 0},
            "role": role,
            "placeholder": "<pick your own output folder after rebuilding>",
            "note": "This pointed at where your training results went. Results don't travel "
                    "with the nest — the recipe does.",
        })

    # ---- Base model: both homes occur in practice, so pick the root by where it lives ----
    base_model = _flag(argv, "--pretrained_model_name_or_path")
    if base_model:
        bp = Path(base_model)
        rel = _rel_to(bp, root)
        hub_rel = _rel_to(bp, hub_root)
        if rel:
            # An ordinary file the user downloaded themselves, with an extension
            files.append({"path": rel, "kind": "checkpoint",
                          "license": _license_unknown("The base model this run trained from.")})
            gaps.append(
                f"{rel}: we couldn't confirm the licence of the base model, so it defaults to "
                f"restricted — and a restricted file needs an origin_url, because that address "
                f"is the only way whoever rebuilds this can fetch it with their own account. "
                f"Add where you got it before you pack for real."
            )
        elif hub_rel:
            repo_dir = hub_rel.split("/", 1)[0]
            files.extend(_collect_hf_repo(hub_root, repo_dir, gaps))
        elif bp.exists():
            gaps.append(
                f"The base model sits outside both the folder being packed and the model cache "
                f"({bp}). Move it under the folder you're packing, or point the run at the "
                f"cached copy — we only pack from those two places."
            )
        else:
            gaps.append(f"The base model named by the run isn't on this machine: {bp}")
    else:
        gaps.append(
            "The run doesn't say which base model it trained from "
            "(no --pretrained_model_name_or_path) — nothing to pack for it."
        )

    # ---- Dataset config: the file itself is packed, the dataset it **points at** is not ----
    ds_cfg = _flag(argv, "--dataset_config")
    if ds_cfg:
        rel = _rel_to(Path(ds_cfg), root)
        if rel:
            config_files.append(rel)
            files.append({
                "path": rel, "kind": "other",
                "license": {"shareable": True, "serving_scope": "private", "tag": "permissive",
                            "note": "Your training recipe — treated as yours."},
            })
            for key, value in _toml_image_dirs(Path(ds_cfg)):
                user_data.append(str(_abs_from(value, Path(ds_cfg).parent)))
                redactions.append({
                    "locator": {"file": rel, "key": key},
                    "role": "dataset",
                    "placeholder": "<point this at your own images after rebuilding>",
                    "note": f"This pointed at your training images ({value}). Your data never "
                            f"travels with the nest.",
                })
        else:
            gaps.append(f"The dataset config sits outside the folder being packed: {ds_cfg}")

    # ---- Tokenizers downloaded only at training time (present only after a real run) ----
    for d in sorted(hub_root.glob("models--*")) if hub_root.is_dir() else []:
        if any(f["path"].startswith(d.name + "/") for f in files):
            continue
        files.extend(_collect_hf_repo(hub_root, d.name, gaps))

    files.extend(_collect_accelerate(hf_home, gaps))
    # Declare "what should exist once the run has worked", which closes the false green where
    # the exit code is 0 but not a single step trained.
    # kohya's artifact name is stated by argv: <output_dir>/<output_name>.<save_model_as>
    expect = None
    out_dir, out_name = _flag(argv, "--output_dir"), _flag(argv, "--output_name")
    if out_dir and out_name:
        rel_out = _rel_to(Path(out_dir), root)
        if rel_out:
            ext = (_flag(argv, "--save_model_as") or "safetensors").lstrip(".")
            expect = f"{rel_out}/{out_name}.{ext}"
    return ({"files": files, "redactions": redactions, "config_files": config_files,
             "expect_artifact": expect, "user_data_paths": user_data}, {"gaps": gaps})


def _toml_image_dirs(path: Path) -> list[tuple[str, str]]:
    """Find the ``image_dir`` keys in kohya's dataset TOML (key path, value).

    Standard library ``tomllib`` only, no new dependency. If it cannot be read, return
    nothing — when we cannot collect it, we skip it honestly.
    """
    try:
        import tomllib

        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    found: list[tuple[str, str]] = []
    for i, ds in enumerate(data.get("datasets", []) or []):
        for j, sub in enumerate((ds or {}).get("subsets", []) or []):
            val = (sub or {}).get("image_dir")
            if val:
                found.append((f"datasets[{i}].subsets[{j}].image_dir", str(val)))
    return found


# -------------------------------------------------------- LLaMA-Factory ----
def _is_builtin_dataset(ds: object, root: Path, rec: dict) -> bool:
    """Is the dataset named in the config one the training software ships, or the user's own?

    **The test is a fact, not a look**: a slash, or a directory that really exists, means
    the user's own; a bare name findable in ``data/dataset_info.json`` means the framework
    ships it, so it travels with the framework source and the user fills in nothing.

    An unreadable index counts as the user's own — better one question too many than
    missing something that really does need filling in.
    """
    if not isinstance(ds, str) or not ds.strip():
        return False
    name = ds.strip()
    if "/" in name or "\\" in name:
        return False
    for base in (Path(str(rec.get("cwd") or "")), root):
        if not str(base):
            continue
        if (base / name).is_dir():
            return False
        info = base / "data" / "dataset_info.json"
        if info.is_file():
            try:
                import json as _json
                if name in _json.loads(info.read_text(errors="replace")):
                    return True
            except (OSError, ValueError):
                pass
    return False


def _capture_llamafactory(rec: dict, root: Path, hub_root: Path, hf_home: Path) -> tuple[dict, dict]:
    argv = rec["argv"]
    gaps: list[str] = []
    files: list[dict] = []
    redactions: list[dict] = []
    config_files: list[str] = []
    user_data: list[str] = []   # never archived — see _keep_user_data_out

    # The whole recipe is in that YAML file (argv is minimal here)
    yaml_arg = next((a for a in argv[1:] if a.endswith((".yaml", ".yml"))), None)
    if not yaml_arg:
        gaps.append(
            "The run doesn't name a training config (no .yaml on the command line) — "
            "LLaMA-Factory keeps its whole recipe in that file, so there's nothing to read."
        )
        return {"files": files, "redactions": redactions, "config_files": config_files}, {"gaps": gaps}

    ypath = Path(yaml_arg)
    rel = _rel_to(ypath, root)
    if rel:
        config_files.append(rel)
        files.append({
            "path": rel, "kind": "other",
            "license": {"shareable": True, "serving_scope": "private", "tag": "permissive",
                        "note": "Your training recipe — treated as yours."},
        })
    else:
        gaps.append(f"The training config sits outside the folder being packed: {ypath}")

    cfg = _read_yaml(ypath)
    if cfg is None:
        gaps.append(f"Couldn't read the training config as YAML: {ypath}")
        cfg = {}

    # The base model is a **repo id**, not a path
    repo_id = cfg.get("model_name_or_path")
    if isinstance(repo_id, str) and repo_id:
        # **A model name and a path look identical** (`Qwen/Qwen2.5-0.5B-Instruct`). Treating
        # it as a path first resolves it against the working directory, lands it inside the
        # root being packed, and kills the pack with "asset file is missing" — the fetch-from-
        # cache branch below never runs. So only a file that really exists counts as a path.
        local = Path(repo_id) if Path(repo_id).is_absolute() else (root / repo_id)
        rel = _rel_to(local, root) if local.is_file() or local.is_dir() else None
        if rel:
            files.append({"path": rel, "kind": "checkpoint",
                          "license": _license_unknown("The base model this run trained from.")})
        else:
            files.extend(_collect_hf_repo(hub_root, _hf_repo_dir(repo_id), gaps))
    else:
        gaps.append("The training config doesn't say which base model to use (model_name_or_path).")

    # The output directory is **always the user's own**, so it must be called out.
    if cfg.get("output_dir") is not None:
        redactions.append({
            "locator": {"file": rel or ypath.name, "key": "output_dir"},
            "role": "output_dir",
            "placeholder": "<pick your own output folder after rebuilding>",
            "note": "This pointed at where your training results went.",
        })
    for key in ("output_dir", "dataset_dir"):
        val = cfg.get(key)
        if isinstance(val, str) and val:
            user_data.append(str(_abs_from(val, ypath.parent)))

    # Dataset: **first work out whether the training software ships it**; if it does, the user
    # fills in nothing, because it travels with the nest inside the framework source. Calling
    # every `dataset` entry "your data, point it back after restoring" is a false alarm that
    # makes people think something is missing. Telling them apart: a shipped dataset is a
    # **name** findable in the framework's dataset index, the user's own is a **path**.
    ds = cfg.get("dataset")
    if ds is not None:
        if _is_builtin_dataset(ds, root, rec):
            gaps.append(
                f"The training data named here ({ds}) ships with the framework itself, "
                f"so it travels with the nest — nothing for you to point at after rebuilding.")
        else:
            # A user dataset given as a path has to stay out of the archive as well; given as
            # a bare name it addresses something inside the framework and there is no path.
            if isinstance(ds, str) and ("/" in ds or "\\" in ds):
                user_data.append(str(_abs_from(ds, ypath.parent)))
            redactions.append({
                "locator": {"file": rel or ypath.name, "key": "dataset"},
                "role": "dataset",
                "placeholder": "<point this at your own data after rebuilding>",
                "note": "This named your training data. Your data never travels with the nest.",
            })

    # What a success should produce: without it the rebuild side has only the exit code, which
    # cannot tell "it really trained something" from "it did nothing and still exited 0".
    expect = None
    out_dir = cfg.get("output_dir")
    if isinstance(out_dir, str) and out_dir:
        # **Write nothing when the output directory is outside the nest** — a forced relative
        # path makes the rebuild side look for something it can never find, and judge a
        # success a failure.
        rel_out = _rel_to(Path(out_dir), root)
        # LoRA and the other PEFT fine-tunes always produce this file name. Full fine-tuning
        # has another shape; unrecognised means write nothing, never a made-up name.
        if rel_out and str(cfg.get("finetuning_type", "lora")).lower() in ("lora", "qlora"):
            expect = f"{rel_out}/adapter_model.safetensors"

    files.extend(_collect_accelerate(hf_home, gaps))
    return ({"files": files, "redactions": redactions, "config_files": config_files,
             "expect_artifact": expect, "user_data_paths": user_data}, {"gaps": gaps})



# **Lock selection order**: export the full list from the training environment first, rather
# than picking a requirements.txt out of a directory by file name. A framework's own
# requirements.txt is not a lock — its `-e .` line fails from any other directory, and the
# unpinned packages give a different environment, which is worse than failing to install.
# An exported list writes the editable framework as an absolute `-e file:///…` line, which
# the environment-root placeholder marker makes portable.
def _git_identity(d: Path) -> tuple[str | None, str | None]:
    """If that directory is a git checkout, read its **origin URL and revision**.

    Returns two Nones when it is not one.

    **The most important item in the compatibility contract**: without the framework's own
    revision, "upstream changed and it broke" — the most common way this line goes wrong —
    is invisible to whoever rebuilds. Unreadable leaves it empty; never invent one.
    """
    import subprocess
    def _run(*args: str) -> str | None:
        try:
            r = subprocess.run(["git", "-C", str(d), *args],  # noqa: S603, S607
                               capture_output=True, text=True, timeout=20, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        out = (r.stdout or "").strip()
        return out if r.returncode == 0 and out else None
    return _run("config", "--get", "remote.origin.url"), _run("rev-parse", "HEAD")


def _venv_dir(rec: dict) -> Path | None:
    """The venv directory of the training environment named in the run record."""
    ve = (rec.get("env") or {}).get("VIRTUAL_ENV")
    if ve and (Path(str(ve)) / "bin" / "python").is_file():
        return Path(str(ve))
    if rec.get("cwd"):
        c = Path(str(rec["cwd"])) / ".venv"
        if (c / "bin" / "python").is_file():
            return c
    return None


#: Evidence that a file looks like a lock but is not one. Any hit = it must not be used as one.
def lock_is_untrustworthy(text: str) -> list[str]:
    """What goes wrong if this file is used as a lock? Returns problems (empty = usable)."""
    problems: list[str] = []
    unpinned = []
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue
        if ln in ("-e .", "-e ./") or ln.startswith(("-e .", "--editable .")):
            problems.append(
                "one line is `-e .` (install the **current folder** as an editable package) — "
                "whoever rebuilds this isn't in that folder, so the line fails on the spot")
            continue
        if ln.startswith(("-e ", "--editable ", "-r ", "-c ", "--")):
            continue
        if "==" not in ln and "@" not in ln:
            unpinned.append(ln)
    if unpinned:
        problems.append(
            "these dependencies have no version pinned: " + ", ".join(unpinned[:6])
            + " — a rebuild installs whatever is newest that day, so **what you get is not the "
              "same environment**")
    return problems


def _venv_python_version(rec: dict, root: Path) -> str | None:
    """Ask that venv's own interpreter for its version (subprocess; never import it)."""
    import subprocess

    ve = (rec.get("env") or {}).get("VIRTUAL_ENV")
    cands = []
    if ve:
        cands.append(Path(str(ve)) / "bin" / "python")
    if rec.get("cwd"):
        cands.append(Path(str(rec["cwd"])) / ".venv" / "bin" / "python")
    for py in cands:
        if not py.is_file():
            continue
        try:
            out = subprocess.run(  # noqa: S603
                [str(py), "-c", "import sys;print('%d.%d.%d' % sys.version_info[:3])"],
                capture_output=True, text=True, timeout=20,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        v = out.stdout.strip()
        if re.match(r"^3\.\d+\.\d+$", v):
            return v
    return None


def _read_yaml(path: Path) -> dict | None:
    """Read YAML. pyyaml is not a runtime dependency: if missing, return None, never crash."""
    try:
        import yaml  # noqa: PLC0415
    except ImportError:
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


# ------------------------------------------------------------ entrypoint --
_ENV_WHITELIST = ("VIRTUAL_ENV", "CUDA_VERSION", "LD_LIBRARY_PATH",
                  "HF_HOME", "HF_HUB_CACHE", "FORCE_TORCHRUN")


def _in_venv(rel: str) -> bool:
    """Does this relative path point into a venv's bin? (venvs aren't packed: no path form.)"""
    parts = Path(rel).parts
    return any(seg in ("bin", "Scripts") for seg in parts) and any(
        seg in (".venv", "venv", "env", ".env") for seg in parts
    )


def _entrypoint(rec: dict, root: Path, redactions: list[dict], gaps: list[str],
                expect_artifact: str | None = None) -> dict:
    """Turn the run record into `entrypoint`.

    argv[0] and every path-shaped env value are **made relative to the rebuild root**: an
    absolute path in a nest is not portable, and the placement gate rejects it anyway.
    env **keeps allow-listed keys only**, and anything that cannot be carried over as it is
    gets dropped and reported — that is the credentials red line.
    """
    argv = list(rec["argv"])
    a0rel = _rel_to(Path(argv[0]), root)
    # **Things inside a venv must not be stored as a path**: the venv is deliberately left out
    # of the nest and rebuilt elsewhere from the dependency lock. So a console script inside
    # one (`…/.venv/bin/llamafactory-cli`) keeps **only its name**, and the rebuild side looks
    # it up in the venv it built. As a path it would point at a directory that never exists.
    if a0rel and _in_venv(a0rel):
        argv[0] = Path(a0rel).name
    elif a0rel:
        argv[0] = a0rel
    elif "/" in argv[0]:
        gaps.append(
            f"The command that ran ({argv[0]}) lives outside the folder being packed, so a "
            f"rebuild can't run it. Pack the folder that contains it."
        )
        argv[0] = Path(argv[0]).name       # bare name: the rebuild looks in its own venv

    # Paths in the **remaining** argv elements are made relative too, or they name places the
    # rebuilding machine does not have.
    #
    # **Relative to cwd, not to the environment root**: the process starts inside
    # `entrypoint.cwd`, so that is where its relative arguments resolve from — against the
    # environment root instead, a config at the root resolves under cwd and is not found.
    # Only paths **inside the environment root** are rewritten; the result may contain `..`,
    # which is fine for an argument (the placement gate governs placement paths, not argv).
    cwd_abs = Path(rec["cwd"]).resolve() if rec.get("cwd") else root
    for i in range(1, len(argv)):
        tok = argv[i]
        flag, sep, val = tok.partition("=")
        cand = val if sep and val.startswith("/") else (tok if tok.startswith("/") else None)
        if cand is None:
            continue
        if _rel_to(Path(cand), root) is None:
            continue                    # outside the environment root: never rewritten
        rel = os.path.relpath(Path(cand).resolve(), cwd_abs)
        argv[i] = f"{flag}={rel}" if sep else rel

    env: dict[str, str] = {}
    for k, v in (rec.get("env") or {}).items():
        if k not in _ENV_WHITELIST:
            continue                        # off-list keys: dropped silently (that's normal)
        if k in ("VIRTUAL_ENV", "HF_HOME", "HF_HUB_CACHE"):
            rel = _rel_to(Path(str(v)), root)
            if rel:
                env[k] = rel
            else:
                gaps.append(
                    f"{k} pointed outside the folder being packed ({v}), so it was left out — "
                    f"the rebuilt machine will work it out itself."
                )
        elif k == "LD_LIBRARY_PATH":
            segs = [_rel_to(Path(s), root) for s in str(v).split(":") if s]
            kept = [s for s in segs if s]
            if kept:
                env[k] = ":".join(kept)
            if len(kept) != len(segs):
                gaps.append(
                    "Some LD_LIBRARY_PATH entries pointed outside the folder being packed and "
                    "were left out — only what travels with the nest is kept."
                )
        else:
            env[k] = str(v)

    cwd = _rel_to(Path(rec["cwd"]), root) if rec.get("cwd") else None
    success: dict = {"exit_code": int((rec.get("verified_run") or {}).get("exit_code", 0))}
    if expect_artifact:
        # An exit code of 0 does not mean the run worked, so the artifact is declared in the
        # nest and the restore side checks against that rather than guessing per framework.
        # Only its expected location is recorded; the artifact itself never travels.
        success["expect_artifact"] = expect_artifact
    ep: dict = {"kind": "oneshot", "argv": argv, "success": success}
    if cwd:
        ep["cwd"] = cwd
    if env:
        ep["env"] = env
    if redactions:
        ep["redactions"] = redactions
    return ep


# ----------------------------------------------------------------- entry ---
def capture_training(
    framework: str,
    run_record: dict,
    env_root: Path,
    *,
    hub_root: Path | None = None,
    hf_home: Path | None = None,
) -> CaptureResult:
    """Statically capture a fine-tuning environment → pack-spec draft + report.

    (Same return shape as the ComfyUI side.)

    Only the record of the run that already worked is parsed; nothing is inferred or filled
    in. Whatever cannot be collected goes into ``gaps`` and is reported honestly — we never
    touch anything that has not been made to work.
    """
    if framework not in FRAMEWORKS:
        raise ValueError(f"unknown framework: {framework!r} (we support {', '.join(FRAMEWORKS)})")
    root = Path(env_root).resolve()
    hub_root = Path(hub_root) if hub_root else resolve_file_root("hf_hub", root)
    hf_home = Path(hf_home) if hf_home else resolve_file_root("hf_home", root)

    handler = {"kohya": _capture_kohya, "llamafactory": _capture_llamafactory}[framework]
    parsed, meta = handler(run_record, root, hub_root, hf_home)
    gaps: list[str] = meta["gaps"]
    files = parsed["files"]

    # ---- code_deps: the host plus the user's own code (the neutral three-way role) ----
    code_deps: list[dict] = []
    user_data: list[str] = parsed.get("user_data_paths", [])
    cwd_rel = _rel_to(Path(run_record["cwd"]), root) if run_record.get("cwd") else None
    if cwd_rel:
        host = cwd_rel.split("/", 1)[0]
        # The name list below only catches the conventional folder names. Anything the run
        # actually named — output_dir inside the framework checkout is the common one —
        # has to come off by path, or it rides along under a name nobody guessed.
        named = _keep_user_data_out(host, root, user_data, gaps) or []
        dep = {
            "name": host, "role": "host", "install_path": host,
            # Outputs and regenerables stay out of the code archive (recipe, not result)
            "exclude": sorted({"out", "outputs", "logs", "__pycache__", ".venv", "wandb",
                               *named}),
        }
        # The framework's own revision — **this is what makes "upstream changed and it broke"
        # recognisable**. Written only when it can be read.
        url, commit = _git_identity(root / host)
        if url:
            dep["repo_url"] = url
        if commit:
            dep["commit"] = commit
        else:
            gaps.append(
                f"{host} isn't a git checkout, so we can't read which version it is — "
                f"rebuilding on another machine can't confirm you got the same version of "
                f"the framework.")
        code_deps.append(dep)
    else:
        gaps.append(
            "The run record doesn't say which folder it ran in (cwd), so we can't tell which "
            "folder holds the framework itself."
        )
    # A config outside the host directory is the user's own code (measured: it is often in no
    # git repo at all, so repo_url/commit stay empty — the format makes both fields optional)
    for cfg in parsed["config_files"]:
        top = cfg.split("/", 1)[0]
        if any(d["install_path"] == top for d in code_deps) or "/" not in cfg:
            continue
        # kohya's own layout is train/dataset.toml beside train/10_name/*.png, so this is
        # the folder that swallows the user's images unless they are excluded by path.
        named = _keep_user_data_out(top, root, user_data, gaps)
        if named is None:
            continue
        code_deps.append({"name": top, "role": "user_code", "install_path": top,
                          "exclude": sorted({"__pycache__", *named})})

    ep = _entrypoint(run_record, root, parsed["redactions"], gaps,
                     expect_artifact=parsed.get("expect_artifact"))

    adapter: dict = {}
    if parsed["config_files"]:
        adapter["config_files"] = parsed["config_files"]
    if run_record.get("verified_run"):
        # An observed run (someone let Renest watch it happen) is authoritative:
        # it can carry timing/memory the file system never records.
        adapter["verified_run"] = run_record["verified_run"]
    elif parsed.get("expect_artifact"):
        # Nobody observed this run — the common case, since packing usually
        # happens well after training finished. Read the same yes/no question
        # off disk instead: an adapter file plus a step count above zero,
        # never "the process exited 0" alone (kohya prints an error and
        # still exits 0 when it cannot find its data).
        import datetime

        from .verified import training_verified_run

        ev = training_verified_run((root / parsed["expect_artifact"]).parent)
        if ev.verified and ev.artifact is not None:
            completed = datetime.datetime.fromtimestamp(
                ev.artifact.stat().st_mtime, tz=datetime.UTC
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            adapter["verified_run"] = {"completed_at": completed}

    if not adapter.get("verified_run") and not run_record.get("verified_run"):
        gaps.append(
            "No verified run was found for this: no adapter file with a positive step "
            "count sits where the recipe says it should. The nest still packs — your "
            "code, config and dependency lock travel byte-for-byte either way — it just "
            "carries no record of a finished run, and a restore will not try to re-run it."
        )

    # ---- Work out what we can rather than asking the user (same rule as infer_spec) ----
    # Lock file: look under the environment root and each host directory. When there is none,
    # **omit the whole block** and never invent a path (an environment that cannot produce a
    # lock is a real thing, and pack reports "this nest has no dependency lock" honestly).
    from .pack import LOCK_CANDIDATES

    lock_rel = None
    lock_from_env = None

    # 1. Ask that training environment itself first: fine-tuning frameworks install
    #    themselves editable into the venv, and only a full list exported from the
    #    environment both pins every version and keeps that editable line pointing at the
    #    source directory.
    venv = _venv_dir(run_record)
    if venv is not None and (venv / "bin" / "python").is_file():
        lock_from_env = str(venv / "bin" / "python")
    else:
        # 2. Fall back to finding a ready-made lock file in the environment — **but check
        #    first whether it deserves to be treated as one**.
        search_dirs = [root] + [root / d["install_path"] for d in code_deps]
        for d in search_dirs:
            hit = next((n for n in LOCK_CANDIDATES if (d / n).is_file()), None)
            if not hit:
                continue
            bad = lock_is_untrustworthy((d / hit).read_text(errors="replace"))
            if bad:
                # **Never force it through**: a requirements.txt taken as a lock kills the
                # rebuild during dependency install, and when it does install it is not the
                # same environment.
                gaps.append(
                    f"{_rel_to(d / hit, root)} looks like a lock, but using it as one causes "
                    f"problems, so it was skipped: "
                    + ";".join(bad)
                    + ". The right way is to export the full list out of that training "
                      "environment — we try that first, and only fell back to looking for a "
                      "file because we couldn't find that environment's interpreter.")
                continue
            lock_rel = _rel_to(d / hit, root)
            break
    if lock_rel is None and lock_from_env is None:
        gaps.append(
            "No dependency lock file in this environment (requirements.lock / uv.lock / "
            "requirements.txt). Without one, a rebuild installs whatever is current — "
            "which is the single most common way a rebuild stops matching."
        )

    # python version: ask the interpreter when VIRTUAL_ENV in the run record points at one,
    # otherwise leave it to be filled in
    runtime = dict(run_record.get("runtime") or {})
    if "python_version" not in runtime:
        ver = _venv_python_version(run_record, root)
        if ver:
            runtime["python_version"] = ver
    if "python_version" not in runtime:
        runtime["python_version"] = "<fill in python --version, e.g. 3.11.9>"
        gaps.append("Couldn't read the python version of that environment — fill it in by hand.")

    # **Say what we know even when we only know half of it**: a run record often knows the
    # image name but not its digest (that needs a registry lookup). Whichever key is missing
    # gets a fill-in placeholder, rather than forcing the caller to invent a fake digest.
    base_image = {
        "ref": "<fill in the image this machine actually runs>",
        "digest": "sha256:<fill in the image digest>",
    }
    base_image.update({k: v for k, v in (run_record.get("base_image") or {}).items() if v})
    # When the image name is known, **look the digest up ourselves** instead of making someone
    # copy 64 hex characters by hand.
    if str(base_image["digest"]).startswith("sha256:<") and not str(
            base_image["ref"]).startswith("<"):
        from .capture import resolve_image_digest
        got = resolve_image_digest(str(base_image["ref"]))
        if got:
            base_image["digest"] = got
        else:
            gaps.append(
                f"We know this machine runs {base_image['ref']} but could not look up its "
                f"digest (the registry did not answer, or it is not a public Docker Hub "
                f"image). Fill base_image.digest in by hand — without it this nest will not "
                f"pass `renest lint`.")
    if "ref" in base_image and str(base_image["ref"]).startswith("<"):
        gaps.append(
            "We can't tell which image this machine runs — fill base_image in by hand. "
            "Without it a rebuild has no floor to stand on."
        )

    pack_spec: dict = {
        "name": f"<give it a name, e.g. my {framework} run>",
        "base_image": base_image,
        "runtime": runtime,
        "code_deps": code_deps,
        "files": files,
        "entrypoint": ep,
        "creation": {"agent_version": CAPTURE_VERSION},
    }
    if lock_from_env:
        # pack runs one export with it and collects the result as the lock (pack.py's
        # from_environment path).
        pack_spec["python_lock"] = {"tool": "uv", "from_environment": {"python": lock_from_env}}
    elif lock_rel:
        pack_spec["python_lock"] = {"tool": "uv", "lockfile_path": lock_rel}
    if adapter:
        pack_spec["adapters"] = {framework: adapter}

    report = {
        "capture_version": CAPTURE_VERSION,
        "framework": framework,
        "files": len(files),
        "hf_cache_files": sum(1 for f in files if f.get("root") == "hf_hub"),
        "redactions": len(parsed["redactions"]),
        "config_files": parsed["config_files"],
        "needs_manual_fill": ["base_image.ref", "base_image.digest", "runtime.python_version",
                              "python_lock.lockfile_path"],
        "gaps": gaps,
    }
    return CaptureResult(pack_spec=pack_spec, report=report)
