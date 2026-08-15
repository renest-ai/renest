"""Rules-data loader — the rules live in data files, not in code.

Doctor checks, the fingerprint compatibility matrix, the source playbook, trusted
hosts and world facts live in data files: a factory baseline inside the wheel (so
everything works offline), plus an optional per-user override in
``~/.renest/rules/<same file name>``, which is also where a cloud refresh lands.

Loading is fail-safe, because the escape hatch must never break. An override must
carry the same schema name and major version and pass the structural check; if any of
those fails the whole file is ignored and the built-in baseline is used (a note on
stderr, never a crash). ``restore.sh`` never reads these files.

Rules data is **not** the nest format: the manifest version does not move; each file
carries its own ``schema_version``. ``RENEST_RULES_DIR`` names an override dir.
"""

from __future__ import annotations

import json
import os
import sys
from functools import lru_cache
from pathlib import Path

__all__ = [
    "DOCTOR_RULES",
    "FINGERPRINT_MATRIX",
    "SOURCE_PLAYBOOK",
    "TRUSTED_HOSTS",
    "active_copy",
    "load_rules",
    "clear_cache",
]

DOCTOR_RULES = "doctor-rules.json"
FINGERPRINT_MATRIX = "fingerprint-matrix.json"
SOURCE_PLAYBOOK = "source-playbook.json"
TRUSTED_HOSTS = "trusted-hosts.json"
#: Facts that go stale when upstream moves (package index addresses, image
#: registries, the egress probe, the default CUDA tag, ComfyUI vocabulary). Data,
#: not code, so following upstream does not need a release.
WORLD_RULES = "world-rules.json"

_DATA_DIR = Path(__file__).resolve().parent / "data"

#: file name → (schema name, accepted schema major version)
_REGISTRY: dict[str, tuple[str, str]] = {
    DOCTOR_RULES: ("ai.renest.rules.doctor", "1"),
    FINGERPRINT_MATRIX: ("ai.renest.rules.fingerprint", "1"),
    SOURCE_PLAYBOOK: ("ai.renest.rules.sources", "1"),
    TRUSTED_HOSTS: ("ai.renest.rules.trusted-hosts", "1"),
    WORLD_RULES: ("ai.renest.rules.world", "1"),
}


def _override_dir() -> Path:
    env = os.environ.get("RENEST_RULES_DIR")
    if env:
        return Path(env)
    return Path.home() / ".renest" / "rules"


def _major(version: str) -> str:
    return str(version).split(".", 1)[0]


def _validate(name: str, data: dict) -> str | None:
    """Structural check. None means it passed; otherwise a description of the problem.

    Deliberately checks only the skeleton the engine actually reads."""
    schema, major = _REGISTRY[name]
    if data.get("schema") != schema:
        return f"schema is not {schema}"
    if _major(str(data.get("schema_version", ""))) != major:
        return f"schema_version major is not {major}"
    if name == DOCTOR_RULES:
        floors = data.get("cuda_driver_floors")
        if not isinstance(floors, dict):
            return "cuda_driver_floors is missing"
        for tag, spec in floors.items():
            f = spec.get("floor") if isinstance(spec, dict) else None
            if not (isinstance(f, list) and len(f) == 2 and all(isinstance(x, int) for x in f)):
                return f"cuda_driver_floors[{tag}].floor is not [major, minor]"
        flags = (data.get("required_cpu_flags") or {}).get("flags")
        if not (isinstance(flags, list) and all(isinstance(x, str) for x in flags)):
            return "required_cpu_flags.flags is not a list of strings"
        eg = data.get("egress") or {}
        for k in ("reject_below_mbps", "warn_below_mbps"):
            if not isinstance(eg.get(k), (int, float)):
                return f"egress.{k} is not a number"
        if not isinstance(eg.get("probe_url"), str):
            return "egress.probe_url is not a string"
    elif name == SOURCE_PLAYBOOK:
        eng = data.get("engine") or {}
        for k in ("probe_timeout_s", "read_timeout_s"):
            if not isinstance(eng.get(k), (int, float)):
                return f"engine.{k} is not a number"
        for k in ("range_workers", "single_stream_min_bytes"):
            if not isinstance(eng.get(k), int):
                return f"engine.{k} is not a whole number"
        rewrites = data.get("host_rewrites")
        if not isinstance(rewrites, list):
            return "host_rewrites is missing"
        for r in rewrites:
            if not (isinstance(r, dict) and isinstance(r.get("match_host"), str)
                    and isinstance(r.get("replace_host"), str)
                    and isinstance(r.get("regions"), list)):
                return "a host_rewrites entry is missing match_host/replace_host/regions"
    elif name == TRUSTED_HOSTS:
        hosts = data.get("hosts")
        if not (isinstance(hosts, list) and hosts and all(isinstance(x, str) and x for x in hosts)):
            return "hosts is not a non-empty list of strings"
    elif name == WORLD_RULES:
        # Only the blocks are checked, not the values inside them: a rigid check would
        # cancel out the point of the file. Hard boundaries (path-escape checks, the
        # entrypoint allow-list) deliberately do not live here.
        for block in ("package_indexes", "image_registry", "egress_probe",
                      "default_cuda_tag", "comfyui_vocab"):
            if not isinstance(data.get(block), dict):
                return f"{block} is missing or not an object"
        if not isinstance(data["comfyui_vocab"].get("model_ref_map"), dict):
            return "comfyui_vocab.model_ref_map is not an object"
    elif name == FINGERPRINT_MATRIX:
        pkgs = data.get("critical_packages")
        if not (isinstance(pkgs, list) and pkgs and all(isinstance(x, str) for x in pkgs)):
            return "critical_packages is not a non-empty list of strings"
        gpus = data.get("tested_gpus")
        if not isinstance(gpus, list):
            return "tested_gpus is missing"
        for g in gpus:
            if not (isinstance(g, dict) and isinstance(g.get("name_contains"), str)):
                return "a tested_gpus entry is missing name_contains"
    return None


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


@lru_cache(maxsize=None)
def _resolve(name: str) -> tuple[dict, str]:
    """The rules in use plus which copy won: ``"downloaded"`` or ``"built-in"``.

    A valid user override wins **unless it is older than the copy this release ships**.

    **Why the date matters** (real case, 2026-08-10): a wrong GPU-driver floor was corrected
    in the package while the last published copy still carried the wrong number. With
    "download always wins", everyone who followed our own "keep your rules fresh" prompt put
    the broken value back -- refreshing made things worse, which is the one thing a refresh
    must never do. The cloud channel exists to fix things without a release; when the release
    is the newer of the two, the release holds the newer knowledge. Newest wins, either way.

    A damaged baseline is a packaging fault and raises."""
    if name not in _REGISTRY:
        raise KeyError(f"Unknown rules file {name!r} (known ones: {sorted(_REGISTRY)})")
    builtin = _read_json(_DATA_DIR / name)
    if builtin is None or _validate(name, builtin) is not None:
        raise RuntimeError(
            f"The built-in rules file {name} is missing or damaged (packaging fault): "
            f"{_validate(name, builtin or {})}"
        )
    override_path = _override_dir() / name
    if override_path.is_file():
        data = _read_json(override_path)
        problem = "cannot read it, or it is not valid JSON" if data is None else _validate(name, data)
        if problem is None:
            here, shipped = _stamp(data), _stamp(builtin)
            if here and shipped and here < shipped:
                # Say which one won rather than choosing silently -- a refresh that quietly
                # did nothing is indistinguishable from a refresh that quietly broke you.
                print(
                    f"↻ The {name} on this machine ({here}) is older than "
                    f"the copy this version ships ({shipped}), so the built-in one is "
                    f"in use. `renest update-rules` will pick a newer one up once it is "
                    f"published.",
                    file=sys.stderr,
                )
                return builtin, "built-in"
            return data, "downloaded"  # type: ignore[return-value]
        print(
            f"⚠ Ignoring the rules override at {override_path} ({problem}); "
            "falling back to the built-in rules",
            file=sys.stderr,
        )
    return builtin, "built-in"


def load_rules(name: str) -> dict:
    """The rules in use for one file (see ``_resolve`` for which copy wins)."""
    return _resolve(name)[0]


def active_copy(name: str) -> str:
    """Which copy of this file is in use: ``"downloaded"`` or ``"built-in"``.

    Answers "did my refresh actually take effect?" without anyone having to open the
    file by hand.
    """
    return _resolve(name)[1]


def builtin_stamp(name: str) -> str:
    """The date carried by the copy shipped inside this install ("" if it carries none).

    It is what "how old is what I know" falls back to on a machine that has never
    downloaded anything -- the install-it-and-forget-it case.
    """
    return _stamp(_read_json(_DATA_DIR / name) or {})


def _stamp(rules: dict) -> str:
    """The date a rules file claims ("" if it does not say).

    Text comparison is deliberate, not lazy: the field is written ``YYYY-MM-DD``, which sorts
    correctly as text. **An undated file is not treated as old**: it cannot be compared, and
    quietly ignoring a refresh the user explicitly asked for is worse than the risk of
    honouring it -- every file we actually publish carries the date.
    """
    value = rules.get("updated")
    return value if isinstance(value, str) else ""


def clear_cache() -> None:
    """For tests: drop the load cache (call after changing RENEST_RULES_DIR)."""
    _resolve.cache_clear()
