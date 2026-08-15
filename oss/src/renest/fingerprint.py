"""Environment fingerprint — collect the machine facts a nest carries.

These are the *functional reproducibility* fields that answer "will this nest
plausibly install here" — not "what to install", which is the manifest recipe's
job. The emitted shape conforms exactly to the frozen ``fingerprint`` block of
``manifest.schema.json``; where any prose disagrees, the schema wins.

Boundary: functional fields only — Python / torch / CUDA / OS / critical package
versions. It **never** reads a safetensors body or subject-profiling metadata
(``ss_tag_frequency`` and kin), and it does **not** record the ComfyUI core
commit, which ``code_deps[].commit`` already pins — two sources of truth for one
fact is what the schema forbids. Missing torch or OS information becomes ``None``
rather than a crash, and absent optional blocks are simply omitted.
"""

from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "FINGERPRINT_VERSION",
    "CRITICAL_PACKAGES",
    "FORBIDDEN_METADATA_KEYS",
    "TorchInfo",
    "OsInfo",
    "Fingerprint",
    "build_fingerprint",
    "build_gpu_block",
    "collect",
    "collect_gpu",
]

#: const "1", matching manifest.schema.json (fingerprint.fingerprint_version).
FINGERPRINT_VERSION = "1"

#: Known crash-prone packages (compiled / CUDA-sensitive / version-brittle). The
#: source of truth is data/fingerprint-matrix.json (critical_packages); this tuple
#: is the factory snapshot used when that data cannot be read.
CRITICAL_PACKAGES: tuple[str, ...] = (
    "torch",
    "torchvision",
    "xformers",
    "insightface",
    "onnxruntime",
    "numpy",
    "transformers",
    "diffusers",
)

#: Subject-profiling keys the fingerprint must NEVER emit or read.
#: Used by tests as a machine-check that the boundary holds.
FORBIDDEN_METADATA_KEYS: frozenset[str] = frozenset(
    {"ss_tag_frequency", "ss_dataset_dirs", "ss_bucket_info", "ss_tag_dropout"}
)

# Probe program run inside the *target* interpreter. Imports nothing that may
# be absent without guarding; a missing package is simply skipped.
_PROBE_SRC = r"""
import json, importlib.metadata as md, sys
out = {}
for name in %r:
    try:
        out[name] = md.version(name)
    except Exception:
        pass
try:
    import torch
    out["__torch_version__"] = torch.__version__
    out["__torch_cuda__"] = torch.version.cuda or ""
except Exception:
    pass
out["__python__"] = "%%d.%%d.%%d" %% sys.version_info[:3]
print(json.dumps(out))
"""


@dataclass(frozen=True)
class TorchInfo:
    version: str
    cuda_version: str | None = None

    def to_dict(self) -> dict[str, str]:
        out = {"version": self.version}
        if self.cuda_version:
            out["cuda_version"] = self.cuda_version
        return out


@dataclass(frozen=True)
class OsInfo:
    name: str
    version: str
    machine: str | None = None
    """CPU family of the machine this was packed on (format 2.3), from
    ``platform.machine()``: ``x86_64`` on most cloud hosts, ``aarch64`` on ARM.

    **Why record it**: ARM GPU instances are now sold by major clouds. Across CPU
    families the pinned wheel URLs in the lockfile and the recorded container image
    are all void, and the resulting failure **points nowhere near the real cause** —
    the user sees a package that will not install, or a shared library that will not
    load, and has no reason to suspect the chip is a different family. Reading it
    costs one call. This field only records the fact; it decides nothing on its own.
    Absent when it cannot be read (``None`` keeps it out of the manifest).
    """

    def to_dict(self) -> dict[str, str]:
        out = {"name": self.name, "version": self.version}
        if self.machine:
            out["machine"] = self.machine
        return out


@dataclass(frozen=True)
class Fingerprint:
    """Layer 1 fingerprint. Absent optional blocks are ``None`` / empty."""

    python_version: str
    torch: TorchInfo | None = None
    os: OsInfo | None = None
    critical_packages: dict[str, str] = field(default_factory=dict)
    fingerprint_version: str = FINGERPRINT_VERSION

    def to_manifest_dict(self) -> dict[str, Any]:
        """Schema-valid shape for ``manifest.fingerprint`` — omits absent
        optional blocks so it satisfies ``additionalProperties: false``."""
        out: dict[str, Any] = {
            "fingerprint_version": self.fingerprint_version,
            "python": {"version": self.python_version},
        }
        if self.torch is not None:
            out["torch"] = self.torch.to_dict()
        if self.os is not None:
            out["os"] = self.os.to_dict()
        if self.critical_packages:
            out["critical_packages"] = dict(self.critical_packages)
        return out

    def to_dict(self, *, include_absent: bool = False) -> dict[str, Any]:
        """Fingerprint as a dict. With ``include_absent`` the absent optional
        blocks are surfaced as explicit ``null`` (for doctor display / the
        absent-is-null contract) — this form is NOT the manifest shape."""
        if not include_absent:
            return self.to_manifest_dict()
        return {
            "fingerprint_version": self.fingerprint_version,
            "python": {"version": self.python_version},
            "torch": self.torch.to_dict() if self.torch is not None else None,
            "os": self.os.to_dict() if self.os is not None else None,
            "critical_packages": dict(self.critical_packages),
        }


def build_fingerprint(probe: Mapping[str, Any], os_info: OsInfo | None) -> Fingerprint:
    """Pure builder: shape a probe result + OS info into a :class:`Fingerprint`.

    ``probe`` keys: ``__python__`` (``"3.11.9"``), optional ``__torch_version__``
    / ``__torch_cuda__``, and any critical-package name → version. Absent torch
    → ``torch=None`` (recorded as null downstream), never a crash.
    """
    python_version = str(probe.get("__python__") or _current_python_version())

    torch: TorchInfo | None = None
    tv = probe.get("__torch_version__")
    if tv:
        cuda = probe.get("__torch_cuda__") or None
        torch = TorchInfo(version=str(tv), cuda_version=str(cuda) if cuda else None)

    packages = {
        str(k): str(v)
        for k, v in probe.items()
        if not str(k).startswith("__") and v is not None
    }

    return Fingerprint(
        python_version=python_version,
        torch=torch,
        os=os_info,
        critical_packages=packages,
    )


def build_gpu_block(
    smi_line: str | None,
    arch_list: list[str] | None,
    torch_facts: dict | None = None,
) -> dict[str, Any] | None:
    """Pure builder: shape nvidia-smi output + torch arch list into the
    manifest ``gpu`` block (v1.1, 03-format-restore.md §3.2.1).

    ``smi_line`` is the first CSV line of ``nvidia-smi
    --query-gpu=name,compute_cap --format=csv,noheader`` (or ``None``).
    ``arch_list`` is ``torch.cuda.get_arch_list()`` from the *target*
    interpreter (or ``None``). Unparseable / absent pieces are honestly
    omitted — never an empty shell; both absent → ``None`` (no ``gpu``
    block, still a legal manifest).

    ``min_vram_gb`` is deliberately never filled here: the packing
    machine's total VRAM is not a reliable *minimum requirement* (an 80 GB
    card can pack a nest that needs 8), and the schema keeps it optional.

    ``torch_facts`` carries what torch reported (format 2.4): how many cards,
    whether they reach each other, whether memory is shared with the system,
    and the total. Each part is written only when present — a guess would put
    a wrong flag in the archive, and a wrong flag is worse than an empty one.
    """
    gpu: dict[str, Any] = {}
    if smi_line and smi_line.strip():
        name, _, cc = smi_line.strip().partition(",")
        captured: dict[str, str] = {}
        if name.strip():
            captured["name"] = name.strip()
        sm = _sm_from_compute(cc)
        if sm:
            captured["sm_arch"] = sm
            captured["cuda_compute"] = cc.strip()
        if captured:
            gpu["captured_on"] = captured
    if arch_list:
        # get_arch_list() looks like ['sm_50','sm_80','compute_90'] — kept verbatim
        gpu["torch_cuda_arch_list"] = [str(a) for a in arch_list]
    facts = torch_facts or {}
    count = facts.get("device_count")
    if isinstance(count, int) and count >= 1:
        gpu["device_count"] = count
    # Only meaningful with more than one card; on a single card it says nothing.
    if isinstance(count, int) and count > 1 and isinstance(facts.get("peer_access"), bool):
        gpu["peer_access"] = facts["peer_access"]
    # What carries the traffic (2.5). Recorded beside the answer above, never
    # instead of it: measured on four machines, two pairs both said "yes" while
    # only one had a dedicated link -- so neither field predicts the other.
    if isinstance(count, int) and count > 1 and facts.get("peer_link") in ("nvlink", "pcie"):
        gpu["peer_link"] = facts["peer_link"]
    if isinstance(facts.get("shares_system_memory"), bool):
        gpu["shares_system_memory"] = facts["shares_system_memory"]
    total = facts.get("total_bytes")
    if isinstance(total, int) and total > 0:
        # Rounded on purpose: two hosts carrying the same card model reported
        # totals 7 MB apart, so byte-for-byte comparison makes twins look different.
        gpu["total_bytes_rounded_gib"] = round(total / 2**30)
    return gpu or None


def collect_gpu(python_path: str | None = None) -> dict[str, Any] | None:
    """Collect the manifest ``gpu`` block (torch side) from this machine.

    ``captured_on`` probes the *host* ``nvidia-smi`` (the packing machine's
    driver, not the target interpreter); ``torch_cuda_arch_list`` probes the
    target interpreter's ``torch.cuda.get_arch_list()`` — the key field for
    Blackwell-class "files match yet no kernel image" failures. No GPU / no
    tools → ``None``, and the caller omits the block entirely.
    """
    facts = dict(_probe_torch_gpu(python_path))
    link = peer_link_from_topology(_query_gpu_topology())
    if link:
        facts["peer_link"] = link
    arch = facts.get("arch_list")
    return build_gpu_block(
        _query_nvidia_smi(),
        [str(a) for a in arch] if isinstance(arch, list) and arch else None,
        facts,
    )


_WHEEL_ENV_PROBE_SRC = r"""
import json, platform, sysconfig
out = {}
tag = sysconfig.get_platform()
if tag:
    out["platform_tag"] = str(tag)
try:
    lib, ver = platform.libc_ver()
    if lib == "glibc" and ver:
        out["libc_version"] = str(ver)
except Exception:
    pass
print(json.dumps(out))
"""


def collect_wheel_env(python_path: str | None = None) -> dict[str, str]:
    """What decides whether a pre-built wheel installs: platform tag + C library.

    Returns only the parts that were actually read; ``{}`` when neither was.
    Nothing here may raise -- it is a record, not a gate.
    """
    if python_path is None:
        try:
            import platform as _p
            import sysconfig as _s

            out: dict[str, str] = {}
            tag = _s.get_platform()
            if tag:
                out["platform_tag"] = str(tag)
            lib, ver = _p.libc_ver()
            if lib == "glibc" and ver:
                out["libc_version"] = str(ver)
            return out
        except Exception:
            return {}
    try:
        result = subprocess.run(  # noqa: S603 - fixed program, caller-chosen interpreter
            [python_path, "-c", _WHEEL_ENV_PROBE_SRC],
            capture_output=True, text=True, timeout=60,
        )
        parsed = json.loads(result.stdout.strip().splitlines()[-1])
    except Exception:
        return {}
    return {str(k): str(v) for k, v in parsed.items()} if isinstance(parsed, dict) else {}


def collect(
    python_path: str | None = None,
    *,
    os_release_path: str | Path = "/etc/os-release",
) -> Fingerprint:
    """Collect this machine's Layer 1 fingerprint.

    ``python_path`` selects the interpreter to probe. ``None`` probes the
    current process in-process (fast, no subprocess); a path probes that
    interpreter via a short subprocess — packing should point it at the
    environment's own python (e.g. ``/workspace/.venv/bin/python``), else the
    fingerprint reflects the tool's env, not the nest's.
    """
    probe = _probe_in_process() if python_path is None else _probe_subprocess(python_path)
    return build_fingerprint(probe, _read_os_release(os_release_path))


# --------------------------------------------------------------------------
# IO helpers (kept thin so build_fingerprint stays pure/testable)
# --------------------------------------------------------------------------
def _current_python_version() -> str:
    return "%d.%d.%d" % sys.version_info[:3]


def _critical_packages() -> tuple[str, ...]:
    """Which packages a fingerprint records a version for: the shipped list, UNION
    whatever the rules file adds.

    **Union, not replacement** (changed 2026-08-13). A rules file narrower than the
    shipped list would silently record fewer packages -- and a fingerprint that checks
    less raises nothing, it just compares fewer things, so nobody finds out. The rules
    file may therefore widen this list but never shrink it; dropping a package needs a
    release. Same reasoning as the loader table in capture.py, and the opposite of the
    trusted-host list in wheels.py, where being able to REVOKE an entry is the point.
    """
    shipped = tuple(CRITICAL_PACKAGES)
    try:
        from .rules import FINGERPRINT_MATRIX, load_rules

        world = [str(x) for x in load_rules(FINGERPRINT_MATRIX)["critical_packages"]]
    except Exception:
        return shipped
    out = list(shipped)
    out += [w for w in world if w not in set(shipped)]
    return tuple(out)


def _probe_in_process() -> dict[str, Any]:
    import importlib.metadata as md

    out: dict[str, Any] = {}
    for name in _critical_packages():
        try:
            out[name] = md.version(name)
        except Exception:
            pass
    try:
        import torch  # type: ignore[import-not-found]

        out["__torch_version__"] = torch.__version__
        out["__torch_cuda__"] = torch.version.cuda or ""
    except Exception:
        pass
    out["__python__"] = _current_python_version()
    return out


def _probe_subprocess(python_path: str) -> dict[str, Any]:
    try:
        result = subprocess.run(  # noqa: S603 - fixed program, caller-chosen interpreter
            [python_path, "-c", _PROBE_SRC % (_critical_packages(),)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return {"__python__": ""}
    if result.returncode != 0 or not result.stdout.strip():
        return {"__python__": ""}
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {"__python__": ""}


def _sm_from_compute(cc: str) -> str | None:
    """Compute capability ``"8.6"`` → ``"sm_86"``. Returns ``None`` if unparseable."""
    cc = (cc or "").strip()
    if not re.fullmatch(r"\d+\.\d+", cc):
        return None
    return "sm_" + cc.replace(".", "")


def _query_nvidia_smi() -> str | None:
    """First CSV line of the host GPU query, or ``None`` (no driver / no GPU)."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed program and args
            ["nvidia-smi", "--query-gpu=name,compute_cap", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return result.stdout.strip().splitlines()[0]


def peer_link_from_topology(text: str | None) -> str | None:
    """What carries traffic between the cards, read off the driver's topology map.

    ``nvlink`` when any pair shows a dedicated link, ``pcie`` when pairs are on the
    host bus, ``None`` when nothing can be told. **Absent is not ``pcie``.**

    Measured on four machines: a marker like ``NV4`` between two cards means a
    dedicated link (that pair also had 12 links per card at 25 GB/s), while
    ``PHB`` / ``NODE`` / ``SYS`` are the shared bus or worse. Whether the cards can
    actually reach each other is a separate reading -- two pairs answered "yes"
    with only one of them on a dedicated link.
    """
    if not text:
        return None
    saw_bus = False
    for line in text.splitlines():
        if not line.strip().upper().startswith("GPU"):
            continue
        for cell in line.split()[1:]:
            token = cell.strip().upper()
            if _NVLINK_CELL.fullmatch(token):
                return "nvlink"
            if token in _BUS_CELLS:
                saw_bus = True
    return "pcie" if saw_bus else None


#: A dedicated-link cell is the letters NV followed by how many links are bundled.
_NVLINK_CELL = re.compile(r"NV\d+")
#: Everything else that means "not a dedicated link": host bridge, same NUMA node,
#: or across the CPU interconnect. Kept as a closed set -- an unfamiliar marker
#: must read as "cannot tell", never get rounded down to pcie.
_BUS_CELLS = frozenset({"PHB", "PXB", "NODE", "SYS"})


def _query_gpu_topology() -> str | None:
    """The driver's topology map, or ``None``. Only meaningful with several cards."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed program and args
            ["nvidia-smi", "topo", "-m"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 and result.stdout.strip() else None


#: Probe run inside the *target* interpreter for torch's compiled arch list.
#: CPU-only torch returns [] → surfaced as null (absent), never an empty shell.
_GPU_PROBE_SRC = r"""
import json
out = {}
try:
    import torch
    out["arch_list"] = list(torch.cuda.get_arch_list()) or None
    if torch.cuda.is_available():
        n = int(torch.cuda.device_count())
        out["device_count"] = n or None
        p = torch.cuda.get_device_properties(0)
        # Video memory comes from torch, never from the driver tool: on a machine
        # that shares memory with the system the tool answers "[N/A]" (measured),
        # and a newer driver answers with an English sentence instead.
        out["total_bytes"] = int(getattr(p, "total_memory", 0)) or None
        shared = getattr(p, "is_integrated", None)
        if shared is not None:
            out["shares_system_memory"] = bool(shared)
        if n > 1:
            # Two cards that cannot reach each other are not one larger pool.
            out["peer_access"] = all(
                torch.cuda.can_device_access_peer(i, j)
                for i in range(n) for j in range(n) if i != j)
except Exception:
    pass
print(json.dumps(out))
"""


def _probe_torch_gpu(python_path: str | None) -> dict:
    """Ask torch what it knows about this machine's GPUs. ``{}`` when it cannot.

    Never raises: a machine with no GPU and a machine with no torch are both
    ordinary, and neither may stop a pack.
    """
    if python_path is None:
        try:
            code = compile(_GPU_PROBE_SRC, "<gpu-probe>", "exec")
        except SyntaxError:  # pragma: no cover - the source is a literal
            return {}
        scope: dict = {}
        buf: list[str] = []
        scope["print"] = buf.append
        try:
            exec(code, scope)  # noqa: S102 - our own literal, run in-process on purpose
            return json.loads(buf[-1]) if buf else {}
        except Exception:
            return {}
    try:
        result = subprocess.run(  # noqa: S603 - fixed program, caller-chosen interpreter
            [python_path, "-c", _GPU_PROBE_SRC],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if result.returncode != 0 or not result.stdout.strip():
        return {}
    try:
        parsed = json.loads(result.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _probe_torch_arch_list(python_path: str | None) -> list[str] | None:
    """Kept for callers that only want the build-target list."""
    got = _probe_torch_gpu(python_path).get("arch_list")
    return [str(a) for a in got] if isinstance(got, list) and got else None


def _read_os_release(path: str | Path = "/etc/os-release") -> OsInfo | None:
    """Parse /etc/os-release; fall back to platform.* off-Linux.

    Returns ``None`` only if nothing usable is found (schema keeps ``os``
    optional, so callers omit it).

    **Since format 2.3 the CPU family is recorded too** (``machine``, e.g.
    ``x86_64`` / ``aarch64``) — see :class:`OsInfo`. Left empty when unreadable;
    never guessed.
    """
    machine = platform.machine() or None
    p = Path(path)
    if p.is_file():
        kv: dict[str, str] = {}
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                kv[key.strip()] = value.strip().strip('"')
        name = kv.get("NAME") or platform.system()
        version = kv.get("VERSION") or kv.get("VERSION_ID") or ""
        if version:
            return OsInfo(name=name, version=version, machine=machine)
    name = platform.system()
    version = platform.release()
    if name and version:
        return OsInfo(name=name, version=version, machine=machine)
    return None
