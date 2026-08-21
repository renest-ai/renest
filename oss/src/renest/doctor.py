"""Pre-flight check.

Two halves, both in the agent layer — the escape hatch ``restore.sh`` never
pre-checks anything, it only informs and never blocks: **host-side checks**
(driver vs container CUDA floor, CPU instruction set, egress, disk headroom)
and **fingerprint comparison** (this machine's Layer 1 fingerprint against the
nest's ``required`` one, four-level verdict). Every host-side rule came out of a
machine that failed in the field, not out of a spec; subprocess probes degrade
to ``""`` when a command is absent, so nothing here crashes off-Linux.

Exit codes (restore protocol, S0 range): 0 = match/compatible;
61 = WARNING_UNCONFIRMED; 62 = PYTHON_BLOCK; 63 = CUDA_BLOCK;
64 = ARCH_UNSUPPORTED; 65 = DISK_INSUFFICIENT; 66 = FINGERPRINT_MISSING.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import (
    ConfigError,
    Credentials,
    CredentialSource,
    resolve_credentials,
    user_config_path,
)
from .errors import ErrorClass, ExitCode
from .events import EventEmitter
from .fingerprint import Fingerprint, collect, collect_wheel_env
from .rules import DOCTOR_RULES, FINGERPRINT_MATRIX, load_rules
from .syslibs import missing_native_libs
from .uvbin import uv_executable

__all__ = [
    "LEVEL_PASS",
    "LEVEL_WARN",
    "LEVEL_REJECT",
    "CUDA_DRIVER_FLOOR",
    "CUDA_TOOLKIT_VERSIONED_PKGS",
    "REQUIRED_CPU_FLAGS",
    "X86_ARCH_NAMES",
    "check_chip_family",
    "CheckResult",
    "PrecheckReport",
    "check_driver",
    "check_cpu_flags",
    "check_egress",
    "check_lock_cuda_family",
    "lock_cuda_tags",
    "check_torch_runtime_cuda",
    "declared_cuda_tag",
    "TORCH_FAMILY",
    "check_lock_cuda_vs_driver",
    "lock_cuda_majors",
    "check_disk",
    "run_precheck",
    "collect_gpu_name",
    "collect_gpu_compute_cap",
    "check_gpu_arch",
    "split_arch_list",
    "gpu_coverage",
    "FingerprintVerdict",
    "compare_fingerprint",
    "doctor",
]

LEVEL_PASS = "pass"
LEVEL_WARN = "warn"
LEVEL_REJECT = "reject"

# The real source of these thresholds is data/doctor-rules.json (a built-in
# factory baseline, overridable from the user's config directory, see rules.py).
# The module constants below are a snapshot of that baseline, kept only as
# defaults for the pure functions and as anchors for test assertions; the engine
# path reads the data through run_precheck.

#: Fallback floors, used only when the rules file cannot be read. **It deliberately does
#: not match the rules file; see the guard test before "tidying" that away.** Two runs
#: disagree: 535.154.05 ran a cu128 wheel fine (2026-08-10), while 545.23 on cu124 died
#: with Error 803 (2026-07-15). Wheels carry their own CUDA runtime and a full toolkit
#: image does not -- but no run has settled that, so it stays a guess. The fallback keeps
#: the higher number on purpose: with the rules unreadable, refusing a machine that would
#: have worked costs one rental; admitting one that dies costs a whole restore.
CUDA_DRIVER_FLOOR: dict[str, tuple[int, int]] = {
    "cu124": (550, 54),
}

# measured: a host without avx2 killed the application with "Illegal instruction"
REQUIRED_CPU_FLAGS: tuple[str, ...] = ("avx2",)

#: Which checks still mean something when **no nest was given**. The rest need
#: something from the nest -- which CUDA release to compare the driver against,
#: which directory to write into -- and running them anyway invents failures:
#: measured on a laptop with no NVIDIA card, `renest doctor` on its own reported
#: "cannot read the driver" and "cannot write into /" and refused the machine.
#: That is this repository's most expensive class of bug (2026-08-08, five in one
#: day): **"I don't recognise this, so it must be broken."** Without a nest these
#: are notes, never a verdict -- unfit *for what*, when nothing was named?
_NEST_FREE_CHECKS: frozenset[str] = frozenset({"cpu_flags", "local_disk", "ram", "egress"})

#: Names of the Intel/AMD chip family — every spelling ``platform.machine()``
#: uses for it across systems.
#:
#: This table has to exist because ``REQUIRED_CPU_FLAGS`` above lists
#: **instruction-set names only Intel/AMD chips have**. On any other family
#: their absence means "the question does not apply", not "this machine is too
#: old" — an ARM host happily running ComfyUI was once failed by this gate and
#: told to rent a different machine, which hard-fails restore at its first step.
def _chip_family(machine: str | None) -> str:
    """Fold every spelling of ``platform.machine()`` into two families.

    Returns an empty string when the name is not recognised (= we don't know).
    The two names are the plain-language ones, ``Intel/AMD`` and ``ARM``: they
    end up in messages users read, which is no place for engineer-only spellings
    like ``x86_64`` / ``aarch64``.
    """
    m = (machine or "").strip().lower()
    if not m:
        return ""
    if m in X86_ARCH_NAMES:
        return "Intel/AMD"
    if m in {"aarch64", "arm64", "armv8l", "armv7l"}:
        return "ARM"
    return ""


X86_ARCH_NAMES: frozenset[str] = frozenset(
    {"x86_64", "amd64", "x86", "i386", "i486", "i586", "i686"}
)

EGRESS_REJECT_MBPS = 20.0  # same threshold as the harness 30s fast-fail gate
EGRESS_WARN_MBPS = 100.0

#: The probe used to measure download speed. **It is a link to one specific
#: release**, so the day that release is deleted the speed check **fails
#: silently** — an unmeasurable link is simply skipped, and nobody notices.
#: That is why the source of truth lives in the rules data (``egress.probe_url``
#: in the doctor rules, and ``egress_probe`` in the world rules); the value here
#: is only the factory fallback for when that data cannot be read.
EGRESS_PROBE_URL = (
    "https://github.com/peak/s5cmd/releases/download/v2.2.2/s5cmd_2.2.2_Linux-64bit.tar.gz"
)

#: Which CUDA release to assume when the dependency list carries no CUDA tag.
#: **Assuming the oldest one is the conservative choice** — it demands the
#: lowest driver version and so never fails a good machine — but it also means
#: newer environments do not get the check they deserve. This default **moves as
#: the ecosystem moves**, which makes it a fact about the world rather than a
#: design decision of ours: the source of truth is the world rules
#: (``default_cuda_tag.value``), and the value here is the factory fallback.
DEFAULT_CUDA_TAG = "cu124"


def default_cuda_tag() -> str:
    """Fall back to the factory value when the rules cannot be read.

    Broken rules data must never make the pre-flight check itself crash.
    """
    try:
        from .rules import WORLD_RULES, load_rules as _lr

        return str((_lr(WORLD_RULES).get("default_cuda_tag") or {}).get("value")) or DEFAULT_CUDA_TAG
    except Exception:  # noqa: BLE001
        return DEFAULT_CUDA_TAG


def _doctor_rules() -> tuple[dict[str, tuple[int, int]], tuple[str, ...], dict]:
    """Read (floors, cpu_flags, egress) from the rules data.

    If that data is broken, rules.py falls back to the factory baseline for us.
    """
    r = load_rules(DOCTOR_RULES)
    floors = {tag: tuple(spec["floor"]) for tag, spec in r["cuda_driver_floors"].items()}
    flags = tuple(r["required_cpu_flags"]["flags"])
    return floors, flags, r["egress"]

#: precheck check name -> S0 error_class it rejects into (shared with restore).
PRECHECK_CLASS: dict[str, ErrorClass] = {
    "driver": ErrorClass.CUDA_BLOCK,
    "cpu_flags": ErrorClass.ARCH_UNSUPPORTED,
    # Wrong chip family: Python packages are built per chip family, one build
    # each. That belongs to the same class as "this card is too new" — things
    # this machine simply cannot install — so it shares the error code.
    "chip_family": ErrorClass.ARCH_UNSUPPORTED,
    "gpu_arch": ErrorClass.ARCH_UNSUPPORTED,
    "disk": ErrorClass.DISK_INSUFFICIENT,
    # "the free-space figure said yes, the disk itself said no" — same class as no room,
    # because that is what it is; the reason (a quota the figure cannot see) is in the text.
    "writable": ErrorClass.DISK_INSUFFICIENT,
    "egress": ErrorClass.UNKNOWN,
    # This one used to be UNKNOWN. Back when the check could only warn, nobody
    # had to decide which code a rejection should carry; once it was raised to a
    # hard block it started landing in the "unclassified" bucket (60), even
    # though it is plainly a CUDA block. A test caught it on the spot.
    "lock_cuda_family": ErrorClass.CUDA_BLOCK,
    "torch_runtime_cuda": ErrorClass.CUDA_BLOCK,
    "lock_cuda_vs_driver": ErrorClass.CUDA_BLOCK,
}


# --------------------------------------------------------------------------
# Host checks
# --------------------------------------------------------------------------
@dataclass
class CheckResult:
    name: str
    level: str  # pass / warn / reject
    reason: str
    reading: dict  # raw readings — record too much rather than too little


@dataclass
class PrecheckReport:
    """Per-check verdicts + overall level. ``force`` only flips ``proceed``;
    it never launders ``overall``."""

    checks: list[CheckResult] = field(default_factory=list)
    forced: bool = False

    @property
    def overall(self) -> str:
        levels = {c.level for c in self.checks}
        if LEVEL_REJECT in levels:
            return "reject"
        if LEVEL_WARN in levels:
            return "warn"
        return "ok"

    @property
    def proceed(self) -> bool:
        return self.overall != "reject" or self.forced

    def to_dict(self) -> dict:
        return {
            "overall": self.overall,
            "forced": self.forced,
            "proceed": self.proceed,
            "checks": [asdict(c) for c in self.checks],
        }


def _parse_driver(driver_version: str) -> tuple[int, int] | None:
    parts = driver_version.strip().split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        return (major, minor)
    except (ValueError, IndexError):
        return None


def check_driver(
    driver_version: str,
    cuda_tag: str | None = None,
    expected_driver: str | None = None,
    floors: dict[str, tuple[int, int]] = CUDA_DRIVER_FLOOR,
) -> CheckResult:
    """Host driver vs container CUDA floor table.

    Below floor = reject (major CUDA mismatch, the measured Error 803 case);
    meets floor but differs from the nest's declared driver = warning
    (minor mismatch, nest stays tagged unverified)."""
    # No tag given: use the current default. That default is a fact about the
    # world and moves as the ecosystem moves, so it comes from the rules data
    # rather than being hardcoded here.
    cuda_tag = cuda_tag or default_cuda_tag()
    got_raw = driver_version.strip()
    reading: dict = {"driver_version": got_raw, "cuda_tag": cuda_tag}
    floor = floors.get(cuda_tag)
    if floor is None:
        return CheckResult(
            "driver",
            LEVEL_WARN,
            f"No driver floor is listed for {cuda_tag}, so we can't check it — "
            f"treating this machine as unverified.",
            reading,
        )
    reading["floor"] = f"{floor[0]}.{floor[1]}"
    got = _parse_driver(got_raw)
    if got is None:
        return CheckResult(
            "driver",
            LEVEL_REJECT,
            f"Can't read this machine's GPU driver version ({got_raw!r}) — "
            f"failing safe and calling it unfit. Check that nvidia-smi works here.",
            reading,
        )
    if got < floor:
        return CheckResult(
            "driver",
            LEVEL_REJECT,
            f"This machine's GPU driver {got_raw} is older than the "
            f"{floor[0]}.{floor[1]} that {cuda_tag} needs (major CUDA mismatch — "
            f"torch dies with Error 803). Rent a machine with a newer driver, "
            f"or pass --force to go ahead anyway.",
            reading,
        )
    if expected_driver and expected_driver.strip() != got_raw:
        reading["expected_driver"] = expected_driver.strip()
        return CheckResult(
            "driver",
            LEVEL_WARN,
            f"Driver {got_raw} clears the floor but differs from the "
            f"{expected_driver.strip()} this nest was packed on (minor mismatch). "
            f"The nest stays marked unverified until you run the workflow here "
            f"and the picture comes out right.",
            reading,
        )
    return CheckResult(
        "driver",
        LEVEL_PASS,
        f"Driver {got_raw} meets the {cuda_tag} floor of {floor[0]}.{floor[1]}",
        reading,
    )


def check_cpu_flags(
    cpu_flags_text: str,
    required: tuple[str, ...] = REQUIRED_CPU_FLAGS,
    *,
    arch: str = "x86_64",
) -> CheckResult:
    """CPU instruction set verdict. Input = full lscpu / flags line.

    ``arch`` is this machine's chip family, taken verbatim from
    ``platform.machine()`` (``x86_64`` on Intel/AMD machines, ``aarch64`` on ARM
    ones). **The default is hardcoded to x86_64 instead of probed here**: this
    is a pure function, and its answer must not shift with whichever machine
    happens to be running the tests today. The real architecture is passed in
    by :func:`run_precheck`.
    """
    tokens = set(re.findall(r"[a-z0-9_]+", cpu_flags_text.lower()))
    reading = {"required": list(required), "arch": arch}
    known_arch = arch.strip().lower()
    # **When the architecture cannot be read, still run the check — never wave
    # it through**: ``platform.machine()`` returns an empty string when it
    # fails, and the "skip this check entirely" path is meant only for machines
    # **confirmed not to be Intel/AMD**. Without this ``and``, an old Intel
    # machine missing avx2 would flip from rejected to accepted the moment
    # architecture detection failed — and that is precisely the machine this
    # gate was built to stop (measured: it dies with "Illegal instruction").
    if known_arch and known_arch not in X86_ARCH_NAMES:
        # Not an Intel/AMD chip: these instruction-set names mean nothing here,
        # so the whole check is skipped (reasoning above X86_ARCH_NAMES).
        # **Passing here does not mean "this nest will install on this
        # machine"** — which chip family a nest was packed for is a separate
        # question, answered by the chip-family check below.
        return CheckResult(
            "cpu_flags",
            LEVEL_PASS,
            f"This machine's CPU is {arch}, not an Intel/AMD one. The "
            f"{' '.join(required)} requirement names Intel/AMD-only instructions, "
            f"so it does not apply here.",
            reading,
        )
    if not cpu_flags_text.strip():
        return CheckResult(
            "cpu_flags",
            LEVEL_REJECT,
            "Can't read this machine's CPU features (empty output) — "
            "failing safe and calling it unfit.",
            reading,
        )
    missing = [f for f in required if f not in tokens]
    reading["missing"] = missing
    if missing:
        return CheckResult(
            "cpu_flags",
            LEVEL_REJECT,
            f"This machine's CPU is missing {' '.join(missing)} — torch and kornia "
            f"need it, and ComfyUI dies with 'Illegal instruction' the moment it "
            f"starts. Rent a different machine.",
            reading,
        )
    return CheckResult(
        "cpu_flags",
        LEVEL_PASS,
        f"CPU has everything needed ({' '.join(required)})",
        reading,
    )


#: The two forms GPU compute code takes inside a package — the distinction is
#: the whole point of this gate. ``sm_90`` is **finished goods**: machine code
#: compiled for exactly that one GPU generation. ``compute_90`` is
#: **half-finished** (the industry calls it PTX): the driver can compile it on
#: the spot for a newer card, which is the only way a package older than the
#: card still works. Never conflate the two — stripping non-digits turns both
#: into 90, which hides whether a package ships the half-finished form at all,
#: and that blind spot is exactly what this pair of prefixes exists to remove.
_PTX_PREFIX = "compute_"
_BINARY_PREFIX = "sm_"


def _arch_num(tag: str) -> int | None:
    """``sm_90`` / ``compute_90`` / ``8.9`` → 90 / 90 / 89. None if unreadable."""
    digits = "".join(ch for ch in str(tag) if ch.isdigit())
    return int(digits) if digits else None


def split_arch_list(arch_list: list[str] | None) -> tuple[list[int], list[int]]:
    """Split ``torch.cuda.get_arch_list()`` into (finished, half-finished).

    Both halves come back as lists of numbers. **Never merge them back into one
    list** — merging them is exactly the blind spot this split was created to
    remove: it hides whether a package ships the half-finished form at all.
    """
    binaries: list[int] = []
    ptx: list[int] = []
    for tag in arch_list or []:
        s = str(tag).strip().lower()
        n = _arch_num(s)
        if n is None:
            continue
        if s.startswith(_PTX_PREFIX):
            ptx.append(n)
        elif s.startswith(_BINARY_PREFIX):
            binaries.append(n)
    return sorted(set(binaries)), sorted(set(ptx))


def check_gpu_arch(
    current_compute_cap: str,
    torch_cuda_arch_list: list[str] | None,
    captured_name: str | None = None,
) -> CheckResult:
    """Does this machine's GPU match the generations the nest's torch was built for?

    **Blocking-level, not advisory.** The escape hatch may only ever inform, so
    it prints one warning line and carries on; the agent layer is the only place
    a machine can actually be refused.

    Field evidence (an RTX 5090): the torch in the nest was built only up to
    sm_90 while the card is sm_120. **Every file matched byte for byte and it
    crashed the moment it ran**: ``no kernel image is available for execution on
    the device``.

    Grading:
    * this card's generation is in the finished-goods list → pass;
    * not in the list but below the highest finished entry → pass (measured to
      run; the first image may be slightly slower);
    * **above the highest finished entry → reject**, ``--force`` goes past it.
      Shipping the half-finished form (PTX) does not change today's verdict, but
      both cases land in ``reading`` so the split can later be revisited on data.
    """
    reading: dict = {
        "current_compute_cap": current_compute_cap,
        "torch_cuda_arch_list": list(torch_cuda_arch_list or []),
    }
    if captured_name:
        reading["captured_on"] = captured_name
    binaries, ptx = split_arch_list(torch_cuda_arch_list)
    reading["binary_archs"] = binaries
    reading["ptx_archs"] = ptx
    reading["ships_ptx"] = bool(ptx)
    have = _arch_num(current_compute_cap)
    reading["current_sm"] = have

    if not binaries and not ptx or have is None:
        return CheckResult(
            "gpu_arch", LEVEL_WARN,
            "This nest records no torch build targets, or this machine's GPU could not be read — "
            "nothing to compare, treating as unverified",
            reading)

    top_binary = max(binaries) if binaries else None
    top_ptx = max(ptx) if ptx else None
    reading["max_binary_arch"] = top_binary
    reading["max_ptx_arch"] = top_ptx

    if have in binaries:
        return CheckResult(
            "gpu_arch", LEVEL_PASS,
            f"This GPU (sm_{have}) is one this nest's torch was built for. Good match.",
            reading)
    if top_binary is not None and have < top_binary:
        return CheckResult(
            "gpu_arch", LEVEL_PASS,
            f"This GPU (sm_{have}) is not a prebuilt target but sits below the highest one "
            f"(sm_{top_binary}), so it should run. Your first image may be slower.",
            reading)

    # Within one GPU generation, **a newer card runs the older finished machine
    # code of that same generation** (NVIDIA's binary compatibility rule:
    # backward compatible inside a major number, incompatible across major
    # numbers). Without this branch the case is misjudged as "card too new".
    # Measured: an sm_121 card on a PyTorch built only up to sm_120, with no PTX
    # in libtorch_cuda.so at all, ran matrix multiplies and cuDNN convolutions
    # correctly. Cross-generation is still rejected below — the RTX 5090 case
    # was sm_120 against an sm_90 build, and 9 to 12 crosses the boundary.
    same_family = sorted(b for b in binaries if b // 10 == have // 10 and b <= have)
    if same_family:
        reading["same_family_binary_archs"] = same_family
        return CheckResult(
            "gpu_arch", LEVEL_PASS,
            f"This GPU (sm_{have}) is newer than the highest prebuilt target "
            f"(sm_{top_binary}), but sm_{same_family[-1]} is the same GPU generation "
            f"and newer cards in a generation run the older code of that generation. "
            f"It should run.",
            reading)

    where = f" (packed on {captured_name})" if captured_name else ""
    ceiling = top_binary if top_binary is not None else top_ptx
    if ptx:
        return CheckResult(
            "gpu_arch", LEVEL_REJECT,
            f"This GPU (sm_{have}) is newer than the highest one this nest's torch was built "
            f"for (sm_{ceiling}){where}. The nest does carry a forward-compatible form "
            f"(PTX up to compute_{top_ptx}), so the driver might be able to compile for this "
            f"card — but we have never measured that, and compiled plugin extensions usually "
            f"carry no PTX at all, so it can still fail later. Refusing by default; "
            f"--force goes ahead anyway.",
            reading)
    return CheckResult(
        "gpu_arch", LEVEL_REJECT,
        f"This GPU (sm_{have}) is newer than the highest one this nest's torch was built for "
        f"(sm_{ceiling}){where}, and the nest carries no forward-compatible form (no PTX at all) "
        f"— there is literally nothing here this card can run. Every file will match byte for "
        f"byte and it still will not start. Use a card at sm_{ceiling} or older, or pack a fresh "
        f"nest on a card of this generation. --force goes ahead anyway.",
        reading)


def check_egress(
    mbps: float,
    reject_below: float = EGRESS_REJECT_MBPS,
    warn_below: float = EGRESS_WARN_MBPS,
) -> CheckResult:
    """Host egress health. Input = measured Mbps."""
    reading = {
        "mbps": round(mbps, 1),
        "reject_below": reject_below,
        "warn_below": warn_below,
    }
    if mbps < reject_below:
        return CheckResult(
            "egress",
            LEVEL_REJECT,
            f"This machine downloads at {mbps:.1f} Mbps, under the "
            f"{reject_below:.0f} Mbps floor. A machine that boots isn't always a "
            f"machine that works — stop here and rent another one.",
            reading,
        )
    if mbps < warn_below:
        return CheckResult(
            "egress",
            LEVEL_WARN,
            f"This machine downloads at {mbps:.1f} Mbps, on the slow side "
            f"(under {warn_below:.0f}). Big model files will take a while, and "
            f"the nest stays marked unverified.",
            reading,
        )
    return CheckResult(
        "egress", LEVEL_PASS, f"Downloads at {mbps:.0f} Mbps — healthy", reading
    )


# --------------------------------------------------------------------------
# The CUDA line inside the lockfile
# --------------------------------------------------------------------------
# An environment can only have one CUDA line, and **both ways of getting this
# wrong report something unrelated to the cause**: torch on cu124 with
# torchaudio on CUDA 13 gives ``OSError: libcudart.so.13``; a whole lock on
# CUDA 13 against a 12.4 driver gives "Your setup doesn't support bf16/gpu",
# which reads like an old card. Thresholds are data (data/doctor-rules.json).
_NVIDIA_PKG = re.compile(
    r"^\s*(?:[-\s]*[\"']?)?(nvidia-[a-z0-9._-]*?)(?:-cu(\d+))?\s*==\s*(\d+)",
    re.IGNORECASE | re.MULTILINE,
)


#: The fallback "read the leading version number as the CUDA generation" applies
#: **only** to packages whose version tracks the CUDA toolkit — hence this
#: allowlist. Several NVIDIA libraries version independently: in a healthy CUDA
#: 13 environment cuFILE is 1.15.1.6 and cuRAND is 10.4.0.35, which the old
#: fallback read as generations 1 and 10 and blocked as "mixed generations".
#: Every user hits this, because CUDA 13 dropped the ``-cuNN`` suffix from these
#: names. A suffixless package missing from this table takes **no part** in the
#: verdict — missing a rare real mix beats blocking a healthy environment.
CUDA_TOOLKIT_VERSIONED_PKGS: frozenset[str] = frozenset(
    {
        "nvidia-cublas",
        "nvidia-cuda-cupti",
        "nvidia-cuda-nvcc",
        "nvidia-cuda-nvrtc",
        "nvidia-cuda-runtime",
        "nvidia-cuda-sanitizer-api",
        "nvidia-nvjitlink",
        "nvidia-nvtx",
    }
)


#: The torch family writes its CUDA line into the **version suffix**:
#: ``torch==2.6.0+cu124``.
_LOCAL_CUDA_TAG = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*==\s*[^\s#]*\+cu(\d+)", re.IGNORECASE)
#: Once pinned to a direct URL, that line moves into the **path segment**:
#: ``.../whl/cu124/torch-2.6.0%2Bcu124-...``.
_URL_CUDA_TAG = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*@\s*https?://\S*?/cu(\d+)/", re.IGNORECASE)


def lock_cuda_tags(lock_text: str) -> dict[str, str]:
    """The **full CUDA tag** of every CUDA-bound package in the lockfile.

    Returns ``{package name: tag}``, e.g. ``124``.

    **All four spellings must be recognised**; missing one is the same as not
    checking at all:

    1. ``nvidia-cudnn-cu12==9.1.0`` — tag in the ``-cu12`` suffix of the name;
    2. ``nvidia-cuda-runtime==13.0.96`` — tag in the major of the version;
    3. ``torch==2.6.0+cu124`` — the torch family's spelling, version suffix;
    4. ``torch @ https://.../whl/cu124/torch-...whl`` — pinned to a direct URL,
       tag in the path segment.

    The last two are not optional. The first two only match ``nvidia-*``, which
    are runtime dependencies torch drags in — the shadow, not the body — so they
    can miss a disagreement between the three real packages, and on another
    platform they may be absent entirely, leaving a check that finds nothing and
    reports "pass". Seen on a real nest: 13 shadow packages matched, none of the
    three real ones did.
    """
    out: dict[str, str] = {}
    for raw in lock_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        bare = line.lstrip("-").strip().strip("\"'")
        m = _NVIDIA_PKG.match(bare)
        if m:
            name, suffix, ver_major = m.group(1), m.group(2), m.group(3)
            if suffix:
                out[f"{name}-cu{suffix}"] = suffix
            elif name.lower() in CUDA_TOOLKIT_VERSIONED_PKGS:
                out[name] = ver_major
            # No suffix in the name and not in the allowlist: its version number
            # is its own, not a CUDA generation, so the package takes no part in
            # the verdict (reasoning above CUDA_TOOLKIT_VERSIONED_PKGS).
            continue
        for rx in (_LOCAL_CUDA_TAG, _URL_CUDA_TAG):
            m = rx.match(bare)
            if m:
                out[m.group(1).lower()] = m.group(2)
                break
    return out


def lock_cuda_majors(lock_text: str) -> dict[str, str]:
    """As above, but returning only the **CUDA major** (``124`` -> ``12``).

    **The contract has not changed**: this name has always meant "major". The
    other check that uses it (lock vs driver) compares by major, so changing it
    breaks that one too — an attempt to make this return the full tag broke that
    check immediately.
    """
    return {k: _cuda_major(v) for k, v in lock_cuda_tags(lock_text).items()}


#: The three torch packages are **one atomic unit**: same version, same CUDA
#: tag, installed together. Pin one and leave another loose and the loose one
#: resolves to a different build, which surfaces at runtime as a missing-library
#: error that points nowhere near the real cause (seen on a real machine).
TORCH_FAMILY = ("torch", "torchvision", "torchaudio")


def _cuda_major(tag: str) -> str:
    """``124`` -> ``12``; ``13`` / ``130`` -> ``13``."""
    return tag[:2] if len(tag) >= 3 else tag


def declared_cuda_tag(lock_text: str) -> str | None:
    """The CUDA tag the nest declares, e.g. ``124``.

    Taken from the torch packages themselves, not from the shadow packages.
    """
    tags = {k: v for k, v in lock_cuda_tags(lock_text).items() if k in TORCH_FAMILY}
    vals = set(tags.values())
    return next(iter(vals)) if len(vals) == 1 else None


def check_torch_runtime_cuda(installed_cuda: str | None, declared_tag: str | None) -> CheckResult:
    """**Ask torch itself**: does the CUDA version it reports after installation
    match the one the nest declares?

    Why checking the lockfile alone is not enough: a lockfile states "what I
    intend to install", and **what ends up installed is a separate question**.
    A pinned URL that stops working and falls back to the generic build,
    another package overriding it, a version preinstalled in the base image
    cutting in — any of these leaves the installed build different from the
    declared one, and **the lockfile does not change by a single character**.

    ``installed_cuda`` is the raw ``torch.version.cuda`` (like ``12.4``);
    ``declared_tag`` is the nest's tag for that family (like ``124``).
    """
    reading = {"torch_version_cuda": installed_cuda, "declared_tag": declared_tag}
    if not declared_tag:
        return CheckResult("torch_runtime_cuda", LEVEL_PASS,
                           "This nest declares no CUDA build for torch — nothing to compare",
                           reading)
    if installed_cuda is None:
        # **"could not ask" and "asked and got nothing back" are two different
        # things — never conflate them** (a test caught this): there is simply
        # no torch installed here, which is legitimate since not every nest uses
        # torch, so the probe could not run at all. Nothing to compare, pass.
        # The branch below is the other case: torch **is** installed and says of
        # itself that it carries no CUDA — that one is a real problem.
        return CheckResult(
            "torch_runtime_cuda", LEVEL_PASS,
            "This environment has no torch to ask — nothing to compare", reading)
    if not installed_cuda:
        return CheckResult(
            "torch_runtime_cuda", LEVEL_REJECT,
            f"This nest was packed against CUDA cu{declared_tag}, but the rebuilt environment's "
            f"torch does not report a CUDA build at all (it may be the CPU-only wheel). "
            f"Training will fail later with an error that does not mention this. --force goes ahead anyway.",
            reading)
    got = installed_cuda.replace(".", "")
    if got != declared_tag:
        return CheckResult(
            "torch_runtime_cuda", LEVEL_REJECT,
            f"This nest was packed against CUDA cu{declared_tag}, but the torch that actually "
            f"got installed reports CUDA {installed_cuda}. Something replaced it between packing "
            f"and here — a pinned download that went away, or a version the base image already "
            f"had. The lockfile still says cu{declared_tag}, so nothing else will tell you. --force goes ahead anyway.",
            reading)
    return CheckResult("torch_runtime_cuda", LEVEL_PASS,
                       f"The rebuilt torch reports CUDA {installed_cuda}, matching the nest",
                       reading)


def check_lock_cuda_family(lock_text: str) -> CheckResult:
    """Are all CUDA-bound packages in the lock on one and the same CUDA line?

    Measured on a real machine: a mixed lock always blows up, and the error it
    produces points nowhere near the real cause.
    """
    tags = lock_cuda_tags(lock_text)
    reading: dict = {"cuda_packages": tags}
    majors = {k: _cuda_major(v) for k, v in tags.items()}
    fam = {k: v for k, v in tags.items() if k in TORCH_FAMILY}
    reading["torch_family"] = fam

    # The order matters: **report the most serious one first**.
    # (1) Two CUDA majors mixed in a single environment — the most common and
    #     the most fatal, so it is reported first.
    if len(set(majors.values())) > 1:
        groups: dict[str, list[str]] = {}
        for pkg, major in sorted(majors.items()):
            groups.setdefault(major, []).append(pkg)
        detail = "; ".join(f"CUDA {k}: {', '.join(v)}" for k, v in sorted(groups.items()))
        return CheckResult(
            "lock_cuda_family",
            LEVEL_REJECT,
            f"This lockfile mixes two CUDA releases in one environment ({detail}). "
            f"They cannot both load: whichever one loses, you get a missing-library error "
            f"naming a file you never asked for, and nothing points at the real cause. "
            f"It usually happens when one package was pinned by hand and the rest came from "
            f"the default index — pin the whole family from the same index and pack again. --force goes ahead anyway.",
            reading,
        )

    # (2) Same major, but the three torch packages disagree on the **exact**
    #     tag (cu124 and cu126 are both 12, so they look like one line, and
    #     installed together they blow up all the same).
    if len(set(fam.values())) > 1:
        detail = "; ".join(f"{k}: cu{v}" for k, v in sorted(fam.items()))
        return CheckResult(
            "lock_cuda_family",
            LEVEL_REJECT,
            f"torch, torchvision and torchaudio must be the same build, and here they are not "
            f"({detail}). They load one shared CUDA runtime between them: whichever one loses, "
            f"you get a missing-library error naming a file you never asked for, and nothing "
            f"points at the real cause. Install all three together from the same index, "
            f"then pack again. --force goes ahead anyway.",
            reading,
        )

    # (3) Some of the three carry a tag and some do not — an incomplete
    #     identity, so a restore ends up with the generic build of that version.
    named = {n for n in TORCH_FAMILY if re.search(rf"(?mi)^\s*-?\s*{n}\s*[=@]", lock_text)}
    untagged = sorted(named - set(fam))
    reading["torch_family_untagged"] = untagged
    if untagged and fam:
        return CheckResult(
            "lock_cuda_family",
            LEVEL_REJECT,
            f"These carry no CUDA tag in the lockfile: {', '.join(untagged)} — while "
            f"{', '.join(sorted(fam))} do. The CUDA tag is part of the identity: without it a "
            f"restore takes the generic build from the public index, which is not the bytes "
            f"this environment ran on. Pin the whole family from the same index and pack again. --force goes ahead anyway.",
            reading,
        )

    return CheckResult(
        "lock_cuda_family",
        LEVEL_PASS,
        (f"All {len(majors)} CUDA-bound packages in the lockfile are on the same CUDA release"
         if majors else "The lockfile pins no CUDA-bound packages"),
        reading,
    )


def check_lock_sources(lock_text: str) -> CheckResult:
    """Does the lock draw dependencies from hosts we don't recognise?

    Said **before any money is spent**, not halfway through the install. This is
    a timing bug found by measurement: a ``git+https://...`` entry was sitting in
    the lock from packing time, yet the restore side only hard-stopped at the
    dependency-install step (S3, exit code 37) — by which point the user has
    already paid for boot, download and verification (measured at 101.7 seconds
    for a small nest, tens of minutes for a large one). The packing side already
    warns on the spot; this is the same warning repeated at the earliest moment
    of the restore chain, before a machine is even rented.

    Warning level, not blocking: the hard stop stays with the install-step gate.
    The job here is to let people know while knowing is still cheap.
    """
    from .wheels import audit_lock_urls

    unknown = audit_lock_urls(lock_text)
    reading = {"unknown_sources": [u[:100] for u in unknown[:5]], "count": len(unknown)}
    if not unknown:
        return CheckResult("lock_sources", LEVEL_PASS,
                           "Every dependency source in the lock is a recognised host", reading)
    return CheckResult(
        "lock_sources", LEVEL_WARN,
        f"{len(unknown)} dependency source(s) in the lock point at hosts we don't "
        f"recognise (e.g. {unknown[0][:80]}). The restore will stop at the "
        f"dependency-install step unless you allow them by name with "
        f"--trust-host <domain> — better to know that now, before renting a machine, "
        f"than after the download has already been paid for.",
        reading)


def check_lock_cuda_vs_driver(lock_text: str, driver_cuda_version: str) -> CheckResult:
    """The CUDA major the lock needs vs the one this machine's driver supports.

    The comparison uses a measured value — the CUDA Version reported by
    ``nvidia-smi`` — rather than an invented table mapping CUDA majors to driver
    numbers: only the cu124 row of such a table was ever measured.
    """
    majors = set(lock_cuda_majors(lock_text).values())
    have = _major(driver_cuda_version)
    reading: dict = {"lock_cuda_majors": sorted(majors), "driver_cuda": driver_cuda_version}
    if not majors or have is None:
        return CheckResult(
            "lock_cuda_vs_driver",
            LEVEL_PASS,
            "Nothing to compare: either the lockfile pins no NVIDIA packages, or this "
            "machine did not say which CUDA its driver supports",
            reading,
        )
    want = max(int(x) for x in majors)
    if want > int(have):
        return CheckResult(
            "lock_cuda_vs_driver",
            LEVEL_REJECT,
            (
                f"This nest needs CUDA {want}, and this machine's driver only goes up to "
                f"CUDA {have}. It will install and then fail to run, and the message you get "
                f"blames your graphics card — the card is fine, the driver is too old for "
                f"what is pinned here. Rent a machine with a newer driver, or pass --force "
                f"to go ahead anyway."
            ),
            reading,
        )
    return CheckResult(
        "lock_cuda_vs_driver",
        LEVEL_PASS,
        f"This machine's driver supports CUDA {have}; the lockfile needs CUDA {want}",
        reading,
    )


#: How much system memory a nest needs, as a fraction of its own size. The nest
#: records no memory figure of its own, and large models are passed through
#: memory while loading, so size is the best proxy available.
#:
#: **0.8 has to stay above 0.78**: a 59.73 GB video environment filled its
#: 46.6 GiB container ceiling and died 42 minutes in, which is about 0.78x. A
#: lower threshold would wave that very accident through. The aim is to stop
#: what is certain to burst, not to predict every case.
RAM_PER_NEST_GB_RATIO = 0.8


def check_ram(total_bytes: int, nest_bytes: int) -> CheckResult:
    """Does this machine have enough system memory to run this nest?

    When the memory size cannot be read (not on Linux, or a container that will
    not tell us), **say so plainly** rather than counting it as a failure: we
    only stop people when we are sure.
    """
    need = int(nest_bytes * RAM_PER_NEST_GB_RATIO)
    reading = {
        "total_ram_gb": round(total_bytes / 2**30, 1) if total_bytes else None,
        "nest_gb": round(nest_bytes / 2**30, 1),
        "rule_of_thumb_gb": round(need / 2**30, 1),
        "ratio": RAM_PER_NEST_GB_RATIO,
    }
    if not total_bytes or nest_bytes <= 0:
        return CheckResult(
            "ram", LEVEL_PASS,
            "Couldn't read this machine's memory (or this nest declares no size) — "
            "nothing to compare",
            reading)
    if total_bytes < need:
        return CheckResult(
            "ram", LEVEL_REJECT,
            f"This machine has {reading['total_ram_gb']} GiB of memory, and a "
            f"{reading['nest_gb']} GiB nest usually needs about "
            f"{reading['rule_of_thumb_gb']} GiB to load. We measured this the hard way: "
            f"a 59.7 GB nest pinned a 46.6 GiB machine and died 42 minutes in, "
            f"after everything had already been downloaded. Rent a machine with more "
            f"memory — --force goes ahead anyway.",
            reading)
    return CheckResult(
        "ram", LEVEL_PASS,
        f"{reading['total_ram_gb']} GiB of memory for a {reading['nest_gb']} GiB nest",
        reading)


def collect_total_ram() -> int:
    """This machine's system memory in bytes. Returns 0 when unreadable — **no
    guessing**.

    Inside a container, ``/proc/meminfo`` reports the **host's** memory while
    the container itself may be capped far lower. So read the cgroup limit first
    (that is what this container can actually use) and only fall back to
    meminfo.
    """
    for p in ("/sys/fs/cgroup/memory.max",                    # cgroup v2
              "/sys/fs/cgroup/memory/memory.limit_in_bytes"):  # cgroup v1
        try:
            raw = Path(p).read_text().strip()
        except OSError:
            continue
        if raw.isdigit():
            v = int(raw)
            # cgroup v1 fills in an astronomical number to mean "no limit";
            # don't read that as the machine really having that much memory
            if 0 < v < (1 << 50):
                return v
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def check_disk(free_bytes: int, required_bytes: int) -> CheckResult:
    """Disk headroom vs need. ``required_bytes<=0`` = no requirement given."""
    reading = {
        "free_gb": round(free_bytes / 2**30, 1),
        "required_gb": round(required_bytes / 2**30, 1),
    }
    if required_bytes <= 0:
        return CheckResult(
            "disk",
            LEVEL_PASS,
            f"No disk requirement given; {reading['free_gb']} GiB free here",
            reading,
        )
    if free_bytes < required_bytes:
        return CheckResult(
            "disk",
            LEVEL_REJECT,
            f"Only {reading['free_gb']} GiB free, and this nest needs "
            f"{reading['required_gb']} GiB. Clear some space or rent a bigger disk.",
            reading,
        )
    return CheckResult(
        "disk",
        LEVEL_PASS,
        f"{reading['free_gb']} GiB free, enough for the "
        f"{reading['required_gb']} GiB this nest needs",
        reading,
    )


#: How much to actually try writing before trusting the free-space figure. Small enough to
#: cost nothing, large enough that a quota with only scraps left refuses it.
_WRITE_PROBE_BYTES = 64 * 2**20


#: Filesystem types that mean somebody else's disk, reached over the network. The list is
#: what actually shows up in ``/proc/mounts`` on real machines; MooseFS and friends appear
#: as ``fuse`` with a device like ``mfs#host:9421``, so both columns get looked at.
_NETWORK_FS = ("nfs", "nfs4", "cifs", "smb", "smb3", "9p", "lustre", "glusterfs",
               "ceph", "afs", "sshfs", "fuse", "fuse.sshfs", "davfs", "moosefs")


def _fstype_of(path: str | os.PathLike[str], mounts_text: str | None = None) -> tuple[str, str]:
    """``(filesystem type, where it is mounted from)``, read from ``/proc/mounts``.

    The **longest matching mount point wins**, or ``/`` would swallow everything under it.
    Returns ``("", "")`` when the file cannot be read (macOS has none, and rebuilds run on
    Linux) -- with no fact in hand the caller skips the check rather than guessing.
    """
    if mounts_text is None:
        try:
            mounts_text = Path("/proc/mounts").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ("", "")
    target = str(Path(os.fspath(path)).absolute())
    best = ("", "", -1)
    for line in mounts_text.splitlines():
        bits = line.split()
        if len(bits) < 3:
            continue
        source, point, fstype = bits[0], bits[1], bits[2]
        if (target == point or target.startswith(point.rstrip("/") + "/")) and len(point) > best[2]:
            best = (fstype, source, len(point))
    return (best[0], best[1])


def check_local_disk(path: str | os.PathLike[str],
                     mounts_text: str | None = None) -> CheckResult:
    """Is this a local disk, or somebody else's disk over the network? **A warning, never
    a block** -- rebuilding onto a network volume is slower, not wrong, and the user may
    have chosen it deliberately.

    Measured 2026-08-10 on a rented pod: the dependency install took 66 s on the local
    disk; on a network volume (a MooseFS mount at ``/workspace``) the same step crawled --
    tens of thousands of small files, each write crossing the network -- and looked hung.
    That machine also had 53 GiB free on its local disk, unused. Cloud providers drop you
    into that mounted directory by default, so people land there without choosing it.
    """
    fstype, source = _fstype_of(path, mounts_text)
    reading: dict[str, object] = {"fstype": fstype or "unknown",
                                  "source": source or "unknown"}
    if not fstype:
        return CheckResult("local_disk", LEVEL_PASS,
                           "Cannot tell what kind of disk this is here — not checking it",
                           reading)
    if fstype.split(".")[0] not in _NETWORK_FS:
        return CheckResult("local_disk", LEVEL_PASS,
                           f"Rebuilding onto a local disk ({fstype})", reading)
    return CheckResult(
        "local_disk", LEVEL_WARN,
        f"This folder is on a network drive ({fstype} from {source}), not a local disk. It "
        f"will still work, but installing the dependencies writes tens of thousands of small "
        f"files and every one of them crosses the network — measured at 66 seconds on a local "
        f"disk and far slower here. Rebuilding somewhere local (say /root/run) is several "
        f"times faster, and the free-space figure on a network mount is the provider's whole "
        f"pool rather than your quota.",
        reading,
    )


#: How to get uv, printed whenever it is missing. A dependency the tool cannot
#: install for you is only useful if we say how to get it — naming it and stopping
#: is a dead end for the person reading.
UV_INSTALL_HINT = (
    "curl -LsSf https://astral.sh/uv/install.sh | sh   (Windows: "
    'powershell -c "irm https://astral.sh/uv/install.ps1 | iex")   '
    "or, if you only have pip: pip install uv — uv has no dependencies of its own, "
    "so that one does not move anything else in your environment."
)


def check_uv() -> CheckResult:
    """Is ``uv`` on this machine? Rebuilding an environment is done by calling it.

    Without uv nothing can be restored — not by this tool, and not by the escape
    hatch inside the archive, which names uv in its five-command dependency list.
    So this belongs in the check that answers "will this machine do?", and it has
    to answer with the command that fixes it, not just with the word "missing".
    """
    # Ask the same question the rebuild will ask. A check that looks somewhere else
    # can pass while the real call fails -- worse than having no check at all.
    found = uv_executable()
    if found != "uv" or shutil.which("uv"):
        return CheckResult("uv", LEVEL_PASS, "uv is installed.", {"path": found})
    return CheckResult(
        "uv",
        LEVEL_REJECT,
        "uv is not installed, and rebuilding an environment is done by calling it — "
        "this machine cannot restore anything until it is there. Install it with:\n"
        f"  {UV_INSTALL_HINT}",
        {"path": None},
    )


def check_writable(path: str | os.PathLike[str]) -> CheckResult:
    """Can we really write here? **Answered by writing, not by asking.**

    ``df`` lies on a quota-backed network mount. Measured 2026-08-10 on a rented pod whose
    ``/workspace`` was a 20 GiB network volume: the free-space call reported **305 TiB
    available** (the provider's entire storage pool) while writing 200 MiB failed at once
    with "Disk quota exceeded". The nest needed ~26 GiB, the disk check happily said
    "plenty", and the rebuild died with the volume full -- the free-space number itself was
    the lie, so no arithmetic on it could have caught this.

    A small probe is the only thing that answers the real question, and it also catches
    read-only mounts and permission trouble, which arithmetic never would.
    """
    reading: dict[str, object] = {"probe_mb": _WRITE_PROBE_BYTES // 2**20}
    target = Path(os.fspath(path))
    for candidate in (target, *target.parents):
        if candidate.is_dir():
            target = candidate
            break
    probe = target / f".renest-write-probe-{os.getpid()}"
    try:
        with probe.open("wb") as fh:
            fh.write(b"\0" * _WRITE_PROBE_BYTES)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        return CheckResult(
            "writable",
            LEVEL_REJECT,
            f"Cannot write {reading['probe_mb']} MiB into {target} ({exc.strerror or exc}). "
            f"On a network volume the free-space figure is the provider's whole pool rather "
            f"than your quota, so \"plenty free\" can still mean full. Rebuild somewhere "
            f"with real room -- a local disk is also far faster for this.",
            reading,
        )
    finally:
        try:
            probe.unlink()
        except OSError:
            pass
    return CheckResult("writable", LEVEL_PASS,
                       f"Wrote and removed a {reading['probe_mb']} MiB probe in {target}",
                       reading)


# -- collectors (thin shells that run real commands) --
def _run_cmd(cmd: list[str], timeout: float = 30) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)  # noqa: S603
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def collect_driver_version() -> str:
    out = _run_cmd(["nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader"])
    return out.strip().splitlines()[0].strip() if out.strip() else ""


def collect_driver_cuda_version() -> str:
    """The highest CUDA this machine's driver supports.

    Read from the header line of ``nvidia-smi``, e.g. "CUDA Version: 12.4".
    """
    out = _run_cmd(["nvidia-smi"])
    m = re.search(r"CUDA Version:\s*([0-9]+\.[0-9]+)", out)
    return m.group(1) if m else ""


def collect_gpu_name() -> str:
    out = _run_cmd(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"])
    return out.strip().splitlines()[0].strip() if out.strip() else ""


def collect_cpu_flags() -> str:
    out = _run_cmd(["lscpu"])
    if out.strip():
        return out
    try:
        return Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def collect_egress_mbps(url: str = EGRESS_PROBE_URL, max_time: int = 30) -> float:
    """curl a known URL to measure Mbps. ``-L`` is mandatory (GitHub release is
    a 302). curl timeout (exit 28) still emits ``-w`` speed, so we parse stdout
    rather than the exit code — a slow pipe should read as truly slow, not 0."""
    try:
        r = subprocess.run(  # noqa: S603
            [
                "curl",
                "-sfL",
                "-o",
                os.devnull,
                "-w",
                "%{speed_download}",
                "--max-time",
                str(max_time),
                url,
            ],
            capture_output=True,
            text=True,
            timeout=max_time + 15,
        )
        out = r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        out = ""
    try:
        return float(out.splitlines()[-1]) * 8 / 1e6  # bytes/s -> Mbps
    except (ValueError, IndexError):
        return 0.0


def collect_gpu_compute_cap() -> str:
    """This machine's GPU compute capability (like ``8.9``); "" if unreadable."""
    out = _run_cmd(["nvidia-smi", "--query-gpu=compute_cap", "--format=csv,noheader"])
    return out.strip().splitlines()[0].strip() if out.strip() else ""


def collect_disk_free(path: str | os.PathLike[str] = "/") -> int:
    """Free bytes on the filesystem that will hold ``path``.

    **``path`` does not have to exist yet, and usually does not**: rebuilding into a
    fresh folder (``restore --dir ./run``) is the normal case, and asking the OS about
    a folder that is not there raises. That used to be reported as "Only 0.0 GiB free"
    and **refused the rebuild before it started** — on a machine with plenty of room.
    So walk up to the nearest parent that does exist; that is the filesystem the new
    folder will be created on. Real cost: it stopped a trial-pack rebuild on 2026-08-10,
    and the same command is the one the walkthrough hands to every user.
    """
    here = Path(os.fspath(path))
    for candidate in (here, *here.parents):
        try:
            return shutil.disk_usage(candidate).free
        except OSError:
            continue
    return 0


def _libc_tuple(v: object) -> tuple[int, ...] | None:
    if not isinstance(v, str) or not v.strip():
        return None
    parts = v.strip().split(".")
    return tuple(int(x) for x in parts if x.isdigit()) or None


def _local_vram_bytes() -> int | None:
    """This machine's largest card, in bytes. None when it cannot be read."""
    out = _run_cmd(["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"])
    if not out:
        return None
    best = 0
    for line in out.splitlines():
        try:
            best = max(best, int(float(line.strip())) * 1024 * 1024)
        except ValueError:
            continue
    return best or None


def check_observed_vram(nest_gpu: dict | None, local_bytes: int | None = None) -> CheckResult:
    """How much video memory the successful run was seen to use, against this card.

    **Advisory in every branch, by ruling.** The figure is the largest use *seen across
    the readings*, not a requirement: a run sampled every second can miss a spike, and a
    run that died before touching the card reported 1 MiB. So the number never travels
    without its sample count -- on its own it reads as "this job needs 1 MiB", which is
    how a reader gets misled into renting too small a card.
    """
    use = ((nest_gpu or {}).get("observed_use") or {})
    used, samples = use.get("max_used_bytes"), use.get("samples")
    if not isinstance(used, int) or used <= 0:
        # **Say which of the two it is.** The old wording ("this nest carries no reading")
        # reads as though this one nest were old or unusual, while *no* nest carries the
        # figure: nothing in the tool writes it yet, so this check has never once fired.
        # A report line that looks like a passed check, on a check that cannot run, is
        # worse than no line at all -- people read it as "the card was sized up".
        return CheckResult("observed_vram", "skip",
                           "Renest does not yet measure how much video memory a working "
                           "run uses, so no nest carries that figure and this check cannot "
                           "run. Nothing here has sized this card up against the job.",
                           {"never_measured": True})
    have = local_bytes if local_bytes is not None else _local_vram_bytes()
    every = use.get("sample_interval_s")
    seen = (f"{used / 2**30:.1f} GiB (largest of {samples} readings taken every "
            f"{every}s -- a reading, not a requirement)")
    reading = {"observed_max_gib": round(used / 2**30, 1), "samples": samples,
               "sample_interval_s": every,
               "this_card_gib": round(have / 2**30, 1) if have else None}
    if not have:
        return CheckResult("observed_vram", "skip",
                           f"The working run was seen using {seen}. This machine's video "
                           f"memory could not be read, so no comparison was made.", reading)
    if used > have:
        return CheckResult(
            "observed_vram", "warn",
            f"The working run was seen using {seen}, and this card has "
            f"{have / 2**30:.1f} GiB. It may still work -- frameworks trade speed for "
            f"memory when they have to -- but expect it to be slower, or to stop partway. "
            f"Never refused on this count alone.", reading)
    return CheckResult("observed_vram", "pass",
                       f"This card has {have / 2**30:.1f} GiB; the working run was seen "
                       f"using {seen}.", reading)


def check_extension_archs(nest_gpu: dict | None, current_compute_cap: str) -> CheckResult:
    """Which GPU generations the nest's **compiled extensions** were built for.

    Separate from :func:`check_gpu_arch`, which asks the same of PyTorch itself, and
    **only ever a warning** where that one can block: PyTorch not covering this card
    means nothing runs, while one extension not covering it means that extension's nodes
    are missing -- the app still starts, and the user may not even use them.
    """
    g = nest_gpu or {}
    entries = [(e.get("code_dep") or e.get("package") or "?", e)
               for key in ("node_native_archs", "package_native_archs")
               for e in (g.get(key) or []) if isinstance(e, dict)]
    if not entries:
        return CheckResult("extension_archs", "skip",
                           "This nest does not record what its compiled extensions were "
                           "built for, so there is nothing to compare.", {})
    try:
        cap = int(str(current_compute_cap).replace(".", ""))
    except (TypeError, ValueError):
        return CheckResult("extension_archs", "skip",
                           "This machine's GPU generation could not be read, so the "
                           "extensions' build targets were not compared.", {})
    missing = []
    for name, e in entries:
        sms, _ptx = split_arch_list(e.get("sm_list"))
        if sms and cap not in sms:
            missing.append(f"{name} (built for {', '.join(str(s) for s in sorted(sms))})")
    reading = {"this_gpu": cap, "checked": len(entries), "not_built_for_this_card": missing}
    if not missing:
        return CheckResult("extension_archs", "pass",
                           f"All {len(entries)} compiled extension(s) were built for this "
                           f"card's generation ({cap}).", reading)
    return CheckResult(
        "extension_archs", "warn",
        f"{len(missing)} of {len(entries)} compiled extension(s) were not built for this "
        f"card's generation ({cap}): {'; '.join(missing[:4])}. Those nodes will be missing "
        f"once the app starts; everything else still works. Never a refusal — the app runs "
        f"without them, and you may not use them.", reading)


def check_system_layer(nest_runtime: dict | None, this_env: dict | None = None) -> CheckResult:
    """What the **machine's own operating system** has to provide, answered in one pass.

    Three facts, one verdict, on purpose: the C library version and the platform tag
    decide whether this nest's pre-built packages install at all, and the machine
    library list decides whether the app can load them once installed. Splitting them
    would have the same machine complained about twice in two different voices.

    **Advisory in every branch.** The one thing here that could justify blocking is a
    library the working run really loaded; even that only warns, because this check runs
    before anything is downloaded and a wrong stop costs more than a wrong warning."""
    rt = nest_runtime or {}
    have = this_env if this_env is not None else collect_wheel_env()
    reading: dict = {}
    lines: list[str] = []
    level = LEVEL_PASS

    want_libc, got_libc = _libc_tuple(rt.get("libc_version")), _libc_tuple(have.get("libc_version"))
    if want_libc and got_libc:
        reading["libc"] = {"nest": rt.get("libc_version"), "this": have.get("libc_version")}
        if got_libc < want_libc:
            level = LEVEL_WARN
            lines.append(
                f"This machine's C library is {have['libc_version']} and the nest was packed "
                f"against {rt['libc_version']}. Pre-built packages are chosen against that "
                f"number, so some of them may refuse to install here.")
    want_tag, got_tag = rt.get("platform_tag"), have.get("platform_tag")
    if want_tag and got_tag:
        reading["platform_tag"] = {"nest": want_tag, "this": got_tag}
        if str(want_tag).split("-")[-1] != str(got_tag).split("-")[-1]:
            level = LEVEL_WARN
            lines.append(
                f"This machine's platform tag is {got_tag} and the nest's is {want_tag}. "
                f"That is what decides which pre-built packages fit.")

    libs = rt.get("native_libs") or {}
    names = [n for n in (libs.get("names") or []) if isinstance(n, str)]
    if libs.get("method") and names:
        gone = missing_native_libs(names)
        reading["native_libs"] = {"method": libs.get("method"), "checked": len(names),
                                  "missing": gone}
        if gone and libs.get("method") == "loaded":
            level = LEVEL_WARN
            lines.append(
                f"This machine is missing {len(gone)} library file(s) the working run used "
                f"({', '.join(gone[:5])}). They belong to the machine's operating system and "
                f"no nest can carry them; a machine short of one is usually short of several, "
                f"so the surest fix is starting from the image this was packed on.")
        elif gone:
            lines.append(
                f"{len(gone)} library file(s) named by this nest are not here "
                f"({', '.join(gone[:5])}). That list was read off the installed packages "
                f"rather than off the working run, so it names libraries that may never be "
                f"used — come back to this only if something fails to load later.")

    if not reading:
        return CheckResult(
            "system_layer", "skip",
            "This nest doesn't record what its machine had to provide (nests older than "
            "format 2.6 don't), so there is nothing to compare.", reading)
    return CheckResult(
        "system_layer", level,
        " ".join(lines) if lines else
        "The operating system underneath looks like the one this nest was packed on.",
        reading)


def check_gpu_generation(this_cap: str, captured_on: dict | None) -> CheckResult:
    """This card against **the card the run actually worked on**.

    Different question from the build-target check next to it: that one asks what the
    nest's torch was compiled for, this one asks what really ran. The exact generation
    has been recorded on every nest the product ever packed and, until now, nothing read
    it -- so when a nest carries no build-target list this was the only signal available
    and it went unused.

    **This one never reassures.** It used to end "allowed and usually fine". Measured
    2026-08-18: three Blackwell machines read that line, passed the pre-flight, and died
    on ``no kernel image is available`` -- while the check that could have refused them
    sat next door reporting "no torch build targets ... unverified". Saying "usually
    fine" next to "I could not check" is the product guessing on the user's behalf."""
    want = (captured_on or {}).get("cuda_compute") or (captured_on or {}).get("sm_arch") or ""
    reading = {"nest": want or None, "this": this_cap or None,
               "captured_on": (captured_on or {}).get("name")}
    if not want or not this_cap:
        return CheckResult(
            "gpu_generation", "skip",
            "Either this nest or this machine doesn't say which GPU generation is involved, "
            "so there is nothing to compare.", reading)
    if _arch_num(want) == _arch_num(this_cap):
        return CheckResult(
            "gpu_generation", LEVEL_PASS,
            f"Same GPU generation as the card this run worked on (sm_{_arch_num(want)}).",
            reading)
    return CheckResult(
        "gpu_generation", LEVEL_WARN,
        f"This run worked on an sm_{_arch_num(want)} card and this machine has "
        f"sm_{_arch_num(this_cap)}. Rebuilding on a different card is allowed, but nothing "
        f"here says it will work: whether this nest's torch carries kernels for this card is "
        f"the separate gpu_arch check — read that one.",
        reading)


def check_chip_family(nest_arch: str | None, this_arch: str | None) -> CheckResult:
    """Which chip family was this nest packed for, and does this machine match?

    Recorded in the manifest from format 2.3 onwards.

    **Blocking, not advisory**: this is "cannot possibly install", not "possibly
    risky". Python dependencies are built per chip family, one build each, so a
    nest packed on Intel has no matching build on ARM. Carrying on ends one way
    — death at the dependency-install step, with an error that points nowhere
    near the chip.

    **Both directions are this check's job alone.** The instruction-name check
    once rejected some Intel-to-ARM moves as a side effect, but that went away
    when it was made chip-family aware, and it never covered ARM-to-Intel.

    An empty ``nest_arch`` (nests older than format 2.3) means we do not know,
    and **not knowing means not blocking** — blocking on nothing would brick a
    whole generation of perfectly usable old nests.
    """
    if not nest_arch:
        return CheckResult(
            "chip_family", "skip",
            "This nest doesn't say which chip family it was packed for (nests older than "
            "format 2.3 don't record it), so there is nothing to compare.",
            {"nest": None, "this": this_arch or None},
        )
    want = _chip_family(nest_arch)
    have = _chip_family(this_arch)
    if not have:
        return CheckResult(
            "chip_family", "warn",
            f"We can't tell what chip this machine has, so we can't check it against the "
            f"nest (packed for {nest_arch}). Carrying on.",
            {"nest": nest_arch, "this": this_arch or None},
        )
    if want == have:
        return CheckResult(
            "chip_family", "pass",
            f"Same chip family as the machine this was packed on ({nest_arch}).",
            {"nest": nest_arch, "this": this_arch},
        )
    return CheckResult(
        "chip_family", "reject",
        f"This nest was packed on a {want} machine and this one is {have}. "
        f"That is not a compatibility guess — the Python packages it needs are built per "
        f"chip family, one build each, so the {want} ones simply do not install here. "
        f"Nothing is wrong with your machine. Rebuild it on a {want} machine, or pack the "
        f"environment again on a {have} one.",
        {"nest": nest_arch, "this": this_arch},
    )


def run_precheck(
    cuda_tag: str | None = None,
    expected_driver: str | None = None,
    need_disk_gb: float = 0.0,
    #: How big this nest is, in bytes. The memory check derives its threshold
    #: from this, because nests record no memory requirement and size stands in
    #: for it (reasoning at RAM_PER_NEST_GB_RATIO). When not given, the disk
    #: requirement is used as an approximation.
    nest_bytes: int = 0,
    disk_path: str | os.PathLike[str] = "/",
    nest_gpu: dict | None = None,
    skip_net: bool = False,
    #: Whether the big files for this rebuild come over the internet. ``False``
    #: means they do not (they are on this machine or on the local network), in
    #: which case a slow link only warns instead of stopping (reasoning in the
    #: egress block below). ``None`` means we do not know, so the strict rule
    #: applies.
    bulk_from_internet: bool | None = None,
    force: bool = False,
    egress_url: str | None = None,
    lock_text: str | None = None,
    #: Which chip family this nest was packed for (``fingerprint.os.machine`` in
    #: the manifest, from format 2.3 onwards). Absent = an older nest that never
    #: recorded it = nothing is blocked (see check_chip_family).
    nest_arch: str | None = None,
    #: The nest's ``runtime`` block. Carries what the machine underneath has to provide
    #: (C library, platform tag, machine libraries). Absent = an older nest = nothing to
    #: compare, never an invented warning.
    nest_runtime: dict | None = None,
    #: Which card the packed run actually worked on (``gpu.captured_on``). Separate
    #: from ``nest_gpu`` on purpose: this one only ever warns, while ``nest_gpu``
    #: switches on a gate that can refuse the machine. A caller that wants advice
    #: without the gate passes this alone.
    nest_captured_on: dict | None = None,
) -> PrecheckReport:
    """Collect on this machine and verdict each check. ``force`` changes no
    verdict — it only allows continuation after a reject.

    The thresholds (driver floors, instruction sets, speed limits) are read from
    data/doctor-rules.json rather than from values embedded in the code; when
    that data is broken, rules.py falls back to the factory baseline by itself.
    """
    cuda_tag = cuda_tag or default_cuda_tag()
    floors, required_flags, egress_rules = _doctor_rules()
    report = PrecheckReport(forced=force)
    report.checks.append(
        check_driver(collect_driver_version(), cuda_tag, expected_driver, floors=floors)
    )
    report.checks.append(
        check_cpu_flags(
            collect_cpu_flags(), required=required_flags, arch=platform.machine()
        )
    )
    # Chip-family gate (blocking). **Its position here is deliberate**: it is
    # cheaper than every other check (one string compared against another), and
    # once it fails, the verdicts of all the later checks are meaningless — that
    # machine cannot install this nest's dependencies at all.
    report.checks.append(check_chip_family(nest_arch, platform.machine()))
    # GPU architecture gate, also blocking. A nest with no gpu block (legal for
    # older nests) skips the whole check rather than inventing a warning.
    if nest_gpu:
        _cap = collect_gpu_compute_cap()
        report.checks.append(
            check_gpu_arch(
                _cap,
                nest_gpu.get("torch_cuda_arch_list"),
                (nest_gpu.get("captured_on") or {}).get("name"),
            )
        )
        report.checks.append(check_gpu_generation(_cap, nest_gpu.get("captured_on")))
        # Two readings the nest already carried and nobody read until 2026-08-13: what the
        # compiled extensions were built for, and how much video memory the run was seen
        # using. Both advisory — see each function for why neither may refuse.
        report.checks.append(check_extension_archs(nest_gpu, _cap))
        report.checks.append(check_observed_vram(nest_gpu))
    elif nest_captured_on:
        report.checks.append(check_gpu_generation(collect_gpu_compute_cap(), nest_captured_on))
    # The operating system underneath: C library, platform tag, machine libraries.
    # One pass and one voice — see check_system_layer.
    report.checks.append(check_system_layer(nest_runtime))
    if not skip_net:
        url = egress_url or str(egress_rules["probe_url"])
        # **When the big files do not come over the internet, a slow link is no
        # reason to refuse.** The gate exists so nobody rents a cloud machine and
        # discovers a broken network twenty GB in; on a home machine whose files
        # are already local, none of those bytes cross the internet and refusing
        # over a 12.9 Mbps line is nonsense. Not a skip, though — the dependency
        # install still needs the network, so it downgrades to a heads-up.
        result = check_egress(
            collect_egress_mbps(url),
            reject_below=float(egress_rules["reject_below_mbps"]),
            warn_below=float(egress_rules["warn_below_mbps"]),
        )
        if bulk_from_internet is False and result.level == LEVEL_REJECT:
            reading = dict(result.reading)
            reading["bulk_from_internet"] = False
            result = CheckResult(
                "egress",
                LEVEL_WARN,
                result.reason.split(" A machine that boots")[0]
                + " — but the big files for this rebuild do not come over the internet, "
                "so this is only a heads-up: installing dependencies will be slow, "
                "and nothing here is a reason to stop.",
                reading,
            )
        report.checks.append(result)
    if lock_text:
        # The lock must be on one CUDA line internally, and that line must also
        # match what this machine's driver can carry.
        report.checks.append(check_lock_cuda_family(lock_text))
        report.checks.append(check_lock_cuda_vs_driver(lock_text, collect_driver_cuda_version()))
        report.checks.append(check_lock_sources(lock_text))
    report.checks.append(check_disk(collect_disk_free(disk_path), int(need_disk_gb * 2**30)))
    # Then ask the disk the same question by writing to it: on a quota-backed network mount
    # the number above is the provider's whole pool, not your share (see check_writable).
    report.checks.append(check_writable(disk_path))
    # Nothing rebuilds without uv (see check_uv) — ask before the long download,
    # not after it.
    report.checks.append(check_uv())
    # A network drive warns, never blocks: it works, it is just much slower -- and cloud
    # providers drop people into such a directory by default, so they land there unaware.
    report.checks.append(check_local_disk(disk_path))
    # Memory. The lesson behind this check: a run that died of memory exhaustion
    # 42 minutes in, by which point every byte had long since been downloaded.
    # If it is going to be stopped, it has to be stopped before the run starts.
    report.checks.append(
        check_ram(collect_total_ram(), int(nest_bytes or need_disk_gb * 2**30)))
    return report


# --------------------------------------------------------------------------
# Fingerprint comparison (four-level verdict)
# --------------------------------------------------------------------------
LEVEL_EXACT = "exact"
LEVEL_COMPATIBLE = "compatible"
LEVEL_WARNING = "warning"
LEVEL_BLOCKING = "blocking"

_SEVERITY = {LEVEL_EXACT: 0, LEVEL_COMPATIBLE: 1, LEVEL_WARNING: 2, LEVEL_BLOCKING: 3}


@dataclass
class FingerprintVerdict:
    """Four-level verdict + per-field rows + the blocking error_class (if any)."""

    level: str
    error_class: ErrorClass | None
    rows: list[dict] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "error_class": str(self.error_class) if self.error_class else None,
            "rows": self.rows,
            "summary": self.summary,
        }


def _major_minor(version: str | None) -> tuple[str, str] | None:
    if not version:
        return None
    m = re.match(r"(\d+)\.(\d+)", str(version))
    return (m.group(1), m.group(2)) if m else None


def _major(version: str | None) -> str | None:
    if not version:
        return None
    m = re.match(r"(\d+)", str(version))
    return m.group(1) if m else None


def compare_fingerprint(local: Fingerprint | dict, required: dict,
                        base_image: str | None = None) -> FingerprintVerdict:
    """Compare this machine's fingerprint vs a nest's ``required`` fingerprint.

    Rules (initial, deliberately lenient — more warnings, fewer blocks):
    Python major.minor differs → blocking PYTHON_BLOCK; CUDA major differs →
    blocking CUDA_BLOCK; torch/os/critical-package diffs → warning; identical →
    exact; torch+cuda major match with lesser diffs → compatible.
    """
    local_d = local.to_dict(include_absent=True) if isinstance(local, Fingerprint) else dict(local)
    rows: list[dict] = []
    level = LEVEL_EXACT
    error_class: ErrorClass | None = None

    def bump(new_level: str, klass: ErrorClass | None = None) -> None:
        nonlocal level, error_class
        if _SEVERITY[new_level] > _SEVERITY[level]:
            level = new_level
            error_class = klass
        elif klass is not None and error_class is None and _SEVERITY[new_level] == _SEVERITY[level]:
            error_class = klass

    def row(fieldname: str, got: str | None, want: str | None, verdict: str) -> None:
        rows.append({"field": fieldname, "local": got, "required": want, "verdict": verdict})

    # -- python (blocking on major.minor) --
    lpy = (local_d.get("python") or {}).get("version")
    rpy = (required.get("python") or {}).get("version")
    if rpy:
        if _major_minor(lpy) != _major_minor(rpy):
            row("python.version", lpy, rpy, LEVEL_BLOCKING)
            bump(LEVEL_BLOCKING, ErrorClass.PYTHON_BLOCK)
        elif lpy != rpy:
            row("python.version", lpy, rpy, LEVEL_COMPATIBLE)
            bump(LEVEL_COMPATIBLE)
        else:
            row("python.version", lpy, rpy, LEVEL_EXACT)

    # -- cuda (blocking on major) --
    ltorch = local_d.get("torch") or {}
    rtorch = required.get("torch") or {}
    lcuda = ltorch.get("cuda_version")
    rcuda = rtorch.get("cuda_version")
    if rcuda:
        if _major(lcuda) != _major(rcuda):
            row("torch.cuda_version", lcuda, rcuda, LEVEL_BLOCKING)
            bump(LEVEL_BLOCKING, ErrorClass.CUDA_BLOCK)
        elif lcuda != rcuda:
            row("torch.cuda_version", lcuda, rcuda, LEVEL_WARNING)
            bump(LEVEL_WARNING, ErrorClass.WARNING_UNCONFIRMED)
        else:
            row("torch.cuda_version", lcuda, rcuda, LEVEL_EXACT)

    # -- torch version (warning on diff, compatible on major match) --
    ltv = ltorch.get("version")
    rtv = rtorch.get("version")
    if rtv:
        if ltv == rtv:
            row("torch.version", ltv, rtv, LEVEL_EXACT)
        elif _major(ltv) == _major(rtv):
            row("torch.version", ltv, rtv, LEVEL_COMPATIBLE)
            bump(LEVEL_COMPATIBLE)
        else:
            row("torch.version", ltv, rtv, LEVEL_WARNING)
            bump(LEVEL_WARNING, ErrorClass.WARNING_UNCONFIRMED)

    # -- critical packages (warning on version diff) --
    lpkgs = local_d.get("critical_packages") or {}
    rpkgs = required.get("critical_packages") or {}
    for name, want in sorted(rpkgs.items()):
        got = lpkgs.get(name)
        if got == want:
            row(f"critical_packages.{name}", got, want, LEVEL_EXACT)
        else:
            row(f"critical_packages.{name}", got, want, LEVEL_WARNING)
            bump(LEVEL_WARNING, ErrorClass.WARNING_UNCONFIRMED)

    # -- os (warning on diff) --
    los = local_d.get("os") or {}
    ros = required.get("os") or {}
    if ros.get("name"):
        got = f"{los.get('name')} {los.get('version')}" if los.get("name") else None
        want = f"{ros.get('name')} {ros.get('version')}"
        if got == want:
            row("os", got, want, LEVEL_EXACT)
        else:
            row("os", got, want, LEVEL_WARNING)
            bump(LEVEL_WARNING, ErrorClass.WARNING_UNCONFIRMED)

    summaries = {
        LEVEL_EXACT: "this machine matches the nest exactly",
        LEVEL_COMPATIBLE: "this machine is compatible (minor differences)",
        LEVEL_WARNING: (
            "this machine differs from the nest, so the restore may have to "
            "reinstall things — check you booted the right image"
        ),
        LEVEL_BLOCKING: (
            "blocked: major versions don't match, so installing here would be "
            "wasted work — rent a machine that matches"
        ),
    }
    summary = summaries[level]
    # Saying "check you booted the right image" without saying which one leaves the
    # reader to go dig the nest out. The name is in the manifest -- print it. Booting
    # that image is also how the system libraries a nest cannot carry all arrive at once.
    if base_image and level in (LEVEL_WARNING, LEVEL_BLOCKING):
        summary += f" — this nest was packed on `{base_image}`"
    return FingerprintVerdict(
        level=level, error_class=error_class, rows=rows, summary=summary
    )


def _verdict_exit_code(
    precheck: PrecheckReport, fp: FingerprintVerdict | None, *, force: bool
) -> int:
    """Combine host precheck + fingerprint verdict into an S0 exit code."""
    # blocking fingerprint / rejecting host check win first
    if fp is not None and fp.level == LEVEL_BLOCKING and fp.error_class is not None:
        code = ExitCode(_S0_BY_CLASS[fp.error_class])
        return int(ExitCode.OK) if force and code not in _HARD_BLOCK else int(code)
    rejects = [c for c in precheck.checks if c.level == LEVEL_REJECT]
    if rejects:
        klass = PRECHECK_CLASS.get(rejects[0].name, ErrorClass.UNKNOWN)
        code = int(_S0_BY_CLASS.get(klass, ExitCode.S0_UNKNOWN))
        return int(ExitCode.OK) if force else code
    warn = (precheck.overall == "warn") or (fp is not None and fp.level == LEVEL_WARNING)
    if warn and not force:
        return int(ExitCode.S0_WARNING_UNCONFIRMED)
    return int(ExitCode.OK)


_S0_BY_CLASS: dict[ErrorClass, ExitCode] = {
    ErrorClass.PYTHON_BLOCK: ExitCode.S0_PYTHON_BLOCK,
    ErrorClass.CUDA_BLOCK: ExitCode.S0_CUDA_BLOCK,
    ErrorClass.ARCH_UNSUPPORTED: ExitCode.S0_ARCH_UNSUPPORTED,
    ErrorClass.DISK_INSUFFICIENT: ExitCode.S0_DISK_INSUFFICIENT,
    ErrorClass.UNKNOWN: ExitCode.S0_UNKNOWN,
    ErrorClass.WARNING_UNCONFIRMED: ExitCode.S0_WARNING_UNCONFIRMED,
}
# blocks --force cannot launder past (Python/CUDA/arch are "install anyway = wasted")
_HARD_BLOCK = frozenset(
    {ExitCode.S0_PYTHON_BLOCK, ExitCode.S0_CUDA_BLOCK, ExitCode.S0_ARCH_UNSUPPORTED}
)


@dataclass
class DoctorResult:
    exit_code: int
    local_fingerprint: dict
    fingerprint: dict | None  # verdict dict, or None when no nest / no required fingerprint
    precheck: dict | None
    summary: str
    coverage: dict | None = None  # is this GPU model in the tested-coverage list?
    storage: dict | None = None  # where the bucket key lives + exposure warnings

    def to_dict(self) -> dict:
        return {
            "ok": self.exit_code == int(ExitCode.OK),
            "exit_code": self.exit_code,
            "summary": self.summary,
            "local_fingerprint": self.local_fingerprint,
            "fingerprint": self.fingerprint,
            "precheck": self.precheck,
            "coverage": self.coverage,
            "storage": self.storage,
        }


def storage_report(creds: Credentials | None = None) -> dict | None:
    """Where the bucket key is kept, and how exposed it is.

    **No sugar-coating**: a key sitting in a plain-text file is reported as
    "plain text", never as "stored securely". Users are entitled to know its
    real form — that is the only way they can judge whether to keep it there.

    Returns None when no bucket key is configured on this machine at all: there
    is nothing to report then, and reporting anyway would only make noise.
    """
    if creds is None:
        try:
            creds = resolve_credentials()
        except ConfigError as exc:
            # Problems found before we even get there, such as wrong file
            # permissions: this command's job is to **report**, not to blow up,
            # so the problem becomes a readable line instead of a failure.
            return {"configured": False, "problem": exc.human, "hint": exc.hint}

    if creds.source is not CredentialSource.BUCKET_KEY or creds.bucket_key is None:
        return None

    key = creds.bucket_key
    report: dict = {
        "configured": True,
        "origin": creds.bucket_key_origin,
        "provider": key.provider or "other",
        "endpoint": key.endpoint,
        "bucket": key.bucket,
        # The effective values, not the ones the user typed — what matters when
        # troubleshooting is what was actually used in the end
        "region": key.effective_region(),
        "addressing": key.effective_addressing(),
        "warnings": list(creds.exposure_warnings),
    }
    if creds.bucket_key_origin == "config_file" and creds.config_path is not None:
        report["path"] = str(creds.config_path)
        report["plaintext"] = True
        report["note"] = (
            f"Your bucket key is stored in plain text in {creds.config_path} "
            f"(permissions 600, so only you can read it)."
        )
    elif creds.bucket_key_origin == "env":
        report["plaintext"] = True
        report["note"] = (
            "Your bucket key is in this shell's environment variables. It disappears "
            "when the shell closes, and every program started from this shell can read it."
        )
    if creds.warning:
        report["warnings"].append(creds.warning)
    return report


def _model_matches(listed: str, actual: str) -> bool:
    """Is the listed model **really this card**, or just a slice of its name?

    **Why a plain "contains" test will not do**: the list holds `L4`, and
    `NVIDIA L40S` happens to contain `L4` — so **a card nobody ever tested gets
    reported as tested**, and the user is handed confidence with nothing behind
    it. That is far worse than saying "untested": "untested" is merely
    cautious, while "tested" is a promise that is false.

    The rule: the model has to land on **word boundaries**. `L4` matches
    `NVIDIA L4` but not `L40S` or `L40`; `RTX 4090` matches
    `NVIDIA GeForce RTX 4090` and also `RTX 4090 D`, a variant of the same model
    where what follows is a separate word.
    """
    import re as _re

    return _re.search(rf"(?<![0-9A-Za-z]){_re.escape(listed)}(?![0-9A-Za-z])",
                      actual, _re.IGNORECASE) is not None


#: What "we have tested this card" is worth, said in one sentence. The matrix
#: carries the strength of the evidence, never the run count or where it ran.
_COVERAGE_SENTENCE = {
    "high": "We have tested this GPU, and the verdict rests on a solid body of runs.",
    "low": "We have tested this GPU, but only lightly, so the verdict still errs "
           "on the cautious side.",
}


def gpu_coverage(gpu_name: str) -> dict | None:
    """Say whether this GPU is inside our tested coverage, honestly.

    Checked against the tested-GPU list in the fingerprint matrix.

    No GPU name readable (no nvidia-smi, no card) -> None: no verdict, and no
    pretending. In the list -> tested=True plus how much testing stands behind
    it (confidence high/low). Not in the list -> tested=False, stating outright
    that it is untested and the verdict errs cautious — we do not pretend to
    recognise a card we have never seen.
    """
    if not gpu_name.strip():
        return None
    matrix = load_rules(FINGERPRINT_MATRIX)
    name = gpu_name.strip()
    for entry in matrix.get("tested_gpus", []):
        if _model_matches(entry["name_contains"], name):
            # Unknown or missing strength reads as "low": a card we cannot rate
            # must never come out sounding better tested than it is.
            confidence = entry.get("confidence", "low")
            if confidence not in _COVERAGE_SENTENCE:
                confidence = "low"
            return {
                "gpu": name,
                "tested": True,
                "confidence": confidence,
                "note": _COVERAGE_SENTENCE[confidence],
            }
    return {
        "gpu": name,
        "tested": False,
        "note": matrix.get(
            "coverage_note",
            "We haven't tested this GPU, so the verdict errs on the cautious side.",
        ),
    }


def doctor(
    manifest: dict | None = None,
    *,
    python_path: str | None = None,
    force: bool = False,
    with_host_checks: bool = True,
    skip_net: bool = True,
    require_fingerprint: bool = False,
    lock_text: str | None = None,
    emitter: EventEmitter | None = None,
    _local: Fingerprint | None = None,
    _precheck: PrecheckReport | None = None,
    _gpu_name: str | None = None,
    _creds: Credentials | None = None,
) -> DoctorResult:
    """Run the pre-check. Without ``manifest`` just collect + print this
    machine's fingerprint (exit 0). With ``manifest`` compare fingerprints and
    (optionally) run host checks; exit by the most-severe verdict.

    ``_local`` / ``_precheck`` are injection seams for tests (no real probes).
    """
    local = _local if _local is not None else collect(python_path)
    local_d = local.to_dict(include_absent=True)
    storage = storage_report(_creds)

    if manifest is None:
        # Without a nest there is nothing to *compare*, but most of the machine
        # checks are about the machine alone -- driver, instruction set, disk,
        # link speed -- and the command's own help offers exactly that: "leave it
        # out to just check this machine". Until 2026-08-11 it ran none of them
        # and always exited 0. Measured on a 2011 CPU with no avx2, a machine
        # that provably cannot install our wheels: it got a clean bill of health.
        # A check that answers "fine" on an unusable machine is worse than absent.
        precheck = _precheck if _precheck is not None else (
            run_precheck(skip_net=skip_net, force=force) if with_host_checks else None
        )
        if precheck is not None:
            precheck = PrecheckReport(
                checks=[c for c in precheck.checks if c.name in _NEST_FREE_CHECKS],
                forced=precheck.forced,
            )
        parts = ["checked this machine, nothing to compare against (no nest given)"]
        if precheck is not None and precheck.checks:
            parts.append("machine notes above — give me a nest and I can give a verdict")
        summary = "Verdict: " + "; ".join(parts)
        if emitter is not None:
            emitter.log(summary, stage="S0")
        return DoctorResult(
            int(ExitCode.OK), local_d, None,
            precheck.to_dict() if (precheck is not None and precheck.checks) else None,
            summary, storage=storage,
        )

    required = manifest.get("fingerprint")
    fp_verdict: FingerprintVerdict | None = None
    if required:
        fp_verdict = compare_fingerprint(
            local, required, (manifest.get("base_image") or {}).get("ref") or None)
    elif require_fingerprint:
        summary = (
            "This nest doesn't say what machine it was packed on, and the check was "
            "required — nothing to compare against (FINGERPRINT_MISSING)."
        )
        if emitter is not None:
            emitter.log(summary, stage="S0", level="warning")
        return DoctorResult(
            int(ExitCode.S0_FINGERPRINT_MISSING), local_d, None, None, summary, storage=storage
        )

    precheck = None
    if with_host_checks:
        if _precheck is not None:
            precheck = _precheck
        else:
            runtime = manifest.get("runtime", {})
            cuda = (runtime.get("cuda_version") or "").replace(".", "")
            precheck = run_precheck(
                cuda_tag=f"cu{cuda}" if cuda else default_cuda_tag(),
                expected_driver=runtime.get("driver_version"),
                skip_net=skip_net,
                force=force,
                lock_text=lock_text,
                # **Deliberately not passing nest_gpu / nest_arch here.** Those switch
                # on two gates that can *refuse* a machine, and `renest doctor` has
                # never refused anything — turning it into a gate is a product change,
                # not a side effect of wiring up a new field. The refusing versions run
                # where they belong, in restore's own pre-flight.
                nest_captured_on=(manifest.get("gpu") or {}).get("captured_on"),
                nest_runtime=runtime,
            )
    precheck = precheck or PrecheckReport(forced=force)
    code = _verdict_exit_code(precheck, fp_verdict, force=force)

    coverage = gpu_coverage(_gpu_name if _gpu_name is not None else collect_gpu_name())

    parts = []
    if fp_verdict is not None:
        parts.append(fp_verdict.summary)
    if precheck.checks:
        parts.append(f"machine check {precheck.overall}")
    if coverage is not None and not coverage["tested"]:
        # Honesty: an untested card model changes no verdict; it only puts
        # "we have never seen this card" out in the open
        parts.append(
            f"we haven't tested {coverage['gpu']}, so this verdict errs on the cautious side"
        )
    if force:
        # Refusing is fine; ignoring in silence is not. Either way the user typed
        # --force and is entitled to know it was read, and what it did or did not buy.
        if code in _HARD_BLOCK:
            parts.append(
                "you asked to go ahead anyway (--force), and this one does not lift: "
                "the packages themselves will not install on this machine, so the "
                "download would be spent for nothing. The rebuild script that comes "
                "with the nest (.renest/escape/restore.sh) never refuses, if you want "
                "the files here regardless"
            )
        elif any(c.level == LEVEL_REJECT for c in precheck.checks):
            parts.append(
                "you asked to go ahead anyway (--force), so this rejection is not "
                "stopping the rebuild: the files will land, and what is written above "
                "is what to expect when you start it"
            )
    summary = "Verdict: " + "; ".join(parts) if parts else "Verdict: all clear"
    if emitter is not None:
        emitter.log(summary, stage="S0", level="warning" if code != 0 else "info")
    return DoctorResult(
        code,
        local_d,
        fp_verdict.to_dict() if fp_verdict is not None else None,
        precheck.to_dict() if precheck.checks else None,
        summary,
        coverage=coverage,
        storage=storage,
    )


def print_human(result: DoctorResult, stream=None) -> None:
    """Human-mode field table + one-line verdict (stderr; stdout stays clean)."""
    stream = stream if stream is not None else sys.stderr
    fp = result.fingerprint
    if fp:
        print("Field check (this machine / needed / verdict):", file=stream)
        for r in fp["rows"]:
            print(f"  {r['field']}: {r['local']} / {r['required']} / {r['verdict']}", file=stream)
    # The machine checks say **why**, and until 2026-08-11 none of them were
    # printed: the whole outcome collapsed into the two words "machine check
    # reject". Measured on a 2011 CPU with no avx2 -- it was refused, correctly,
    # and the report never once said the word avx2. A verdict whose reason is
    # invisible sends the user to fix the wrong thing.
    mc = result.precheck
    if mc and mc.get("checks"):
        print("Machine check (what and why):", file=stream)
        for c in mc["checks"]:
            mark = {LEVEL_PASS: "✓", LEVEL_WARN: "⚠", LEVEL_REJECT: "✗"}.get(c["level"], "·")
            print(f"  {mark} {c['name']}: {c['reason']}", file=stream)
    _print_storage(result.storage, stream)
    print(result.summary, file=stream)


def _print_storage(storage: dict | None, stream) -> None:
    """Print where the bucket key is kept, out in the open and unvarnished."""
    if not storage:
        return
    print("Your own bucket:", file=stream)
    if not storage.get("configured"):
        print(f"  ✗ {storage.get('problem', 'not set up')}", file=stream)
        if storage.get("hint"):
            print(f"    → {storage['hint']}", file=stream)
        return
    where = storage.get("path") or "environment variables"
    print(
        f"  {storage['provider']} · bucket {storage.get('bucket') or '(not set)'} · "
        f"region {storage.get('region') or '(not set)'} · "
        f"{storage.get('addressing')}-style",
        file=stream,
    )
    print(f"  key: plain text in {where}", file=stream)
    for warning in storage.get("warnings", []):
        print(f"  ⚠ {warning}", file=stream)


def storage_setup_hint(path: Path | None = None) -> str:
    """**Copy-pasteable** setup instructions for when no bucket is configured.

    Why hand over commands instead of writing the file for the user: a setup
    wizard was ruled out, and so was turning this read-only check into a command
    that writes files. Hand-editing a config file is a legitimate first-class
    path — rclone shows as much — and what actually has to be guaranteed is that
    **the file is 0600 from the moment it exists**. Hence ``install -m 600`` in
    one step for the first command, rather than a ``touch`` that creates the
    file with default permissions followed by a ``chmod``, which leaves a brief
    window where the key is exposed.

    Shown only under an **explicit** ``--storage``: users who only ever use the
    hosted side need no bucket of their own, so prompting them to configure one
    in the default output would be pestering.
    """
    target = path or user_config_path()
    return (
        "No bucket of your own is set up yet.\n"
        "\n"
        "1. In your storage provider's console, make a key that can only read and write\n"
        "   this one bucket. Don't use your main account key.\n"
        f"2. Create the config file so that only you can read it, from the start:\n"
        f"     mkdir -p {target.parent}\n"
        f"     install -m 600 /dev/null {target}\n"
        "3. Put this in it, with your own values:\n"
        "\n"
        "     [storage]\n"
        '     provider   = "b2"          # b2 | r2 | aws | other\n'
        '     endpoint   = "https://s3.us-west-004.backblazeb2.com"\n'
        '     bucket     = "my-nests"\n'
        '     access_key = "…"\n'
        '     secret_key = "…"\n'
        "\n"
        "4. Run this check again. It will tell you where the key is kept and whether\n"
        "   that spot is risky (inside a git repo, or in a folder that syncs to the cloud).\n"
        "\n"
        "Prefer not to keep a key on disk? Set RENEST_S3_ACCESS_KEY and\n"
        "RENEST_S3_SECRET_KEY in your shell instead — they win over the file."
    )


def print_storage_check(storage: dict | None, stream=None) -> None:
    """Human output for ``renest doctor --storage``. Read-only, writes nothing."""
    stream = stream if stream is not None else sys.stderr
    if storage is None:
        print(storage_setup_hint(), file=stream)
        return
    _print_storage(storage, stream)


def run_bucket_selftest(*, json_mode: bool = False):
    """Run one real round trip against an already-configured bucket.

    Every exception collapses into a single failed step: a check-up command must
    never blow up on its own, since it is the very command people reach for when
    they want to see what is wrong.
    """
    # Imported late: ``pack`` already imports this module, so this module cannot
    # import ``pack``/``byos`` at the top level (byos -> hosted -> pack ->
    # doctor would close the cycle).
    from .byos import BucketSelfTest, SelfTestResult, SelfTestStep
    from .pack import PackError

    try:
        creds = resolve_credentials()
    except ConfigError as e:  # pragma: no cover - storage_report catches it first
        return SelfTestResult(ok=False, steps=[SelfTestStep("read your bucket settings", False, e.human)])
    if creds.bucket_key is None:  # pragma: no cover - the caller checked already
        return None
    try:
        test = BucketSelfTest(
            creds.bucket_key,
            log=None if json_mode else (lambda m: print(m, file=sys.stderr)),
        )
    except PackError as e:
        return SelfTestResult(ok=False, steps=[SelfTestStep("read your bucket settings", False, e.human)])
    return test.run()


def print_selftest(result, stream=None) -> None:
    """Human output for the self-test result.

    On failure it gives **something the reader can act on**, not a raw S3 error
    code.
    """
    stream = stream if stream is not None else sys.stderr
    eff = result.effective
    print(
        f"Round-trip test on your bucket "
        f"(~{eff.get('bytes_each_way', 0) // (1024 * 1024)} MiB each way, then deleted):",
        file=stream,
    )
    for step in result.steps:
        mark = "✓" if step.ok else "✗"
        print(f"  {mark} {step.name}", file=stream)
        if step.detail and not step.ok:
            for line in _wrap(step.detail):
                print(f"      {line}", file=stream)
        elif step.detail:
            print(f"      {step.detail}", file=stream)
    if result.leftover_key:
        print(f"  ⚠ a test object was left behind: {result.leftover_key}", file=stream)
    print(
        "  → This bucket works with Renest." if result.ok
        else "  → Renest cannot use this bucket yet. Fix the ✗ above and run this again.",
        file=stream,
    )
    # **The command line stays dumb**: no subcommand's output may carry sign-up
    # or pricing links, may compute "how much upload the hosted side would save
    # you", or may hang a promotional tail off a success message. Commercial
    # information belongs on the website; the command line is a tool and nothing
    # else. Guard: `tests/consistency/test_cli_stays_quiet_about_selling.py`.


def _wrap(text: str, width: int = 74) -> list[str]:
    import textwrap

    return textwrap.wrap(text, width=width) or [text]


def emit_json(result: DoctorResult, stream=None) -> None:
    stream = stream if stream is not None else sys.stdout
    stream.write(json.dumps(result.to_dict(), ensure_ascii=False, indent=2) + "\n")


def add_arguments(parser) -> None:
    parser.add_argument(
        "nest_ref",
        nargs="?",
        help="path to a nest manifest (leave it out to just check this machine)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="go ahead despite warnings and non-blocking failures",
    )
    parser.add_argument(
        "--require-fingerprint",
        action="store_true",
        help="stop with FINGERPRINT_MISSING (66) when the nest doesn't say what "
        "machine it was packed on, instead of carrying on",
    )
    parser.add_argument(
        "--lock",
        help="path to the lockfile this nest installs from — lets us check that its "
        "NVIDIA packages all come from one CUDA release, and that this machine's "
        "driver is new enough for them",
    )
    parser.add_argument(
        "--skip-net",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="skip the download speed test (skipped by default)",
    )
    parser.add_argument(
        "--storage",
        action="store_true",
        help="check your own bucket end to end: where its key is kept and whether that "
        "spot is risky, then a real round-trip (sends ~10 MiB in three parts, reads it "
        "back, compares every byte, deletes it). Prints setup instructions when no "
        "bucket is set up yet",
    )


def run_from_args(args, emitter: EventEmitter) -> int:
    manifest = None
    if args.nest_ref:
        try:
            manifest = json.loads(Path(args.nest_ref).read_text())
        except (OSError, json.JSONDecodeError) as e:
            print(f"✗ Can't read that nest: {e}", file=sys.stderr)
            return int(ExitCode.USAGE)
    # doctor is a single-object command, not an NDJSON stream: keep the internal
    # narration off stdout so ``--json`` stays one clean JSON document.
    lock_text = None
    if getattr(args, "lock", None):
        try:
            lock_text = Path(args.lock).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"✗ Can't read that lockfile: {e}", file=sys.stderr)
            return int(ExitCode.USAGE)
    if getattr(args, "storage", False):
        # Read-only check-up of the storage side, kept separate from the machine
        # check-up: the question being asked is "is my bucket set up?", and
        # answering it should not force a run of the GPU and driver probes.
        # Nothing along this path writes a file.
        try:
            storage = storage_report()
        except ConfigError as e:  # pragma: no cover - storage_report swallows it
            print(f"✗ {e.human}", file=sys.stderr)
            return int(e.exit_code)
        selftest = None
        if storage is not None and storage.get("configured"):
            selftest = run_bucket_selftest(json_mode=args.json)
        if args.json:
            print(json.dumps(
                {"storage": storage, "selftest": selftest.to_dict() if selftest else None},
                ensure_ascii=False, indent=2,
            ))
        else:
            print_storage_check(storage, sys.stderr)
            if selftest is not None:
                print_selftest(selftest, sys.stderr)
        # Only a broken configuration (wrong file permissions, say) counts as a
        # failure; "no bucket configured yet" is a normal state, not an error.
        if storage is not None and storage.get("configured") is False:
            return int(ExitCode.CONFIG_OR_CREDENTIAL)
        if selftest is not None and not selftest.ok:
            return int(ExitCode.S1_STORAGE_UNAVAILABLE)
        return int(ExitCode.OK)

    result = doctor(
        manifest,
        force=args.force,
        require_fingerprint=args.require_fingerprint,
        skip_net=args.skip_net,
        lock_text=lock_text,
        emitter=None,
    )
    if args.json:
        emit_json(result)
    else:
        print_human(result, sys.stderr)
    # Every verdict here was reached using the compatibility facts on this machine, so
    # say so when they have gone stale -- on stderr, so --json output stays one clean
    # document. A warning only: old facts are a reason to look, never a reason to block.
    from .update_rules import warn_if_stale

    warn_if_stale(sys.stderr)
    return result.exit_code
