"""Exit codes and error_class canon. Single source of truth for this package.

Layout rules (frozen):

* ``0 / 2 / 3`` are pre-gate codes ("died before entering any stage").
* Staged codes: tens digit = stage (S1..S5 -> 1x..5x, S0 -> 6x), ones digit
  = error_class within the stage; ``x0`` is the stage's unclassified failure.
* ``error_class`` = exit-code name with the ``S?_`` prefix removed. A new
  class takes a free ones digit *within* its stage; crossing stages is a
  format change and goes through the version process.
* Producer split: the blocking S0 codes 60/61/62/63/64/66 come only from the
  agent layer (`renest doctor` / `renest restore`); restore.sh may exit S0
  with 65 and nothing else.
"""

from __future__ import annotations

import enum

__all__ = [
    "ExitCode",
    "ErrorClass",
    "STAGES",
    "PACK_STAGES",
    "RETRYABLE_ERROR_CLASSES",
    "EXIT_CODE_BY_STAGE_CLASS",
    "STAGE_CLASS_BY_EXIT_CODE",
    "exit_code_for",
    "stage_class_for",
    "NestFailure",
]

#: Restore stages (five-gate state machine plus S0 pre-check).
STAGES: tuple[str, ...] = ("S0", "S1", "S2", "S3", "S4", "S5")

#: Pack stages (contract 1.1). A pack failure reuses the closest
#: error_class / exit code; the error object's ``stage`` records ``P1..P4``.
PACK_STAGES: tuple[str, ...] = ("P1", "P2", "P3", "P4")


class ExitCode(enum.IntEnum):
    """Master plan 1.2 exit-code table, complete and verbatim."""

    # -- pre-gate (never entered a stage) --------------------------------
    OK = 0
    USAGE = 2
    CONFIG_OR_CREDENTIAL = 3

    # -- S0 pre-check (6x; replaces the retired 6/7 doctor codes) --------
    S0_UNKNOWN = 60
    S0_WARNING_UNCONFIRMED = 61
    S0_PYTHON_BLOCK = 62
    S0_CUDA_BLOCK = 63
    S0_ARCH_UNSUPPORTED = 64
    S0_DISK_INSUFFICIENT = 65
    S0_FINGERPRINT_MISSING = 66

    # -- S1 transfer (1x) -------------------------------------------------
    S1_UNKNOWN = 10
    S1_NETWORK_INTERRUPTED = 11
    S1_RANGE_THROTTLED = 12
    S1_CREDENTIAL_EXPIRED = 13
    S1_STORAGE_UNAVAILABLE = 14
    S1_MANIFEST_UNSUPPORTED = 15
    #: Storage answered "that object is not here". Kept apart from 11
    #: NETWORK_INTERRUPTED for one reason: retryability. Retrying will not make a
    #: missing object appear, so folding it into the network class makes automatic
    #: retries spin and sends the user off to check their connection.
    S1_OBJECT_MISSING = 16

    # -- S2 layout & byte verification (2x) -------------------------------
    S2_UNKNOWN = 20
    S2_PATH_CONFLICT = 21
    S2_PERMISSION_DENIED = 22
    S2_HASH_MISMATCH = 23  # lint / verify byte-level failures reuse this
    S2_SYMLINK_BROKEN = 24
    S2_DISK_FULL = 25  # ran out of space mid-write; pre-check catches -> 65
    #: A nest someone handed you wants to run ``post_install`` (the one free-text
    #: shell command a manifest can carry) and the recipient has not named the sender
    #: yet. Same way out as 37 UNTRUSTED_SOURCE: name the party you are trusting.
    #: Nests you packed yourself are not stopped here (the command is printed, then run).
    S2_UNTRUSTED_SETUP = 26

    # -- S3 environment build (3x) ----------------------------------------
    S3_UNKNOWN = 30
    S3_TORCH_CUDA_CONFLICT = 31
    S3_NODE_REQUIREMENTS_FAILED = 32
    S3_NODE_VERSION_CONFLICT = 33
    S3_PYTHON_MISMATCH = 34
    S3_SYSLIB_MISSING = 35
    S3_MANAGER_INCOMPATIBLE = 36
    S3_UNTRUSTED_SOURCE = 37  # lockfile installs from a host that is not on the
    # allow-list; --trust-unsafe-urls goes ahead anyway
    #: Installing dependencies could not reach upstream (no network, a proxy in the
    #: way, a mirror down, the artifact withdrawn). Must stay separate from 31: the
    #: installer's network errors carry URLs like `https://pypi.org/simple/torch/`,
    #: so matching stderr on "torch" reads a dead network as a CUDA version clash.
    S3_UPSTREAM_UNREACHABLE = 38

    # -- S4 application startup (4x) ---------------------------------------
    S4_UNKNOWN = 40
    S4_NODE_IMPORT_FAILED = 41
    S4_NODE_NOT_REGISTERED = 42
    S4_WORKFLOW_PATH_STALE = 43
    S4_STARTUP_CRASH = 44
    S4_NEED_USER_DATA = 45
    #: Rebuild correct, app still dies: a library owned by the operating system is not on
    #: this machine (a nest carries Python packages and code, never the OS). Same word as
    #: 35 one stage later — 35 is the compiler wanting headers, 46 the loader wanting a
    #: `.so`; kept out of 44 because the remedy is to install an OS package, not to debug
    #: the run. **Main path for a nest that runs to completion** — a fine-tuning run really
    #: does die on start. An image-gen app tolerates an extension that cannot import and
    #: starts anyway, so there a missing library usually lands on 55 — unless it is a core
    #: dependency (real machine 2026-08-12: app UP, failure only once the recipe went in).
    S4_SYSLIB_MISSING = 46

    # -- S5 workflow reproduction (5x) --------------------------------------
    S5_UNKNOWN = 50
    S5_NODE_RUNTIME_ERROR = 51
    S5_OOM_OR_SLOW = 52
    S5_ARCH_UNSUPPORTED_RUNTIME = 53  # pre-check escapee; echoes 64
    S5_IMAGE_MISMATCH = 54
    #: Same cause as 46 one gate later, and **the likelier of the two**: ComfyUI tolerates an
    #: extension that fails to import -- it logs it and starts anyway -- so a machine short of
    #: a system library often gets through start-up and only breaks when the recipe asks for
    #: that extension. Landing in the S5 catch-all made the report say "the test render failed"
    #: while the app's own log named `libGL.so.1` two lines down.
    S5_SYSLIB_MISSING = 55


class ErrorClass(enum.StrEnum):
    """error_class vocabulary (contract 1.3).

    Value = exit-code name minus the ``S?_`` prefix. ``UNKNOWN`` is shared
    by every stage (the ``x0`` slot), so the (stage, error_class) pair —
    not the class alone — is what maps to an exit code.
    """

    UNKNOWN = "UNKNOWN"
    # S0
    WARNING_UNCONFIRMED = "WARNING_UNCONFIRMED"
    PYTHON_BLOCK = "PYTHON_BLOCK"
    CUDA_BLOCK = "CUDA_BLOCK"
    ARCH_UNSUPPORTED = "ARCH_UNSUPPORTED"
    DISK_INSUFFICIENT = "DISK_INSUFFICIENT"
    FINGERPRINT_MISSING = "FINGERPRINT_MISSING"
    # S1
    NETWORK_INTERRUPTED = "NETWORK_INTERRUPTED"
    RANGE_THROTTLED = "RANGE_THROTTLED"
    CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
    STORAGE_UNAVAILABLE = "STORAGE_UNAVAILABLE"
    MANIFEST_UNSUPPORTED = "MANIFEST_UNSUPPORTED"
    OBJECT_MISSING = "OBJECT_MISSING"
    # S2
    PATH_CONFLICT = "PATH_CONFLICT"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    HASH_MISMATCH = "HASH_MISMATCH"
    SYMLINK_BROKEN = "SYMLINK_BROKEN"
    DISK_FULL = "DISK_FULL"
    UNTRUSTED_SETUP = "UNTRUSTED_SETUP"
    # S3
    TORCH_CUDA_CONFLICT = "TORCH_CUDA_CONFLICT"
    NODE_REQUIREMENTS_FAILED = "NODE_REQUIREMENTS_FAILED"
    NODE_VERSION_CONFLICT = "NODE_VERSION_CONFLICT"
    PYTHON_MISMATCH = "PYTHON_MISMATCH"
    SYSLIB_MISSING = "SYSLIB_MISSING"
    MANAGER_INCOMPATIBLE = "MANAGER_INCOMPATIBLE"
    UNTRUSTED_SOURCE = "UNTRUSTED_SOURCE"
    UPSTREAM_UNREACHABLE = "UPSTREAM_UNREACHABLE"
    # S4
    NODE_IMPORT_FAILED = "NODE_IMPORT_FAILED"
    NODE_NOT_REGISTERED = "NODE_NOT_REGISTERED"
    WORKFLOW_PATH_STALE = "WORKFLOW_PATH_STALE"
    STARTUP_CRASH = "STARTUP_CRASH"
    NEED_USER_DATA = "NEED_USER_DATA"
    # S5
    NODE_RUNTIME_ERROR = "NODE_RUNTIME_ERROR"
    OOM_OR_SLOW = "OOM_OR_SLOW"
    ARCH_UNSUPPORTED_RUNTIME = "ARCH_UNSUPPORTED_RUNTIME"
    IMAGE_MISMATCH = "IMAGE_MISMATCH"


#: retryable rule (contract 1.3): transient network/storage -> true;
#: deterministic failures (version conflicts, permissions, disk, SSIM) -> false.
RETRYABLE_ERROR_CLASSES: frozenset[ErrorClass] = frozenset(
    {
        ErrorClass.NETWORK_INTERRUPTED,
        ErrorClass.RANGE_THROTTLED,
        ErrorClass.STORAGE_UNAVAILABLE,
        # Unreachable upstream and an interrupted transfer are the same family: once
        # the network is back, re-running works, and dependency installation resumes
        # where it stopped anyway.
        ErrorClass.UPSTREAM_UNREACHABLE,
    }
)


def _build_maps() -> tuple[
    dict[tuple[str, ErrorClass], ExitCode], dict[int, tuple[str, ErrorClass]]
]:
    forward: dict[tuple[str, ErrorClass], ExitCode] = {}
    reverse: dict[int, tuple[str, ErrorClass]] = {}
    for member in ExitCode:
        stage, _, class_name = member.name.partition("_")
        if stage not in STAGES:
            continue  # pre-gate code (OK / USAGE / CONFIG_OR_CREDENTIAL)
        error_class = ErrorClass(class_name)
        forward[(stage, error_class)] = member
        reverse[member.value] = (stage, error_class)
    return forward, reverse


#: (stage, error_class) -> exit code. Derived mechanically from ExitCode names.
EXIT_CODE_BY_STAGE_CLASS, STAGE_CLASS_BY_EXIT_CODE = _build_maps()


def exit_code_for(stage: str, error_class: ErrorClass | str) -> ExitCode:
    """Canonical exit code for a (stage, error_class) pair.

    Raises ``KeyError`` if the pair is not in the frozen table — adding a
    class means editing :class:`ExitCode` (version process), never mapping
    on the fly.
    """
    return EXIT_CODE_BY_STAGE_CLASS[(stage, ErrorClass(error_class))]


def stage_class_for(exit_code: int) -> tuple[str, ErrorClass]:
    """Inverse lookup: exit code -> (stage, error_class)."""
    return STAGE_CLASS_BY_EXIT_CODE[exit_code]


class NestFailure(Exception):
    """Dual-track error carrier (contract 1.3 / CLI design 3.2).

    Carries everything both tracks need: the machine-readable error object
    (``to_error_object``) and the one-line human attribution
    (``format_human``).

    ``stage`` accepts S0..S5 (exit code derived from the canon) or P1..P4
    (pack reuses the closest error_class: pass the borrowed ``exit_code``
    explicitly; the error object still records the P-stage).
    """

    def __init__(
        self,
        stage: str,
        error_class: ErrorClass | str,
        human: str,
        *,
        detail: str = "",
        context: dict | None = None,
        exit_code: int | None = None,
    ) -> None:
        error_class = ErrorClass(error_class)
        if stage in STAGES:
            if error_class not in {c for s, c in EXIT_CODE_BY_STAGE_CLASS if s == stage}:
                error_class = ErrorClass.UNKNOWN
            resolved = int(exit_code_for(stage, error_class))
        elif stage in PACK_STAGES:
            if exit_code is None:
                raise ValueError(
                    f"pack stage {stage} reuses the closest error_class: "
                    "pass exit_code explicitly"
                )
            resolved = int(exit_code)
        else:
            raise ValueError(f"unknown stage: {stage!r}")
        if exit_code is not None and exit_code != resolved:
            raise ValueError(
                f"exit_code {exit_code} contradicts canon {resolved} for "
                f"({stage}, {error_class})"
            )
        self.stage = stage
        self.error_class = error_class
        self.exit_code = resolved
        self.retryable = error_class in RETRYABLE_ERROR_CLASSES
        self.human = human
        self.detail = detail or human
        self.context = dict(context or {})
        super().__init__(self.format_human())

    def format_human(self) -> str:
        """One-line human attribution, e.g. ``[S3/TORCH_CUDA_CONFLICT] …``."""
        return f"[{self.stage}/{self.error_class}] {self.human}"

    def to_error_object(self) -> dict:
        """Contract 1.3 error object (``type``/``ts`` added by the emitter)."""
        return {
            "stage": self.stage,
            "error_class": str(self.error_class),
            "exit_code": self.exit_code,
            "retryable": self.retryable,
            "detail": self.detail,
            "human": self.human,
            "context": self.context,
        }
