"""One-command restore orchestrator: a five-gate state machine.

S0 pre-check → S1 download → S2 layout (full sha256 re-verify, self-heal
re-pull, unpack) → S3 deps (uv) → S4 launch → S5 smoke → result. Failures raise
:class:`~renest.errors.NestFailure` with the exit codes from
``oss/specs/restore-protocol.md``; the state file
``<target>/.renest/state/restore-<nest_id>.json`` is a public contract, and a
mismatched ``nest_id`` refuses to resume.

S2 also runs the bad-byte structural probe: an all-green sha256 proves the bytes
match the package, not that the bucket was not storing a truncated download to
begin with. Those findings **never block**. This path never calls
``scripts/restore.sh`` and shares no code with it — parity rides on the shared
format and exit-code table; ComfyUI is only ever a subprocess.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import uuid
from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

import httpx

from .config import (
    ConfigError,
    Grant,
    SourceError,
    SourceErrorKind,
    load_grant,
    parse_iso8601,
    read_json_source,
)
from .doctor import LEVEL_WARN, PRECHECK_CLASS, PrecheckReport, run_precheck
from .download import (
    BlobSpec,
    ResolveReport,
    Source,
    SourcesExhausted,
    classify_source_failures,
    resolve,
)
from .errors import NestFailure, ErrorClass, ExitCode
from .events import EventEmitter, sanitise_terminal
from .gated import GatedAsset, check_reach, fetch_from_origin, find_token, gated_assets, summarise
from .integrity import probe_model_bytes
from .report import maybe_report_sink
from .roots import (
    ENV_ROOT_TOKEN,
    MAX_MANIFEST_FILES,
    FILE_ROOTS,
    ROOT_PATH_PATTERNS,
    bad_entrypoint_env,
    bad_root_entry,
    materialise_entrypoint_env,
    resolve_env_root_token,
    resolve_file_root,
    unsafe_relpath,
)
from .wheels import audit_lock_urls, dead_wheel_fallback

__all__ = [
    "FORMAT_VERSION",
    "SUPPORTED_FORMAT_VERSIONS",
    "GRANT_VERSION",
    "STATE_DIR_REL",
    "FILE_ROOTS",
    "ROOT_PATH_PATTERNS",
    "resolve_file_root",
    "LOCKFILE_LANDING_REL",
    "ImageMismatch",
    "ComfyUILauncher",
    "OneshotRunner",
    "OneshotResult",
    "resolve_argv0",
    "classify_deps_failure",
    "summarise_redactions",
    "LaunchHandle",
    "Journal",
    "PlanItem",
    "RestorePlan",
    "RestoreOptions",
    "RestoreReport",
    "StageResult",
    "restore",
]

FORMAT_VERSION = "2.7"
# 2.0 made `code_deps[].role` mandatory and dropped 1.3, so that the consumer
# side need not sniff /custom_nodes/ paths forever. 2.1 through 2.7 only added
# fields or relaxed required ones, so **every 2.x package still reads** —
# nothing here may tighten without a version bump.
SUPPORTED_FORMAT_VERSIONS = ("2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7")
GRANT_VERSION = "1"
GRANT_ENVELOPE_VERSION = "2"  # grant-code envelope (server token); redeems to a v1 payload
# When the free-tier retention window has this many days or fewer left, print a
# countdown line during restore (same threshold as the in-site reminder).
_RETENTION_NOTICE_DAYS = 30

# <target>/.renest/ layout (state-file path is a public contract; the rest
# are orchestrator implementation detail)
STATE_DIR_REL = ".renest/state"  # restore-<nest_id>.json lands here
STAGING_REL = ".renest/staging"  # code archives / lockfile staging
EVIDENCE_REL = ".renest/evidence"  # one evidence dir per run
ARCHIVES_REL = f"{STAGING_REL}/archives"
LOCK_REL = f"{STAGING_REL}/requirements.lock"  # working copy uv sync reads from
RECIPE_REL = f"{STAGING_REL}/workflow.json"  # the recipe of the run that worked

#: Which adapters keep a re-runnable recipe, and where its bytes land. The core
#: layer names no tool, so the pairing lives in one table instead of in the stage
#: logic; a fourth framework is one line here.
_RECIPE_BLOBS: tuple[tuple[str, str], ...] = (("comfyui", RECIPE_REL),)

# Where the lockfile lands when the nest does not say (every nest older than 2.6).
# From 2.6 on `python_lock.lockfile_path` carries the original relative path and
# wins: the fine-tuning frameworks keep their lock in a sub-directory, and this
# fixed spot moved the file somewhere the framework does not look.
LOCKFILE_LANDING_REL = "requirements.lock"


def _declared_relpath(value: object) -> str | None:
    """A relative path the nest declared, or None when it declared nothing usable."""
    return value if isinstance(value, str) and value and not unsafe_relpath(value) else None


def recipe_landing_rel(manifest: dict, adapter: str) -> str | None:
    """Where this adapter's recipe belongs (format 2.6), or None when the nest does
    not say.

    None is a real answer and must stay one: every nest older than 2.6 lands here, and
    **inventing a path is worse than leaving the file in staging** — a guess either
    overwrites something the user has or points at a place the app never reads, and in
    both cases nothing tells them so."""
    return _declared_relpath(((manifest.get("adapters") or {}).get(adapter) or {}).get(
        "workflow_path"
    ))


def _land_recipe(
    adapter: str,
    manifest: dict,
    staged: Path,
    target: Path,
    narrate: Callable[..., None],
) -> None:
    """Put the recipe of the run that worked back where it lived.

    Three branches, all three settled by the 2026-08-12 ruling: the nest says where →
    put it there; something **different** is already there → the user's copy wins and
    ours stays in staging; the nest does not say → staging, and say so. Putting a file
    down is not starting the app, so this is the escape hatch's business too."""
    rel = recipe_landing_rel(manifest, adapter)
    if rel is None:
        narrate(
            f"This nest doesn't record where its {adapter} recipe used to live, so it is "
            f"here instead: {staged}. Copy it wherever you keep your workflows.",
            stage="S2",
        )
        return
    dest = target / rel
    # `exists() and not is_file()` catches a directory sitting on that name. Without it
    # the two legs part company on this one square: copyfile raises here while the shell
    # `cp` drops the file *inside* that directory.
    if (dest.exists() and not dest.is_file()) or (
        dest.is_file() and _sha256_file(dest) != _sha256_file(staged)
    ):
        narrate(
            f"There is already a different {rel} here, so we left yours alone. The recipe "
            f"from this nest is here instead: {staged}.",
            stage="S2",
            level="warning",
        )
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(staged, dest)
    narrate(f"Recipe is back where it lived: {dest}", stage="S2")


def lock_landing_rel(manifest: dict) -> str:
    """Where the dependency lock belongs: what the nest says (2.6), else the fixed spot."""
    return _declared_relpath(
        (manifest.get("python_lock") or {}).get("lockfile_path")
    ) or LOCKFILE_LANDING_REL

DEFAULT_RETRY_ROUNDS = 3  # per-blob round retry (download layer already has source-level fallback)
DEFAULT_BACKOFF_BASE_S = 2.0  # inter-round exponential backoff base: 2s -> 4s -> 8s …
DEFAULT_SSIM_THRESHOLD = 0.98  # configurable

#: If dependency installation takes longer than this many seconds, tell the user
#: they can pick a package source closer to them. A healthy install with a nearby
#: source runs in a couple of minutes while the default source can take hours, so
#: this sits clearly above normal and far below "hours" — nagging every run is
#: worse than not warning at all.
SLOW_DEPS_SECONDS = 300

# Both numbers are measured, not guessed: fetching files one at a time loses
# badly to four in parallel, and the in-file ranged-segment engine cannot rescue
# it; four-way verification of large files was 2.6x faster than serial, and on a
# 64-core machine that ratio says the disk is the bottleneck, so more workers buy
# nothing.
FILE_WORKERS = 4
VERIFY_WORKERS = 4

STAGE_DESC = {
    "S0": "checking this machine",
    "S1": "downloading",
    "S2": "putting files in place",
    "S3": "installing dependencies",
    "S4": "starting up",
    "S5": "test render",
}

# journal blob state machine: pending -> downloaded -> verified.
# In the current impl resolve() atomically downloads+verifies, so ``downloaded``
# is never observed; the enum is reserved for a future streaming impl and
# consumers must not assume it is absent.
BLOB_PENDING = "pending"
BLOB_DOWNLOADED = "downloaded"
BLOB_VERIFIED = "verified"


def _iso_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _tail(path: Path, n_chars: int = 600) -> str:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return "<could not read the log>"
    return text[-n_chars:].replace("\n", " ⏎ ")


class ImageMismatch(RuntimeError):
    """S5 image comparison below threshold (-> IMAGE_MISMATCH/54). An injected
    Launcher may raise it."""

    def __init__(self, ssim: float, threshold: float, message: str = ""):
        self.ssim = ssim
        self.threshold = threshold
        super().__init__(message or f"image similarity {ssim} is below the {threshold} threshold")


# --------------------------------------------------------------------------
# journal (public-contract state file)
# --------------------------------------------------------------------------
class Journal:
    """State file = ``<target>/.renest/state/restore-<nest_id>.json`` (public
    contract).

    Contract fields: nest_id / started_at / stages / resume_token; ``blobs`` is an
    orchestrator extension (the content-addressed resume ledger). Atomic writes
    (tmp+replace): a crash leaves no half-written file. A stale state with a
    mismatched nest_id is discarded (never resume nest B off nest A's state)."""

    def __init__(self, target: Path, nest_id: str):
        self.path = target / STATE_DIR_REL / f"restore-{nest_id}.json"
        # S1 runs several download threads that mark blobs concurrently, while
        # save() is a read-modify-write of the whole file — without a lock two
        # threads would overwrite the entries the other just wrote into data.
        self._lock = threading.Lock()
        self.data: dict = {
            "journal_version": 1,
            "nest_id": nest_id,
            "started_at": _iso_now(),
            "resume_token": None,
            "stages": {},
            "blobs": {},
        }

    def load_if_matching(self) -> None:
        try:
            d = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError):
            return
        if d.get("journal_version") == 1 and d.get("nest_id") == self.data["nest_id"]:
            self.data = d

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=1))
        os.replace(tmp, self.path)  # atomic cross-platform rename

    def blob(self, sha256: str) -> dict:
        return self.data["blobs"].get(sha256, {})

    def mark_blob(self, sha256: str, status: str, dest: Path) -> None:
        with self._lock:
            self.data["blobs"][sha256] = {"status": status, "dest": str(dest)}
            self.save()

    def stage(self, key: str) -> dict:
        return self.data["stages"].get(key, {})

    def mark_stage(self, key: str, **info: Any) -> None:
        with self._lock:
            self.data["stages"][key] = info
            self.save()


# --------------------------------------------------------------------------
# plan
# --------------------------------------------------------------------------
#: Bytes at these addresses never cross the public internet: this machine, the
#: local network, and plain local file paths.
#: The test is deliberately strict — anything we cannot recognise counts as
#: internet (see RestorePlan.bulk_comes_from_internet).
_LOCAL_HOST_PREFIXES = ("127.", "10.", "192.168.", "169.254.")


def _is_local_url(url: str) -> bool:
    from urllib.parse import urlparse

    u = urlparse(str(url))
    if u.scheme in ("file", ""):
        return True
    host = (u.hostname or "").lower()
    if host in ("localhost", "::1"):
        return True
    if any(host.startswith(p) for p in _LOCAL_HOST_PREFIXES):
        return True
    if host.startswith("172."):          # only 172.16.0.0 ~ 172.31.255.255 is private
        try:
            return 16 <= int(host.split(".")[1]) <= 31
        except (IndexError, ValueError):
            return False
    return False


@dataclass
class PlanItem:
    sha256: str
    size_bytes: int
    dest: Path  # absolute landing path
    sources: list[Source]
    role: str  # asset / code_archive / python_lock / recipe
    label: str  # human-readable identifier (relpath or dep name); events use it


@dataclass
class RestorePlan:
    """The rebuild plan derived from a manifest (+ grant blobmap)."""

    nest_id: str
    target: Path
    items: list[PlanItem]
    python_version: str
    lock_sha256: str
    lock_landing: Path  # where the lockfile lands (target/LOCKFILE_LANDING_REL)
    app_dir: Path  # S4 launch working dir (where the host app lands)
    entrypoint: dict | None = None  # v2.0 manifest.entrypoint; absent = legacy path
    #: The image the nest was packed on, as the manifest recorded it. Carried this far
    #: for one reason: when the app dies for want of a system library, the surest fix is
    #: not installing that one library -- it is booting this image, which brings all of
    #: them. Recorded since v2.0 and, until 2026-08-12, never once read on this side.
    base_image_ref: str | None = None

    @property
    def total_bytes(self) -> int:
        return sum(i.size_bytes for i in self.items)

    @property
    def asset_items(self) -> list[PlanItem]:
        return [i for i in self.items if i.role == "asset"]

    @property
    def bulk_comes_from_internet(self) -> bool:
        """Whether any bulk file this rebuild pulls comes from the internet.

        The pre-flight bandwidth gate is aimed at rented cloud machines: measure
        the downlink before paying for an hour that dies twenty-odd GB in. When
        the files sit on this machine or the local network none of those bytes
        cross the internet, so failing the run over a slow home link and telling
        the user to rent a different machine is nonsense.

        The test is **strict**: one unrecognised source makes the whole run
        count as internet-bound.
        """
        return any(
            not _is_local_url(src.url) for item in self.items for src in item.sources
        )

    @classmethod
    def from_manifest(
        cls,
        manifest: dict,
        target: Path,
        blob_base: str = "",
        blobmap: dict[str, list[str]] | None = None,
    ) -> RestorePlan:
        blobmap = blobmap or {}

        def mk_sources(blob: dict, declared: list[dict] | None = None) -> list[Source]:
            h = blob["sha256"]
            srcs: list[Source] = []
            # grant blobmap primary first: first = authoritative, rest = mirror
            for i, url in enumerate(blobmap.get(h, [])):
                srcs.append(
                    Source(
                        url=url,
                        kind="authoritative" if i == 0 else "mirror",
                        note="restore-grant blobmap",
                    )
                )
            srcs += [
                Source(url=s["url"], kind=s["kind"], note=s.get("note", ""))
                for s in (declared or [])
            ]
            if blob_base:
                srcs.append(
                    Source(
                        url=f"{blob_base.rstrip('/')}/{h[:2]}/{h}",
                        kind="authoritative",
                        note="built from blob_base",
                    )
                )
            return srcs

        items: list[PlanItem] = []
        for dep in manifest["code_deps"]:
            blob = dep["archive"]
            items.append(
                PlanItem(
                    sha256=blob["sha256"],
                    size_bytes=int(blob["size_bytes"]),
                    dest=target / ARCHIVES_REL / f"{dep['name']}.tar.gz",
                    sources=mk_sources(blob),
                    role="code_archive",
                    label=dep["name"],
                )
            )
        lock = manifest["python_lock"]["lockfile"]
        items.append(
            PlanItem(
                sha256=lock["sha256"],
                size_bytes=int(lock["size_bytes"]),
                dest=target / LOCK_REL,
                sources=mk_sources(lock),
                role="python_lock",
                label="requirements.lock",
            )
        )
        # The recipe of the run that worked. **Packed into every nest and, until
        # 2026-08-11, never fetched back**: the download plan covered files[] and
        # the lockfile only, while this blob sits outside files[] under adapters.
        # Verified on a real nest -- the bytes were in the store, and no restore
        # ever asked for them. So we paid to keep it and could not re-run it,
        # which is also why the run gate had nothing to run.
        for _adapter, _rel in _RECIPE_BLOBS:
            _ref = ((manifest.get("adapters") or {}).get(_adapter) or {}).get("workflow")
            if not (isinstance(_ref, dict) and _ref.get("sha256")):
                continue
            items.append(
                PlanItem(
                    sha256=_ref["sha256"],
                    size_bytes=int(_ref.get("size_bytes") or 0),
                    dest=target / _rel,
                    sources=mk_sources(_ref),
                    role="recipe",
                    label=f"{_adapter} workflow",
                )
            )
        for f in manifest["files"]:
            blob = f["blob"]
            # The landing root comes from files[].root. Bytes always land the
            # same way: download to <dest>.part, verify sha256, atomic rename,
            # **always a real file**. Never symlinks, never a rebuilt blobs/ —
            # kohya resolves realpath and then classifies by extension alone, so
            # a link target without the extension raises _pickle.UnpicklingError
            # nowhere near the real cause. Nobody may later "save disk space
            # with symlinks".
            root = f.get("root", "env")
            items.append(
                PlanItem(
                    sha256=blob["sha256"],
                    size_bytes=int(blob["size_bytes"]),
                    dest=resolve_file_root(root, target) / f["path"],
                    sources=mk_sources(blob, f.get("sources")),
                    role="asset",
                    label=f["path"] if root == "env" else f"{root}:{f['path']}",
                )
            )

        # S4's working directory: entrypoint.cwd first (the format decides), then
        # code_deps[].role == "host". **Never inferred from name == "comfyui"** —
        # that drags a ComfyUI-specific noun into the core layer and is always
        # wrong for the fine-tuning frameworks.
        deps = manifest["code_deps"]
        entrypoint = manifest.get("entrypoint")
        if isinstance(entrypoint, dict) and entrypoint.get("cwd"):
            app_dir = target / entrypoint["cwd"]
        else:
            host = next(
                (d for d in deps if d.get("role") == "host"), deps[0] if deps else None
            )
            app_dir = target / host["install_path"] if host else target
        return cls(
            nest_id=manifest.get("id", ""),
            target=target,
            items=items,
            python_version=manifest["runtime"]["python_version"],
            lock_sha256=lock["sha256"],
            lock_landing=target / lock_landing_rel(manifest),
            app_dir=app_dir,
            entrypoint=entrypoint if isinstance(entrypoint, dict) else None,
            base_image_ref=(manifest.get("base_image") or {}).get("ref") or None,
        )


# --------------------------------------------------------------------------
# launcher
# --------------------------------------------------------------------------
@dataclass
class LaunchHandle:
    proc: Any
    port: int
    log_path: Path
    logf: Any = None
    smoke_path: str = "/object_info"  # v2.0: entrypoint.ready_probe.smoke_get
    #: The recipe of the run that worked, once it has landed. Present -> the smoke
    #: step re-runs it for real instead of only asking whether the app answers.
    recipe_path: Path | None = None
    #: Set when a recipe landed but the nest carries no evidence it ever produced
    #: anything -- packing a mid-debugging environment must not be refused.
    #: Re-running an unverified recipe would report a false failure -- the
    #: environment isn't broken, the recipe just never worked -- so the smoke
    #: step skips it and says why.
    unverified_note: str | None = None


@dataclass
class OneshotResult:
    """Result of one ``kind=oneshot`` execution."""

    exit_code: int
    seconds: float
    log_path: Path


def resolve_argv0(argv0: str, env_root: Path, python_bin: Path) -> Path:
    """Work out which file ``entrypoint.argv[0]`` actually runs, and block
    "run anything at all that happens to be on this system".

    **Constraint: the resolved path must stay inside the rebuild root.** A nest
    may only run the code it brought with it — a handed-off nest is somebody
    else's bytes, and `entrypoint` is the single entry for "what gets executed on
    your machine". Without this, `argv` could simply read `bash -c "curl … | sh"`.

    Three rules, the same set as the service branch:
    - an interpreter name such as `python` / `python3.11` → swapped for the one
      we rebuilt;
    - anything containing `/` → treated as a path relative to the rebuild root
      (escapes are rejected here);
    - a bare name → **looked up only in the nest's own venv bin**, never on the
      system PATH.
    """
    name = PurePosixPath(argv0).name
    if name.startswith("python"):
        return python_bin
    if "/" in argv0:
        if unsafe_relpath(argv0):
            raise NestFailure(
                "S4",
                ErrorClass.MANIFEST_UNSUPPORTED,
                f"This nest wants to run something outside the folder being rebuilt: {argv0!r}. "
                "A nest may only run code it brought with it — refusing.",
            )
        return env_root / argv0
    # Bare name: only the nest's own venv, never the system PATH (what happens to
    # be installed on this system is not the nest's decision to make)
    return python_bin.parent / argv0


class OneshotRunner:
    """``entrypoint.kind == "oneshot"``: run to completion, verdict = exit code.

    Both fine-tuning frameworks have this shape. The only difference from
    :class:`ComfyUILauncher` is what counts as success: that one waits on an HTTP
    probe, this one waits for the process to exit.

    Subprocess only, never import any framework code (GPL isolation). All output
    goes to ``log_path`` — a training crash leaves its scene there, and it must
    not live only in the stdout of a single ssh session.
    """

    def __init__(self, timeout_s: float = 6 * 3600.0):
        self.timeout_s = timeout_s

    def run(
        self,
        env_root: Path,
        entrypoint: dict,
        python_bin: Path,
        log_path: Path,
    ) -> OneshotResult:
        argv_spec = list(entrypoint.get("argv") or [])
        if not argv_spec:
            raise NestFailure(
                "S4", ErrorClass.MANIFEST_UNSUPPORTED, "This nest's entrypoint has no command to run."
            )
        exe = resolve_argv0(argv_spec[0], env_root, python_bin)
        argv = [str(exe), *argv_spec[1:]]

        cwd = env_root / (entrypoint.get("cwd") or ".")
        # env: gate first, then join against the root, and pass only the allowlist
        try:
            extra_env = materialise_entrypoint_env(entrypoint.get("env"), env_root)
        except ValueError as e:
            raise NestFailure(
                "S4",
                ErrorClass.MANIFEST_UNSUPPORTED,
                f"This nest's start-up settings put something where it does not belong: {e}. Refusing to run it.",
            ) from e
        env = dict(os.environ)
        env.update(extra_env)
        # The venv's bin must be on PATH: accelerate spawns an accelerate-launch
        # subcommand, so an absolute path alone gives FileNotFoundError.
        env["PATH"] = f"{python_bin.parent}{os.pathsep}{env.get('PATH', '')}"

        log_path.parent.mkdir(parents=True, exist_ok=True)
        t0 = time.monotonic()
        with log_path.open("wb") as logf:
            logf.write(f"$ (cwd={cwd}) {' '.join(argv)}\n".encode())
            logf.flush()
            try:
                proc = subprocess.Popen(  # noqa: S603
                    argv, cwd=str(cwd), stdout=logf, stderr=subprocess.STDOUT, env=env
                )
            except OSError as e:
                raise NestFailure(
                    "S4", ErrorClass.STARTUP_CRASH, f"Could not start {argv[0]}: {e}"
                ) from e
            try:
                rc = proc.wait(timeout=self.timeout_s)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=30)
                raise NestFailure(
                    "S4",
                    ErrorClass.STARTUP_CRASH,
                    f"This nest's run did not finish within {self.timeout_s / 3600:.1f} hours. "
                    f"Its log is at {log_path}",
                ) from None
        return OneshotResult(exit_code=rc, seconds=round(time.monotonic() - t0, 3), log_path=log_path)


class ComfyUILauncher:
    """Default launcher: subprocess ComfyUI, poll /system_stats, smoke via
    /object_info.

    GPL isolation: subprocess only, never imports ComfyUI code. The launch log
    streams to ``log_path`` (the crash-scene original). ``ssim_threshold`` is
    passed through for interface completeness — the default impl is a
    service-level smoke; image comparison is carried by an injected Launcher that
    raises :class:`ImageMismatch` below threshold."""

    def __init__(
        self,
        ready_timeout_s: float = 300.0,
        poll_interval_s: float = 5.0,
        ssim_threshold: float = DEFAULT_SSIM_THRESHOLD,
        render_timeout_s: float = 1800.0,
    ):
        self.ready_timeout_s = ready_timeout_s
        self.poll_interval_s = poll_interval_s
        self.ssim_threshold = ssim_threshold
        # Half an hour to draw. A cap, not an estimate: a run that never finishes
        # must end in a stated failure, never in a hang and never in a pass.
        self.render_timeout_s = render_timeout_s

    def launch(
        self,
        app_dir: Path,
        python_bin: Path,
        log_path: Path,
        entrypoint: dict | None = None,
    ) -> LaunchHandle:
        """Read the command and the probe from ``manifest.entrypoint``; absent or
        not a service falls back to the legacy hard-coded shape.

        Two argv adaptations stay here as adapter-layer knowledge, out of the
        core format: a python ``argv[0]`` is swapped for the interpreter we
        rebuilt, and a free port is appended when argv carries no ``--port``
        (the port is only knowable at rebuild time).
        """
        ep = entrypoint if isinstance(entrypoint, dict) and entrypoint.get("kind") == "service" else {}
        probe = ep.get("ready_probe") or {}
        ready_path = probe.get("http_get") or "/system_stats"
        smoke_path = probe.get("smoke_get") or "/object_info"
        timeout_s = float(probe.get("timeout_s") or self.ready_timeout_s)

        argv: list[str] = list(ep.get("argv") or [])
        if argv:
            if Path(argv[0]).name.startswith("python"):
                argv = [str(python_bin)] + argv[1:]
        else:
            main_py = app_dir / "main.py"
            if not main_py.is_file():
                raise RuntimeError(f"Cannot find {main_py} — is the app missing from this nest?")
            argv = [str(python_bin), "main.py", "--listen", "127.0.0.1"]
        port = _free_port()
        if "--port" not in argv:
            argv += ["--port", str(port)]
        else:
            port = int(argv[argv.index("--port") + 1])

        log_path.parent.mkdir(parents=True, exist_ok=True)
        logf = log_path.open("wb")
        proc = subprocess.Popen(  # noqa: S603
            argv,
            cwd=str(app_dir),
            stdout=logf,
            stderr=subprocess.STDOUT,
        )
        handle = LaunchHandle(proc=proc, port=port, log_path=log_path, logf=logf, smoke_path=smoke_path)
        url = f"http://127.0.0.1:{port}{ready_path}"
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                logf.close()
                raise RuntimeError(
                    f"The app stopped with code {proc.returncode}. "
                    f"End of its log: {_tail(log_path)} — full log at {log_path}"
                )
            try:
                if httpx.get(url, timeout=5.0).status_code == 200:
                    return handle
            except httpx.HTTPError:
                pass
            time.sleep(self.poll_interval_s)
        self.shutdown(handle)
        raise RuntimeError(f"The app did not come up within {timeout_s:.0f}s. Log: {log_path}")

    def smoke(self, handle: LaunchHandle) -> str:
        """Re-run the recipe when the nest carries one; otherwise ask the app if it answers.

        The most expensive lesson in this project (2026-07-13) is that **checking
        files cannot stand in for running the thing**: every byte matched and the
        environment was dead. Until 2026-08-11 this step only fetched a page and
        reported "the app answered", which reads like a render and is not one.
        With the recipe on disk it now submits the very run that worked and
        insists something came out.
        """
        if handle.recipe_path is not None and handle.recipe_path.is_file():
            return self._rerun_recipe(handle)
        path = handle.smoke_path
        r = httpx.get(f"http://127.0.0.1:{handle.port}{path}", timeout=30.0)
        if r.status_code != 200:
            raise RuntimeError(f"{path} HTTP {r.status_code}")
        classes = r.json()
        if not isinstance(classes, dict) or not classes:
            raise RuntimeError("The app reports no nodes at all — its node registry did not load")
        if handle.unverified_note:
            return (
                f"The app answered and loaded {len(classes)} node types. "
                f"**Skipped re-running the recipe** — {handle.unverified_note} Re-running it "
                f"would report a false failure, not a broken environment: everything else was "
                f"restored byte-for-byte, exactly as it was."
            )
        # Say plainly that nothing was drawn. The old wording ("the app answered
        # normally") was read as evidence of a render for weeks.
        return (
            f"The app answered and loaded {len(classes)} node types. "
            f"**Nothing was rendered** — this nest carries no recipe to re-run, "
            f"so this is a liveness check, not proof that it still produces images."
        )

    def _rerun_recipe(self, handle: LaunchHandle) -> str:
        """Submit the packed recipe and require an output. Raises on anything else.

        Not one field of the recipe is altered -- the question is whether *this*
        run still produces something here, and a fresh seed would answer a
        different question.
        """
        base = f"http://127.0.0.1:{handle.port}"
        recipe = json.loads(handle.recipe_path.read_text(encoding="utf-8"))
        started = time.monotonic()
        r = httpx.post(f"{base}/prompt", json={"prompt": recipe}, timeout=60.0)
        if r.status_code != 200:
            raise RuntimeError(f"the app refused the recipe: HTTP {r.status_code} {r.text[:300]}")
        prompt_id = (r.json() or {}).get("prompt_id")
        if not prompt_id:
            raise RuntimeError(f"the app accepted nothing back: {r.text[:300]}")
        deadline = time.monotonic() + self.render_timeout_s
        while time.monotonic() < deadline:
            if handle.proc.poll() is not None:
                raise RuntimeError(
                    f"the app died while rendering (code {handle.proc.returncode}); "
                    f"end of its log: {_tail(handle.log_path)}"
                )
            try:
                entry = (httpx.get(f"{base}/history/{prompt_id}", timeout=15.0).json()
                         or {}).get(prompt_id)
            except Exception:  # noqa: BLE001 - a poll that fails is a poll, not a verdict
                entry = None
            if entry:
                status = entry.get("status") or {}
                if status.get("status_str") == "error":
                    raise RuntimeError(
                        "the app reported an error while running the packed recipe: "
                        f"{json.dumps(status.get('messages') or [])[:400]}"
                    )
                if status.get("completed"):
                    images = sum(len(o.get("images") or [])
                                 for o in (entry.get("outputs") or {}).values())
                    if not images:
                        raise RuntimeError(
                            "the recipe ran to completion but produced no image. Either this "
                            "nest's recipe saves nothing, or the rebuild is not equivalent."
                        )
                    return (f"Re-ran the packed recipe and it produced {images} image(s) "
                            f"in {time.monotonic() - started:.0f}s")
            time.sleep(3.0)
        raise RuntimeError(
            f"the packed recipe was still running after {self.render_timeout_s:.0f}s; "
            f"giving up rather than reporting a pass"
        )

    def shutdown(self, handle: LaunchHandle) -> None:
        with contextlib.suppress(Exception):
            handle.proc.terminate()
            handle.proc.wait(timeout=10)
        with contextlib.suppress(Exception):
            handle.proc.kill()
        with contextlib.suppress(Exception):
            if handle.logf:
                handle.logf.close()


# --------------------------------------------------------------------------
# options / report
# --------------------------------------------------------------------------
def _default_runner(
    cmd: list[str], env: dict | None = None, cwd: str | None = None
) -> subprocess.CompletedProcess:
    """Default command executor (uv / post_install). Tests inject a fake."""
    merged = {**os.environ, **(env or {})}
    try:
        return subprocess.run(  # noqa: S603
            cmd, env=merged, cwd=cwd, capture_output=True, text=True
        )
    except FileNotFoundError as e:
        return subprocess.CompletedProcess(cmd, 127, "", str(e))
    except OSError as e:
        return subprocess.CompletedProcess(cmd, 126, "", str(e))


@dataclass
class RestoreOptions:
    skip_precheck: bool = False
    force: bool = False  # continue after a precheck reject (report still records truthfully)
    resume: bool = True  # resume (default on)
    reverify: bool = False  # on resume, re-hash already-verified files
    json_events: bool = False
    no_report: bool = False  # turn off grant-mode progress uplink (never blocks restore)
    verbose: bool = False  # also narrate to stderr
    #: The user typed --verbose themselves. Kept apart from ``verbose`` because a
    #: terminal turns narration on by itself, and "show me progress" must not be
    #: read as "print every disclosure field on every run".
    verbose_explicit: bool = False
    skip_launch: bool = False  # rebuild only, don't launch (no-GPU env; S4/S5 recorded skipped)
    trust_unsafe_urls: bool = False  # blanket bypass of the dep-source allowlist (automation only)
    #: Named hosts to allow. What makes this safer than trust_unsafe_urls is not
    #: technical, it is **human**: the user has to type that hostname out
    #: themselves, and so they see what they are trusting.
    #: Our error messages only teach this option, never the blanket bypass —
    #: otherwise we would be writing the attacker's bypass instructions for them.
    trust_hosts: tuple[str, ...] = ()
    #: Where dependencies are installed from. Empty = the default place; a nearby
    #: mirror can turn hours of installing into minutes. **This is only safe
    #: because the manifest records a content fingerprint per package**, which
    #: makes switching source a pure speed knob — mismatched bytes stop the
    #: rebuild. The address still has to pass the dependency-source allowlist.
    package_source: str = ""
    #: Name a sender as "I trust this person". Only meaningful for a nest someone
    #: handed off to you, and it must match the sender display name the server
    #: attests — what the receiver really has to judge is the person, not a
    #: domain.
    trust_sender: str = ""
    #: Skip ``post_install`` entirely (both top-level and dependency-level). For
    #: the "unknown provenance, I only want the bytes" case: the nest did not
    #: reach the user **through us** (no sender in the payload), so the gate
    #: cannot tell whether to block, but the user knows their own situation.
    #: Skipping is recorded truthfully in the report — the environment may be
    #: incomplete as a result, and that was their choice.
    no_setup: bool = False
    #: Check only, do not rebuild: probe whether the assets that do not travel
    #: with the nest are reachable on this machine, print the result and exit.
    #: **No GPU needed, runs on a laptop** — spend a minute first instead of
    #: twenty minutes plus machine cost.
    check_only: bool = False
    blob_base: str = ""  # path-pattern blob root URL when manifest has no sources
    retry_rounds: int = DEFAULT_RETRY_ROUNDS
    backoff_base_s: float = DEFAULT_BACKOFF_BASE_S
    ssim_threshold: float = DEFAULT_SSIM_THRESHOLD
    # injection seams (the key to zero-network zero-real-dep tests)
    precheck_fn: Callable[..., PrecheckReport] | None = None
    runner: Callable[..., subprocess.CompletedProcess] | None = None
    launcher: Any = None
    oneshot_runner: Any = None  # injection seam (tests); None = default OneshotRunner
    client: httpx.Client | None = None
    event_sink: Callable[[dict], None] | None = None


@dataclass
class StageResult:
    name: str  # S0..S5
    ok: bool
    seconds: float
    detail: str = ""


@dataclass
class RestoreReport:
    """Full account of one restore: per-stage result + timing, failure
    attribution (error object), precheck original."""

    ok: bool = False
    nest_id: str = ""
    exit_code: int = int(ExitCode.OK)
    stages: list[StageResult] = field(default_factory=list)
    failure: dict | None = None  # error object (no type/ts)
    precheck: dict | None = None
    metrics: dict = field(default_factory=dict)
    evidence_dir: str = ""
    blobs_total: int = 0
    blobs_downloaded: int = 0
    blobs_cached: int = 0
    #: Findings from the bad-byte structural check: the bytes match the package
    #: but do not look like complete weights. Reported only, never blocking.
    integrity_warnings: list[str] = field(default_factory=list)
    #: Packages whose pinned wheel was withdrawn and that were installed from a
    #: generic build instead. Warn in plain language, never silently.
    wheel_fallbacks: list[str] = field(default_factory=list)
    oneshot: dict | None = None  # kind=oneshot result (exit code / duration / log)
    #: Spots the user must point back at their own data after the rebuild
    redactions: list[str] = field(default_factory=list)
    #: The CUDA version torch itself reports after dependency install, compared
    #: against what the nest declared
    checks_after_deps: dict = field(default_factory=dict)
    #: Install commands skipped by ``--no-setup``. **A skip must stay in the
    #: report** — the environment may be incomplete because of it, and when
    #: somebody later asks "why did it install but not run", this line is the
    #: answer.
    setup_skipped: list[str] = field(default_factory=list)
    #: Assets that do not travel with the nest and must be fetched from source,
    #: and whether each is reachable **on this machine**.
    #: This makes "do I need to go accept something right now" answerable before
    #: the run starts, instead of discovering missing files at the end.
    gated: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "nest_id": self.nest_id,
            "exit_code": self.exit_code,
            "stages": [asdict(s) for s in self.stages],
            "failure": self.failure,
            "precheck": self.precheck,
            "metrics": self.metrics,
            "evidence_dir": self.evidence_dir,
            "blobs_total": self.blobs_total,
            "blobs_downloaded": self.blobs_downloaded,
            "blobs_cached": self.blobs_cached,
            "integrity_warnings": self.integrity_warnings,
            "wheel_fallbacks": self.wheel_fallbacks,
            "oneshot": self.oneshot,
            "redactions": self.redactions,
            "checks_after_deps": self.checks_after_deps,
            "setup_skipped": self.setup_skipped,
            "gated": self.gated,
        }


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _extract_strip1(archive: Path, dest: Path) -> int:
    """Equivalent to ``tar --strip-components=1``: strip the archive's top dir
    then land into ``dest``. Safe: rejects absolute / ``..`` escaping members;
    uses the ``data`` filter where available (3.11.4+).

    Returns how many members actually landed. **The count matters**: a code
    folder that was a symlink tars into a single top-level link entry, which
    strip-1 drops — so the archive verifies byte-perfect and unpacks to nothing.
    The caller turns 0 into a loud failure; see :func:`_place_code_dep_or_die`."""
    dest.mkdir(parents=True, exist_ok=True)
    placed = 0
    with tarfile.open(archive, "r:gz") as tf:
        for m in tf.getmembers():
            parts = Path(m.name).parts
            if len(parts) < 2:
                continue  # top dir / top-level loose file, matches tar behaviour
            rel = Path(*parts[1:])
            if rel.is_absolute() or ".." in rel.parts:
                raise ValueError(f"This archive tries to write outside the target directory: {m.name}")
            m.name = str(rel)
            try:
                tf.extract(m, dest, filter="data")
            except TypeError:  # < 3.11.4 has no filter arg
                tf.extract(m, dest)
            placed += 1
    return placed


def _cuda_tag(cuda_version: str) -> str:
    """manifest runtime.cuda_version ("12.4") -> precheck floor-table tag ("cu124")."""
    v = (cuda_version or "").strip()
    return "cu" + v.replace(".", "") if v else ""


def _load_json_input(source: Any, client: httpx.Client) -> dict:
    """dict / local path / URL -> dict. Failures attributed under S1.

    Dispatching between the three input shapes belongs to
    :func:`config.read_json_source` (single entry point, with size/timeout
    guardrails); this only translates its :class:`SourceError` into the restore
    side's error picture."""
    try:
        return read_json_source(source, client=client)
    except SourceError as e:
        raise _source_failure(e, str(source)) from e


#: SourceErrorKind -> restore-side attribution (wording kept word for word)
_SOURCE_ERROR_CLASS = {
    SourceErrorKind.NETWORK: ErrorClass.NETWORK_INTERRUPTED,
    SourceErrorKind.DENIED: ErrorClass.CREDENTIAL_EXPIRED,
    SourceErrorKind.STATUS: ErrorClass.STORAGE_UNAVAILABLE,
    SourceErrorKind.READ: ErrorClass.UNKNOWN,
    SourceErrorKind.TOO_LARGE: ErrorClass.MANIFEST_UNSUPPORTED,
    SourceErrorKind.NOT_JSON: ErrorClass.MANIFEST_UNSUPPORTED,
}


def _source_failure(e: SourceError, source: str) -> NestFailure:
    human = {
        SourceErrorKind.NETWORK: f"Could not fetch that input: {e.exc_type}",
        SourceErrorKind.DENIED: f"Input refused (HTTP {e.status}) — the signed link has probably expired; sign a new one",
        SourceErrorKind.STATUS: f"Could not fetch that input: HTTP {e.status}",
        SourceErrorKind.READ: f"Cannot read that input: {source}",
        SourceErrorKind.TOO_LARGE: e.human,
        SourceErrorKind.NOT_JSON: f"That input is not valid JSON: {e.detail}",
    }[e.kind]
    detail = e.detail if e.kind in (SourceErrorKind.NETWORK, SourceErrorKind.READ) else ""
    return NestFailure("S1", _SOURCE_ERROR_CLASS[e.kind], human, detail=detail)


def machine_fingerprint() -> str | None:
    """A stable id for this machine, hashed. None when nothing stable can be read.

    A restore code binds to the first machine that redeems it, so the machine has to
    say who it is. Two properties matter and both are easy to get wrong:
    **stable across a reboot** (a resumed transfer has to present the same value, so
    nothing random or boot-scoped goes in), and **the same value the escape hatch
    computes** -- the two must agree or redeeming through one would lock out the other.
    Only the hash leaves the machine; the server has no business knowing the hostname.
    """
    machine_id = ""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            machine_id = Path(path).read_text(encoding="utf-8").strip()
            break
        except OSError:
            continue
    try:
        host = socket.gethostname()
    except OSError:
        host = ""
    if not host and not machine_id:
        return None
    return hashlib.sha256(f"{host}|{machine_id}".encode()).hexdigest()


def _exchange_envelope(env: dict, client: httpx.Client) -> dict:
    """Restore-code envelope (grant_version 2) -> server redeems it into a v1
    payload (freshly signed, short-lived links).

    The code is the credential; it is revocable and auditable; resuming = redeem
    the same code again. A 410 (revoked/expired) gets a plain-language pointer."""
    url = env.get("exchange_url") or (
        f"{str(env.get('origin', '')).rstrip('/')}/api/v1/restore-grants/{env.get('grant_id')}/exchange"
    )
    if not url.startswith(("http://", "https://")):
        raise NestFailure("S1", ErrorClass.MANIFEST_UNSUPPORTED,
                         f"This restore code has no exchange address: {url!r}")
    headers = {}
    fp = machine_fingerprint()
    if fp:
        headers["X-Renest-Machine"] = fp
    try:
        r = client.post(url, headers=headers)
    except httpx.HTTPError as e:
        raise NestFailure("S1", ErrorClass.NETWORK_INTERRUPTED,
                         f"Could not redeem the restore code: {type(e).__name__}", detail=str(e)) from e
    if r.status_code == 410:
        raise NestFailure("S1", ErrorClass.CREDENTIAL_EXPIRED,
                         "This restore code has expired or been revoked. Sign a new one from your drive — your nest is still there.")
    if r.status_code == 403:
        raise NestFailure("S1", ErrorClass.CREDENTIAL_EXPIRED,
                         "This restore code was already used on a different machine. A code binds to the first machine that redeems it — sign a new one from your drive and it will work here.")
    if r.status_code != 200:
        raise NestFailure("S1", ErrorClass.CREDENTIAL_EXPIRED,
                         f"Redeeming the restore code was refused (HTTP {r.status_code})", detail=r.text[:300])
    try:
        payload = r.json()
    except ValueError as e:
        raise NestFailure("S1", ErrorClass.MANIFEST_UNSUPPORTED,
                         f"The redeem response is not valid JSON: {e}") from e
    if payload.get("grant_version") != GRANT_VERSION:
        raise NestFailure("S1", ErrorClass.MANIFEST_UNSUPPORTED,
                         f"Unexpected grant_version in the redeem response: {payload.get('grant_version')!r}")
    return payload


def _parse_grant(obj: dict) -> Grant:
    """dict -> :class:`Grant`. Shaping belongs to config.load_grant (single entry
    point); the version verdict still belongs to the restore side: only an exact
    v1 payload is accepted here, with unchanged wording."""
    try:
        grant = load_grant(obj)
    except ConfigError as e:
        raise NestFailure(
            "S1",
            ErrorClass.MANIFEST_UNSUPPORTED,
            f"Unrecognised grant_version: {obj.get('grant_version')!r}",
        ) from e
    return grant


def _resolve_grant(grant: Grant, client: httpx.Client) -> tuple[dict, dict[str, list[str]]]:
    """Consume a restore-grant: check version / expiry -> fetch
    manifest -> verify sha256. Returns (manifest, blobmap)."""
    if grant.grant_version != GRANT_VERSION:
        raise NestFailure(
            "S1",
            ErrorClass.MANIFEST_UNSUPPORTED,
            f"Unrecognised grant_version: {grant.grant_version!r}",
        )
    expires = grant.expires_at
    if expires:
        exp = parse_iso8601(expires)
        if exp is None:
            raise NestFailure(
                "S1", ErrorClass.MANIFEST_UNSUPPORTED, f"Could not read the restore code's expiry date: {expires!r}"
            )
        if exp < datetime.now(UTC):
            raise NestFailure(
                "S1",
                ErrorClass.CREDENTIAL_EXPIRED,
                f"This restore code expired at {expires}. Sign a new one, then re-run with --resume to carry on where it stopped.",
            )
    url = grant.manifest_url or ""
    try:
        r = client.get(url)
    except httpx.HTTPError as e:
        raise NestFailure(
            "S1", ErrorClass.NETWORK_INTERRUPTED, f"Could not download the manifest: {type(e).__name__}", detail=str(e)
        ) from e
    if r.status_code in (401, 403):
        raise NestFailure(
            "S1", ErrorClass.CREDENTIAL_EXPIRED, f"The manifest was refused (HTTP {r.status_code}) — the signed link has probably expired"
        )
    if r.status_code in (404, 410):
        # A missing manifest != storage is down. The most common causes are a
        # wrong NEST_URL / bucket, or a nest that was never fully published (a
        # half-published nest has no manifest written yet). Retrying will not
        # make it appear.
        raise NestFailure(
            "S1",
            ErrorClass.OBJECT_MISSING,
            f"The storage says there is no nest manifest at that address (HTTP {r.status_code}). "
            "Check the nest id and the bucket you are pointing at — and if the nest was "
            "packed very recently, the upload may not have finished (the manifest is written "
            "last, on purpose). This is not a network problem; retrying will not help.",
        )
    if r.status_code != 200:
        raise NestFailure(
            "S1", ErrorClass.STORAGE_UNAVAILABLE, f"Could not download the manifest: HTTP {r.status_code}"
        )
    manifest_bytes = r.content
    got = hashlib.sha256(manifest_bytes).hexdigest()
    want = grant.manifest_sha256 or ""
    if want and got != want:
        raise NestFailure(
            "S1",
            ErrorClass.UNKNOWN,
            f"The manifest is not the one this restore code is for ({got[:12]}… ≠ {want[:12]}…). Refusing to use it.",
        )
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as e:
        raise NestFailure(
            "S1", ErrorClass.MANIFEST_UNSUPPORTED, f"The manifest is not valid JSON: {e}"
        ) from e
    if grant.nest_id and manifest.get("id") != grant.nest_id:
        raise NestFailure(
            "S1",
            ErrorClass.UNKNOWN,
            f"This restore code is for nest {grant.nest_id}, but the manifest says {manifest.get('id')}. "
            f"Refusing — a code for one nest must never restore a different one.",
        )
    return manifest, dict(grant.blobmap)


def _wheel_fallback(
    lock_path: Path,
    client: httpx.Client,
    narrate: Callable[..., None],
    report: RestoreReport,
) -> Path | None:
    """When dependency install fails, check whether the wheels pinned in the lock
    have been withdrawn.

    If there are dead links, write a "fall back to the generic version" copy of
    the lock and return its path so the caller can retry once; if there are none
    (or we cannot tell), return None and let the original failure be reported
    exactly as it was.

    The original lock is not touched by a single byte — it is a landing spot
    covered by the byte-for-byte guarantee; the fallback lock is written
    separately into staging.
    """
    try:
        lock_text = lock_path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        new_text, warnings = dead_wheel_fallback(lock_text, client=client)
    except Exception:  # the fallback probe itself must never break the restore
        return None
    for w in warnings:
        report.wheel_fallbacks.append(w)
        narrate(w, stage="S3", level="warning")
    if new_text == lock_text:
        return None
    fallback = lock_path.with_name("requirements.fallback.lock")
    fallback.write_text(new_text, encoding="utf-8")
    narrate(
        f"Trying again with the generic versions instead (your original lockfile is untouched; using {fallback.name})",
        stage="S3",
        level="warning",
    )
    return fallback


def _hosts_of(urls: list[str]) -> list[str]:
    """List of URLs -> de-duplicated, order-preserving list of hostnames (the
    error message has to show them to the user)."""
    out: list[str] = []
    for u in urls:
        h = urlparse(u).hostname or u
        if h not in out:
            out.append(h)
    return out


#: What uv prints when it cannot reach upstream, covering both break shapes:
#: the hostname does not resolve, and the hostname resolves into a black hole.
#: Taken from real uv output — do not extend this list from memory.
_UPSTREAM_UNREACHABLE_MARKERS = (
    "failed to fetch",
    "error sending request for url",
    "client error (connect)",
    "tcp connect error",
    "connection refused",
    "tls handshake eof",
    "dns error",
    "failed to lookup address information",
    "could not resolve host",   # wording when a dep comes via git (git+https in the lock)
    "failed to clone",
)

#: What a real torch/CUDA clash says: cannot resolve, mismatch, version conflict.
_TORCH_CONFLICT_MARKERS = ("cuda", "conflict", "no solution", "incompatible", "requires")

#: A package with no ready-made build for this machine falls back to compiling from
#: source, and that compile needs system libraries and build tools the machine may not
#: have. Markers are copied from real uv output (2026-08-10: ``PyGObject`` dragged in
#: ``pycairo``, whose build died with "Found CMake: NO" and "Pkg-config ... not found").
#: **Tested before the torch branch on purpose**: uv's build log mentions torch
#: elsewhere, so that branch was labelling a cairo build failure a torch/CUDA clash and
#: sending the reader off to check their CUDA version.
_SOURCE_BUILD_MARKERS = (
    "failed to build",
    "subprocess-exited-with-error",
    "pkg-config",
    "found cmake: no",
    "dependency lookup for",
    "meson-log.txt",
)

#: Where uv names the package it could not build: the message itself, or the sdist
#: cache path it printed (``…/sdists-v9/pypi/pycairo/1.29.1/…``).
_BUILT_PKG_PATTERNS = (
    r"failed to build[\s`'\"]+([A-Za-z0-9_.\-]+)",
    r"sdists-v\d+/[^/]+/([A-Za-z0-9_.\-]+)/",
    r"building wheel for ([A-Za-z0-9_.\-]+)",
)


#: Room the dependency install needs, on top of the files themselves. A CUDA build of
#: PyTorch plus its companions unpacks to roughly 10 GiB, and the downloads are cached on
#: the way in, so 12 is the honest figure for a GPU nest. Measured 2026-08-10 on the
#: klein-4b nest: files 12.4 GiB, and the check asked for only 14.3 GiB — a 20 GiB machine
#: sailed through S0 and then **ran out of space mid-install**, which is the worst place to
#: find out. Erring high costs the user a slightly bigger rental; erring low costs them the
#: whole run, twenty minutes in.
_DEPS_RESERVE_GPU_GB = 12.0
#: Same idea for a nest with no GPU stack: wheels, build dirs and the cache still need room.
_DEPS_RESERVE_PLAIN_GB = 2.0


def _deps_disk_reserve_gb(manifest: dict) -> float:
    """How much room to leave for building the environment, on top of the files.

    Read from what the manifest already records — no new format field: a nest that names a
    CUDA version, or whose fingerprint carries a torch block, is going to install a CUDA
    torch stack, and that is where the space goes.
    """
    runtime = manifest.get("runtime") or {}
    fp = manifest.get("fingerprint") or {}
    gpu_stack = bool(runtime.get("cuda_version")) or bool((fp.get("torch") or {}))
    return _DEPS_RESERVE_GPU_GB if gpu_stack else _DEPS_RESERVE_PLAIN_GB


def classify_deps_failure(stderr: str) -> tuple[ErrorClass, str]:
    """Dependency install failed — whose fault is it? Returns (attribution, the
    one line a human reads).

    **The order is fixed: reachability first, version conflict second.** uv's
    network errors carry URLs like ``https://pypi.org/simple/torch/``, so a
    conflict test that keys on the word ``torch`` turns "cannot reach the package
    index" into "version conflict" and sends the user off to check their CUDA
    version when the real move is to check the network or switch mirror.
    """
    low = stderr.lower()
    if any(m in low for m in _UPSTREAM_UNREACHABLE_MARKERS):
        hosts = _hosts_of(re.findall(r"https?://[^\s`'\"<>)]+", stderr))
        named = ", ".join(hosts[:4]) if hosts else "the package sources in the lock"
        return (
            ErrorClass.UPSTREAM_UNREACHABLE,
            f"Installing dependencies failed because these sources could not be reached: {named}. "
            f"This machine is offline, behind a proxy that blocks them, or those sites are down — "
            f"it is not a version conflict. Your nest's own files are already restored and verified; "
            f"re-run the same command once the network is back and it carries on where it stopped.",
        )
    if any(m in low for m in _SOURCE_BUILD_MARKERS):
        pkg = ""
        for pat in _BUILT_PKG_PATTERNS:
            m = re.search(pat, low)
            if m:
                pkg = m.group(1)
                break
        named = f"`{pkg}`" if pkg else "one of the packages in the lock"
        return (
            ErrorClass.SYSLIB_MISSING,
            f"Installing dependencies failed while **building {named} from source**: there is "
            f"no ready-made build of it for this machine, and compiling it needs system "
            f"libraries and tools this machine does not have (the compiler's own output above "
            f"names which). This is not a version clash and not your GPU. Either install those "
            f"system packages and re-run, or — if that package is not something the nest "
            f"actually needs — pack again from an environment that does not carry it.",
        )
    if "torch" in low and any(m in low for m in _TORCH_CONFLICT_MARKERS):
        return (
            ErrorClass.TORCH_CUDA_CONFLICT,
            "Installing dependencies failed — uv's own output tells you why",
        )
    return (ErrorClass.UNKNOWN, "Installing dependencies failed — uv's own output tells you why")


# The only definition of landing roots and the home-directory allowlist lives in
# roots.py (pack side and rebuild side share the one copy).
_unsafe_dest = unsafe_relpath
_bad_root_entry = bad_root_entry


#: The loader's words when a shared library is not on this machine. Both spellings
#: are real: Python's importer says the first, the dynamic linker the second.
_SO_MISSING = re.compile(
    r"([A-Za-z0-9_.+-]+\.so[0-9.]*)\s*:\s*cannot open shared object file", re.I
)

#: Which Debian/Ubuntu package carries the library — only entries we have actually
#: seen a machine miss. A wrong package name is worse than none, so an unfamiliar
#: library gets named without a guess at where it comes from.
_SO_PACKAGE = {
    "libgl.so.1": "libgl1",
    "libglu.so.1": "libglu1-mesa",
    "libglib-2.0.so.0": "libglib2.0-0",
    "libgthread-2.0.so.0": "libglib2.0-0",
    "libsm.so.6": "libsm6",
    "libxext.so.6": "libxext6",
    "libxrender.so.1": "libxrender1",
    "libxcb.so.1": "libxcb1",   # the first one actually missing on a real machine, 2026-08-12
    "libx11.so.6": "libx11-6",
    "libsndfile.so.1": "libsndfile1",
    "libgomp.so.1": "libgomp1",
}


#: How much of a log to read when looking for the loader's complaint. The report's own
#: `detail` stays at 600 characters, but on a real machine on 2026-08-12 that line sat
#: 2,338 characters from the end of a 9,508-character log, so classifying from the short
#: tail found nothing and a missing library was reported as "the test render failed".
_SYSLIB_SCAN_CHARS = 200_000


def missing_system_libraries(text: str | None) -> list[str]:
    """Every shared library this machine does not have, as the loader named them.

    All of them, not the first: a machine short of one graphics library is usually short
    of the whole chain — eight of them on the machine that found this — and a reader who
    installs only the one we named comes straight back.

    Kept apart from a crash on purpose: the environment rebuilt *correctly* — every byte
    matches and every package installed — and the thing missing belongs to the operating
    system, which a nest does not carry. Telling that story as "the app would not start"
    sends the reader off to re-check files that are fine.
    """
    if not text:
        return []
    out: list[str] = []
    for m in _SO_MISSING.finditer(text):
        if m.group(1) not in out:
            out.append(m.group(1))
    return out


def missing_system_library(text: str | None) -> str | None:
    """First one only — for callers that just need to know whether this happened."""
    libs = missing_system_libraries(text)
    return libs[0] if libs else None


def _libs_the_working_run_used_but_this_machine_lacks(precheck: dict | None) -> list[str]:
    """Machine libraries the packed run really loaded and this machine does not have.

    Only the list read off the working run counts ("loaded"). The fallback list, read
    off installed packages, names libraries nothing ever loads — one machine was short
    of four of them while producing images perfectly well, so acting on it would cry
    wolf. Reads the pre-check's own record rather than re-measuring: same numbers,
    and it stays true if the measurement moves.
    """
    for check in ((precheck or {}).get("checks") or []):
        nl = (check.get("reading") or {}).get("native_libs") or {}
        if nl.get("method") == "loaded":
            return [n for n in (nl.get("missing") or []) if isinstance(n, str)]
    return []


def missing_library_advice(libs: str | list[str], base_image: str | None = None) -> str:
    """What is missing, and the ways out — surest one first.

    One command for the whole set, not one per library: the machine that found this was
    short of eight, and eight round trips is not a fix. When the nest recorded the image
    it was packed on, that goes first — it brings every one of them at once.
    """
    if isinstance(libs, str):
        libs = [libs]
    named = ", ".join(f"**{lib}**" for lib in libs)
    pkgs: list[str] = []
    for lib in libs:
        pkg = _SO_PACKAGE.get(lib.lower())
        if pkg and pkg not in pkgs:
            pkgs.append(pkg)
    surest = (
        f"**Surest fix:** boot a machine from the image this nest was packed on — "
        f"`{base_image}` — which carries these and anything else the app needs. "
        if base_image
        else ""
    )
    if pkgs:
        # Only the ones we recognise go in the command. Naming a package we are not sure
        # about would send someone to install the wrong thing, which is worse than the
        # honest "look this one up" below.
        rest = [lib for lib in libs if not _SO_PACKAGE.get(lib.lower())]
        where = (
            f"On Debian/Ubuntu machines: `apt-get install -y {' '.join(pkgs)}`"
            + (f" — then look up which package provides {', '.join(rest)}." if rest else ".")
        )
    else:
        where = "Your machine's own package manager will know which package provides them."
    count = "a system library" if len(libs) == 1 else f"{len(libs)} system libraries"
    return (
        f"This machine is missing {count} the app needs: {named}. Your nest itself is "
        f"fine — every file matched and every package installed. Libraries like these "
        f"belong to the operating system, so they do not travel inside a nest. "
        f"{surest}{where} Then run the same command again; it carries on from here."
    )


#: What a framework says when there is no user data. This case must be kept
#: apart from a genuine crash — the environment is fine, what is missing is the
#: user's own data, and the error should say so instead of just "startup
#: failed".
_MISSING_DATA_MARKERS = (
    "no data found",
    "no images found",
    "found 0 images",
    "dataset is empty",
    "no training data",
)


def sender_named(handed_off_from: str | None, trust_sender: str) -> bool:
    """Whether the receiver typed the sender's name **correctly, by hand**.

    Two gates share this one verdict (S2's ``post_install`` and S3's
    dependency-source allowlist) and there is **deliberately only one
    implementation**: define "I trust this person" twice and the user hits "I did
    name them, why is it still blocking me?"

    An empty ``handed_off_from`` (a nest you packed yourself) means there is
    nobody to name, so this is always true.
    """
    if not handed_off_from:
        return True
    return trust_sender.strip().casefold() == handed_off_from.strip().casefold()


def _setup_disclosure(commands: list[tuple[str, str]]) -> str:
    """Lay out the verbatim commands that would run.
    ``commands`` = [(where, verbatim command), …]."""
    return "\n".join(f"    [{where}]\n      {cmd}" for where, cmd in commands)


def summarise_redactions(manifest: dict) -> list[str]:
    """Turn ``entrypoint.redactions`` into plain language: which spots the user
    has to point back at their own data after the rebuild.

    User data never goes into a nest. All the nest keeps is the fact that
    "**this used to point at something of yours**".
    The user should not have to wait for training to say "No data found" and then
    guess — say it out loud as soon as the files have landed.
    """
    out: list[str] = []
    for r in ((manifest.get("entrypoint") or {}).get("redactions") or []):
        if not isinstance(r, dict):
            continue
        role = r.get("role", "something")
        loc = r.get("locator") or {}
        where = (
            f"argument #{loc['argv_index']} of the command it runs"
            if "argv_index" in loc
            else f"{loc.get('file', '?')} → {loc.get('key', '?')}"
        )
        what = {
            "dataset": "the training data it read",
            "output_dir": "where its results went",
            "output_name": "what its result was called",
            "log_dir": "where its logs went",
        }.get(role, role)
        hint = r.get("placeholder") or ""
        out.append(f"{where}: {what}" + (f" — {hint}" if hint else ""))
    return out


def _looks_like_missing_user_data(log_path: Path) -> bool:
    """Did this run fail because the user's data is not there? (Reads only the
    tail of the log; if it cannot be read, assume not.)"""
    try:
        tail = log_path.read_text(encoding="utf-8", errors="replace")[-8000:].lower()
    except OSError:
        return False
    return any(m in tail for m in _MISSING_DATA_MARKERS)


def newer_minor_within_major(fv: object) -> bool:
    """Is this version "same major, minor newer than anything I know"?

    **The forward-compatibility fuse.** Exact allowlist matching makes every new
    optional field turn a readable nest into a brick — the bytes restore in full,
    yet the whole nest is refused over one field it does not even use.

    The rule is written into the format spec, an obligation on consumers rather
    than a choice: **within one major version, a reader meeting an unknown
    optional field must ignore it and must not reject the nest**; strict
    validation is `renest lint`'s job. Across major versions we still refuse
    hard — a major bump means breaking changes, and guessing is just guessing.
    """
    if not isinstance(fv, str):
        return False
    known_major = {v.split(".")[0] for v in SUPPORTED_FORMAT_VERSIONS}
    try:
        major, minor = fv.split(".", 1)
        minor_n = int(minor)
    except ValueError:
        return False
    if major not in known_major:
        return False
    highest = max(
        int(v.split(".")[1]) for v in SUPPORTED_FORMAT_VERSIONS if v.startswith(f"{major}.")
    )
    return minor_n > highest


def _validate_manifest(manifest: dict, *, narrate: Callable[..., None] | None = None) -> None:
    fv = manifest.get("format_version")
    if fv not in SUPPORTED_FORMAT_VERSIONS:
        if newer_minor_within_major(fv):
            # Newer minor of a known major: warn and continue, never reject.
            msg = (
                f"This nest says format {fv}, and this version knows up to "
                f"{max(SUPPORTED_FORMAT_VERSIONS)}. Same major version, so it carries "
                f"optional fields this build does not know about — those are ignored and "
                f"the rebuild goes ahead. Upgrade Renest if you want everything it offers."
            )
            if narrate is not None:
                narrate(msg, stage="S1", level="warning")
            return
        raise NestFailure(
            "S1",
            ErrorClass.MANIFEST_UNSUPPORTED,
            f"Unrecognised nest format version: {fv!r} — this version reads "
            f"{', '.join(SUPPORTED_FORMAT_VERSIONS)}. "
            "Nests packed in the older 1.x format cannot be read here: 2.0 made "
            "code_deps[].role a required field, and guessing it would be guessing at "
            "which parts of the nest are the app and which are your own code. "
            "Pack the environment again with this version. Stopping rather than guessing.",
        )
    # ``k not in manifest`` is not enough: ``python_lock: null`` means "key
    # present, value absent" and would pass this gate only to raise a TypeError
    # while building the plan — throwing a traceback in the user's face is a
    # defect.
    missing = [
        k
        for k in ("id", "runtime", "code_deps", "python_lock", "files")
        if manifest.get(k) is None
    ]
    if missing:
        raise NestFailure(
            "S1", ErrorClass.MANIFEST_UNSUPPORTED, f"The manifest is missing: {','.join(missing)}"
        )
    # Pack deliberately leaves this field empty when it cannot find the
    # interpreter, so it does occur. Without this check we walk all the way to
    # plan building and throw a `KeyError` traceback in the user's face, while
    # every other missing field in the same manifest gets plain language.
    if not str(manifest.get("runtime", {}).get("python_version", "") or "").strip():
        raise NestFailure(
            "S1",
            ErrorClass.MANIFEST_UNSUPPORTED,
            "This nest doesn't say which Python version it needs, so we can't build the "
            "environment for it. That happens when it was packed from a setup where we "
            "couldn't find the interpreter. Pack it again from that machine with "
            "`--env-python /path/to/python` (the interpreter the app starts with), or add "
            "runtime.python_version to the manifest by hand if you know it.",
        )
    # ``python_lock`` present with no ``lockfile`` is a shape pack really does
    # produce, and such a nest cannot rebuild its environment — say so here
    # rather than waiting for a KeyError downstream. The escape hatch degrades
    # and continues on the same input; the difference in strictness is meant.
    if not isinstance(manifest["python_lock"], dict) or not manifest["python_lock"].get("lockfile"):
        raise NestFailure(
            "S1",
            ErrorClass.MANIFEST_UNSUPPORTED,
            "This nest has no dependency lockfile, so the Python environment cannot be "
            "rebuilt from it. That happens when the machine it was packed from had no "
            "requirements.lock / uv.lock / requirements.txt — the pack step warns about it "
            "at the time. Add a lockfile to that environment and pack it again.",
        )
    # Landing gate: some files land **on purpose** outside the target directory
    # (the two home-directory roots), so "everything is inside $TARGET" does not
    # hold. This is an **extension, not a relaxation** — escape rejection still
    # applies to every root, plus per-root enumeration and pattern checks.
    n_files = len(manifest.get("files") or [])
    if n_files > MAX_MANIFEST_FILES:
        raise NestFailure(
            "S1",
            ErrorClass.MANIFEST_UNSUPPORTED,
            f"This nest lists {n_files} files. We stop at {MAX_MANIFEST_FILES} — "
            f"past that, placing them takes longer than it is worth and a nest that big "
            f"is nearly always a mistake. Split it into more than one nest.",
        )
    bad = [
        r
        for r in (_bad_root_entry(f) for f in manifest.get("files", []))
        if r is not None
    ]
    bad += [
        f"a path that writes outside where it belongs: {d.get('install_path')!r}"
        for d in manifest.get("code_deps", [])
        if not isinstance(d, dict) or _unsafe_dest(d.get("install_path"))
    ]
    # Path-shaped keys in entrypoint.env: their values are confined to the
    # rebuild directory too, so whatever consumes them is protected by
    # construction.
    bad += bad_entrypoint_env((manifest.get("entrypoint") or {}).get("env"))
    # The two paths 2.6 added get the same treatment as files[] and code_deps: a nest
    # that names a spot outside the rebuild directory is refused, not quietly ignored.
    bad += [
        f"a path that writes outside where it belongs: {v!r}"
        for v in [(manifest.get("python_lock") or {}).get("lockfile_path")]
        + [
            ((manifest.get("adapters") or {}).get(a) or {}).get("workflow_path")
            for a, _ in _RECIPE_BLOBS
        ]
        if v is not None and _unsafe_dest(v)
    ]
    if bad:
        raise NestFailure(
            "S1",
            ErrorClass.MANIFEST_UNSUPPORTED,
            "This nest asks for something we will not do — it names "
            + "; ".join(x[:100] for x in bad[:5])
            + ". Files may only land inside the folder you are rebuilding into, or in the "
            "two known model-cache folders. Refusing to restore it.",
        )


# --------------------------------------------------------------------------
# main orchestration
# --------------------------------------------------------------------------
def restore(
    source: dict | str | Path,
    target_dir: str | Path,
    opts: RestoreOptions | None = None,
) -> RestoreReport:
    """One-command restore. ``source`` = manifest (dict/path) or restore-grant
    (dict/path/URL, recognised by the ``grant_version`` field). Idempotent:
    re-running the same command resumes. Returns a :class:`RestoreReport`; never
    raises a business exception — the CLI exit code = ``report.exit_code``."""
    opts = opts or RestoreOptions()
    target = Path(target_dir).resolve()
    _extra_sinks: list = []

    def _fanout_sink(ev: dict) -> None:
        if opts.event_sink is not None:
            opts.event_sink(ev)
        for _s in _extra_sinks:
            _s(ev)

    em = EventEmitter(json_mode=opts.json_events, sink=_fanout_sink)
    # Anonymous usage data: **this observer exists only if the user answered
    # yes**, otherwise None. It hangs off the fanout rather than replacing the
    # sink — the grant-code uplink (report.py) has to keep working as usual.
    _ts = _telemetry_sink()
    if _ts is not None:
        _extra_sinks.append(_ts)
    runner = opts.runner or _default_runner
    launcher = opts.launcher or ComfyUILauncher(ssim_threshold=opts.ssim_threshold)
    client = opts.client or httpx.Client(follow_redirects=True)
    own_client = opts.client is None

    def narrate(message: str, *, stage: str | None = None, level: str = "info", **extra: Any) -> None:
        if opts.verbose:
            # This line goes straight to the terminal, bypassing emit, so
            # sanitise it here as well. Take the rewriting progress line down first,
            # or this one lands on top of half a progress bar and both become unreadable.
            em.clear_live()
            print(f"[restore] {sanitise_terminal(message)}", file=sys.stderr, flush=True)
        em.log(message, stage=stage, level=level, **extra)

    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    evidence = target / EVIDENCE_REL / run_id
    report = RestoreReport(evidence_dir=str(evidence))
    mani: dict = {}
    plan: RestorePlan | None = None
    journal: Journal | None = None
    handed_off_from: str | None = None  # sender the server attests; None = you packed it
    handed_off_relayed: bool | None = None  # the sender was themselves a relay (anti-laundering)
    # Assets that do not travel with the nest (licence-restricted), sha256 ->
    # asset. Their absence from the grant's blobmap is not an accident: the
    # server only signs links for bytes you genuinely possess, and these you must
    # fetch from source with your own credentials. When S1 finds no link, this is
    # what lets us say the right thing (go and fetch it yourself, rather than
    # "transfer failed").
    gated_origin: dict[str, GatedAsset] = {}
    handle_box: dict = {}
    state: dict = {
        "blobs_downloaded": 0,
        "blobs_cached": 0,
        "transfer_seconds": 0.0,
        "transfer_bytes": 0,
        "verify_seconds": 0.0,
        "active_sources": [],
    }
    t_run = time.monotonic()
    failure: NestFailure | None = None

    # -- stage skeleton: timing + contract events + attribution --
    def run_stage(
        code: str, fn: Callable[[], str | None], start_extra: dict | None = None
    ) -> None:
        em.stage_start(code, STAGE_DESC[code], **(start_extra or {}))
        t0 = time.monotonic()
        try:
            detail = fn() or ""
        except NestFailure as e:
            secs = round(time.monotonic() - t0, 3)
            report.stages.append(StageResult(code, False, secs, e.human))
            em.error(e)
            narrate(
                f"✗ {code} {STAGE_DESC[code]}({secs}s)—— [{e.stage}/{e.error_class}] {e.human}",
                level="error",
            )
            raise
        except Exception as e:  # backstop: an unexpected exception must still get a stage
            sf = NestFailure(code, ErrorClass.UNKNOWN, f"{type(e).__name__}: {e}")
            secs = round(time.monotonic() - t0, 3)
            report.stages.append(StageResult(code, False, secs, sf.human))
            em.error(sf)
            narrate(f"✗ {code}({secs}s)—— [{code}/UNKNOWN] {sf.human}", level="error")
            raise sf from e
        secs = round(time.monotonic() - t0, 3)
        report.stages.append(StageResult(code, True, secs, detail))
        if journal is not None:
            journal.mark_stage(code, status="done", finished_at=_iso_now(), duration_s=secs)
        em.stage_done(code, secs, detail=detail)
        narrate(
            f"✓ {code} {STAGE_DESC[code]}({secs}s)" + (f" —— {detail}" if detail else ""),
            stage=code,
        )

    # -- fetch primitive: resume skip -> round retry (backoff) -> journal bookkeeping --
    def fetch_one(it: PlanItem) -> tuple[str, ResolveReport | None]:
        assert journal is not None
        if (
            opts.resume
            and journal.blob(it.sha256).get("status") == BLOB_VERIFIED
            and it.dest.is_file()
        ):
            if opts.reverify:
                if _sha256_file(it.dest) == it.sha256:
                    return "cached", None
                narrate(f"--reverify found a mismatch, downloading again: {it.label}", stage="S1", level="warning")
            elif it.dest.stat().st_size == it.size_bytes:
                return "cached", None
            else:
                narrate(
                    f"An earlier run marked this done, but the size is wrong — downloading again: {it.label}",
                    stage="S1", level="warning",
                )
        if it.sha256 in gated_origin and it.dest.is_file() and _sha256_file(it.dest) == it.sha256:
            # A restricted asset (one that does not travel with the nest) was
            # already fetched from source before the run, or the user put it
            # there themselves — a matching byte fingerprint means it has landed,
            # and we no longer demand a download link for it (it never would have
            # one).
            journal.mark_blob(it.sha256, BLOB_VERIFIED, it.dest)
            return "cached", None
        if not it.sources:
            gated = gated_origin.get(it.sha256)
            if gated is not None:
                where = (
                    f"get it from <{gated.origin_url}> with your own account"
                    if gated.origin_url
                    else "this nest does not even record where it came from, so find a file "
                         f"with this exact fingerprint (sha256 {it.sha256}) yourself"
                )
                raise NestFailure(
                    "S1",
                    ErrorClass.OBJECT_MISSING,
                    f"{it.label} is licence-restricted, so it never travels with a hand-off "
                    f"and your drive holds no copy you may download. Not a transfer failure — "
                    f"{where}, put it at {it.dest}, then run this again.",
                    context={"sha256": it.sha256, "origin_url": gated.origin_url},
                )
            raise NestFailure(
                "S1",
                ErrorClass.UNKNOWN,
                f"Nowhere to download {it.label} from — the nest lists no sources, and there is no restore code or --blob-base to fall back on",
            )
        narrate(
            f"Downloading {it.label} ({it.size_bytes} bytes)",
            stage="S1",
            blob_sha256=it.sha256,
            blob_path=it.label,
            blob_status="start",
            blob_role=it.role,
        )
        it.dest.parent.mkdir(parents=True, exist_ok=True)
        journal.mark_blob(it.sha256, BLOB_PENDING, it.dest)
        spec = BlobSpec(sha256=it.sha256, size_bytes=it.size_bytes, sources=it.sources)
        last: SourcesExhausted | None = None
        for rnd in range(1, max(opts.retry_rounds, 1) + 1):
            try:
                rep = resolve(spec, it.dest, client)
                journal.mark_blob(it.sha256, BLOB_VERIFIED, it.dest)
                state["active_sources"] = [rep.winner_host]
                return "downloaded", rep
            except SourcesExhausted as e:
                last = e
                if rnd < opts.retry_rounds:
                    wait = round(opts.backoff_base_s * (2 ** (rnd - 1)), 3)
                    narrate(
                        f"Every source failed on attempt {rnd}; retrying in {wait}s: {it.label}",
                        stage="S1",
                        level="warning",
                        blob_sha256=it.sha256,
                        blob_path=it.label,
                        blob_status="retry",
                        retry_round=rnd,
                        retry_rounds_max=opts.retry_rounds,
                        retry_wait_s=wait,
                    )
                    time.sleep(wait)
        # Attribute by how each source actually failed, rather than recording
        # everything as a network interruption — filing a 404 under the
        # retryable network class makes retries pointless and sends the user off
        # to check their network while the real problem is in the bucket.
        attribution = last.attribution if last else []
        class_name, why = classify_source_failures(attribution)
        raise NestFailure(
            "S1",
            ErrorClass(class_name),
            f"Gave up on {it.label} ({it.sha256[:12]}…) — {why} "
            f"({opts.retry_rounds} attempts each)",
            detail=str(last) if last else "",
            context={"sha256": it.sha256, "attribution": attribution},
        )

    def blob_done(it: PlanItem, status: str, rep: ResolveReport | None, seconds: float) -> None:
        narrate(
            f"Done [{status}]: {it.label}",
            stage="S1",
            blob_sha256=it.sha256,
            blob_path=it.label,
            blob_status=status,
            blob_role=it.role,
            blob_seconds=round(seconds, 3),
            blob_mbps=rep.mbps if rep else None,
        )

    # -- prelude (no stage): load manifest / grant, make plan, build journal --
    def load_inputs() -> None:
        nonlocal mani, plan, journal, handed_off_from, handed_off_relayed
        obj = _load_json_input(source, client)
        blobmap: dict[str, list[str]] = {}
        if "grant_version" in obj:
            if obj.get("grant_version") == GRANT_ENVELOPE_VERSION:
                # Restore-code envelope: redeem first (the code is the
                # credential; resuming = redeem the same code again, links are
                # freshly signed every time)
                narrate("Redeeming your restore code… (codes last a few days; expired or lost, sign a new one from your drive)")
                envelope = obj
                obj = _exchange_envelope(envelope, client)
                # The uplink origin comes from the value recorded in the envelope
                # (so a file-based source can report upward as well)
                rs = maybe_report_sink(
                    source, envelope, disabled=opts.no_report, target=str(target)
                )
            else:
                rs = maybe_report_sink(
                    source, obj, disabled=opts.no_report, target=str(target)
                )
            if rs is not None:
                _extra_sinks.append(rs)
                # Say exactly what is sent and what is not — "reporting
                # progress" on its own says nothing. Print the full list right
                # here (uplink.disclosure); do not turn it into "see our
                # website for details".
                narrate(
                    "Progress is being sent to your drive (--no-report turns this off; "
                    "if it fails, your restore carries on regardless)"
                )
                # Four lines always; the full field-by-field list only when the user
                # actually asked for --verbose. **Not the same condition as `opts.verbose`
                # any more**: on a terminal we now turn narration on by ourselves, and that
                # quietly turned a 35-line disclosure into something printed on every run,
                # burying the progress the user was waiting for (2026-08-10, watched live).
                from .uplink import disclosure, disclosure_brief

                em.clear_live()
                print(disclosure() if opts.verbose_explicit else disclosure_brief(),
                      file=sys.stderr, flush=True)
            parsed = _parse_grant(obj)
            # Who handed you this nest, as attested by the server. Trust only
            # the grant (which the server signs); never look at any
            # self-declared field in the manifest.
            handed_off_from = parsed.handed_off_from
            handed_off_relayed = parsed.handed_off_relayed
            mani, blobmap = _resolve_grant(parsed, client)
            # Free-tier retention countdown. Why it has to be printed: a free
            # user may well bring a pod back to life with a restore code every
            # day and never open the website, while renewal only counts a
            # website sign-in — without a word here they would be quietly wiped
            # while still actively using it. Absent/None prints nothing (paying
            # users have no such thing).
            left = parsed.retention_days_left
            if left is not None and left <= _RETENTION_NOTICE_DAYS:
                narrate(
                    f"Heads up: what you keep on your drive reaches the end of "
                    f"its keeping period in {left} days"
                    " (the free plan keeps things for 90 days). Signing in to "
                    "the website once starts the 90 days over, at no cost."
                    " Restoring on this machine is not affected — carry on.",
                    stage="S1",
                    level="warning",
                )
            if handed_off_from:
                narrate(
                    f"{handed_off_from} handed you this nest. Restoring it runs code from "
                    f"their setup on this machine, so anything unusual will be held to a "
                    f"stricter standard from here on"
                    + (
                        f". Note that {handed_off_from} was passing it on too — they did not pack it"
                        if handed_off_relayed
                        else ""
                    ),
                    stage="S1",
                    level="warning",
                )
        else:
            mani = obj
        _validate_manifest(mani, narrate=narrate)
        # The assets that do not travel with the nest: say it all **before the
        # run starts**, instead of discovering missing files at the very end.
        # Restricted assets never serve bytes across users, so without this the
        # files would simply be quietly absent. The probe downloads no bytes and
        # needs no GPU.
        _gated = gated_assets(mani)
        # Anything the restore code **does** carry a link for is not a
        # "fetch it yourself" case: a link means the server attests these bytes
        # are genuinely yours (for instance you packed the nest), so they are
        # served straight from your drive as usual.
        # Only assets the manifest marks restricted **and** the drive will not
        # serve go down the "fetch from source with your own credentials" path.
        _gated = [a for a in _gated if not (a.sha256 and a.sha256 in blobmap)]
        gated_origin.update({a.sha256: a for a in _gated if a.sha256})
        if _gated:
            _tok = find_token()
            for _a in _gated:
                check_reach(_a, token=_tok, client=client)
            narrate(summarise(_gated, have_token=bool(_tok)), stage="S1", level="warning")
            # Whatever can be fetched automatically is fetched, **with no
            # confirmation dialog** — same reason a batch of machines must not
            # be stalled by pop-ups: ask every day and the user just clicks
            # through with their eyes shut.
            for _a in _gated:
                if _a.reach != "free":
                    continue
                _dst = resolve_file_root(
                    next((f.get("root", "env") for f in (mani.get("files") or [])
                          if f.get("path") == _a.path), "env"), target) / _a.path
                _why = fetch_from_origin(_a, _dst, token=_tok, client=client)
                if _why:
                    _a.reach = "error"
                    _a.detail = _why
                    narrate(f"Could not fetch {_a.path}: {_why}", stage="S1", level="warning")
                else:
                    _a.detail = "fetched from the source"
                    narrate(f"Fetched from the source: {_a.path}", stage="S1")
            report.gated = [
                {"path": a.path, "reach": a.reach, "origin_url": a.origin_url,
                 "detail": a.detail} for a in _gated
            ]

        report.nest_id = mani.get("id", "")
        plan = RestorePlan.from_manifest(mani, target, opts.blob_base, blobmap)
        journal = Journal(target, plan.nest_id)
        if opts.resume:
            journal.load_if_matching()
        narrate(
            f"Nest {plan.nest_id}: {len(plan.items)} files, {plan.total_bytes} bytes in total. "
            f"Logs and evidence go to {evidence}"
        )

    # -- S0 precheck --
    def s0_precheck() -> str:
        if opts.skip_precheck:
            return "skipped (--skip-precheck)"
        assert plan is not None
        fn = opts.precheck_fn or run_precheck
        runtime = mani.get("runtime", {})
        pr: PrecheckReport = fn(
            cuda_tag=_cuda_tag(runtime.get("cuda_version", "")),
            expected_driver=runtime.get("driver_version"),
            need_disk_gb=round(plan.total_bytes * 1.15 / 2**30 + _deps_disk_reserve_gb(mani), 2),
            # The memory check is derived from the nest's actual size — a nest
            # records no memory requirement of its own.
            nest_bytes=plan.total_bytes,
            disk_path=str(target),
            # Which GPUs the PyTorch inside this nest was compiled for. It is
            # legal for an older nest to carry no gpu block, and then this check
            # is skipped entirely.
            nest_gpu=mani.get("gpu"),
            # Whether the bulk files cross the internet — decides whether "slow
            # network" blocks the user or merely warns (see egress in doctor)
            bulk_from_internet=plan.bulk_comes_from_internet,
            # Which chip this nest was packed for (recorded in the manifest from
            # format 2.3 on). A chip mismatch means dependencies **certainly**
            # will not install, not "might be risky" — dependency packages are
            # compiled per chip, one build per chip. Older nests that did not
            # record it are not blocked.
            nest_arch=((mani.get("fingerprint") or {}).get("os") or {}).get("machine"),
            # What the machine underneath has to provide (format 2.6): C library,
            # platform tag, and the machine libraries the working run really loaded.
            # Checked here rather than after the download, because the whole point is
            # to say so before the user spends twenty minutes and a rented machine.
            nest_runtime=runtime,
            force=opts.force,
        )
        report.precheck = pr.to_dict()
        if not pr.proceed:
            rejects = [c for c in pr.checks if c.level == "reject"]
            klass = (
                PRECHECK_CLASS.get(rejects[0].name, ErrorClass.UNKNOWN)
                if rejects
                else ErrorClass.UNKNOWN
            )
            raise NestFailure(
                "S0",
                klass,
                "This machine did not pass the checks: "
                + "; ".join(c.reason for c in rejects)
                + " (--force goes ahead anyway; the report still records the truth)",
                context={"checks": [c.name for c in rejects]},
            )
        if pr.overall == "reject":
            narrate("⚠ Failed checks are being ignored because you passed --force — the report still records them", stage="S0", level="warning")
            return "checks failed (forced through, recorded as such)"
        # Say the warnings out loud, here, before a single byte moves. They were
        # written into the report and nowhere else, so the screen said "machine check:
        # warn" and then downloaded 7 GB -- measured 2026-08-13 on a machine short of
        # libGL.so.1: the check found it, named it, and never told the person watching.
        # The whole reason the check runs at S0 rather than after the download is to
        # save someone twenty minutes and a rented machine; recording it silently
        # throws that away. The escape hatch has always printed these.
        for _c in pr.checks:
            if _c.level == LEVEL_WARN and _c.reason:
                narrate(f"⚠ {_c.reason}", stage="S0", level="warning")
        return f"machine check: {pr.overall}"

    # -- S1 download --
    def s1_download() -> str:
        assert plan is not None
        meta = [i for i in plan.items if i.role != "asset"]
        assets = plan.asset_items
        for it in meta:
            t0 = time.monotonic()
            status, rep = fetch_one(it)
            state["blobs_" + ("cached" if status == "cached" else "downloaded")] += 1
            blob_done(it, status, rep, time.monotonic() - t0)
        # asset segment timed separately: this wall clock is the only legit
        # denominator for bandwidth
        t_assets = time.monotonic()
        total_bytes = sum(i.size_bytes for i in assets)
        done_bytes = 0

        # Download threads only run fetch_one (which marks the journal under its
        # own lock); counting, progress and events stay on the main thread, or
        # consumers of the event stream see interleaved, corrupted lines.
        # **Bucket by landing path: parallel across buckets, serial within a
        # bucket.** The manifest allows several entries to land on one path (last
        # write wins, S2 checks afterwards), and two threads writing the same
        # file trample each other — one hashing while the other truncates.
        buckets: dict[Path, list[PlanItem]] = {}
        for it in assets:
            buckets.setdefault(it.dest, []).append(it)

        def fetch_bucket(items: list[PlanItem]) -> list[tuple[PlanItem, str, ResolveReport | None, float]]:
            out = []
            for it in items:
                t0 = time.monotonic()
                status, rep = fetch_one(it)
                out.append((it, status, rep, time.monotonic() - t0))
            return out

        first_failure: BaseException | None = None
        with ThreadPoolExecutor(max_workers=max(1, min(FILE_WORKERS, len(buckets) or 1))) as ex:
            futures = [ex.submit(fetch_bucket, items) for items in buckets.values()]
            for fut in as_completed(futures):
                try:
                    results = fut.result()
                except CancelledError:
                    # Cancelled before starting: still pending in the journal,
                    # so a resume picks it up.
                    continue
                except NestFailure as e:
                    # The first failure decides: cancel whatever has not started
                    # (it would most likely die on the same source, and there is
                    # no point quadrupling the retry wait); let whatever is
                    # already running finish — those bytes are not wasted, the
                    # journal records them verified and a retry skips them.
                    if first_failure is None:
                        first_failure = e
                        for other in futures:
                            other.cancel()
                    continue
                for it, status, rep, secs in results:
                    if status == "downloaded":
                        state["transfer_bytes"] += it.size_bytes
                        state["blobs_downloaded"] += 1
                    else:
                        state["blobs_cached"] += 1
                    done_bytes += it.size_bytes
                    blob_done(it, status, rep, secs)
                elapsed = max(time.monotonic() - t_assets, 1e-6)
                em.progress(
                    "S1",
                    percent=round(done_bytes * 100 / total_bytes, 1) if total_bytes else 100.0,
                    bytes_done=done_bytes,
                    bytes_total=total_bytes,
                    speed_mbps=round(state["transfer_bytes"] * 8 / 1e6 / elapsed, 1),
                    active_sources=list(state["active_sources"]),
                )
        if first_failure is not None:
            raise first_failure
        state["transfer_seconds"] = round(time.monotonic() - t_assets, 3)
        return f"{state['blobs_downloaded']} downloaded, {state['blobs_cached']} already here"

    # -- S2 layout: full re-verify + self-heal re-pull + unpack --
    def s2_place() -> str:
        assert plan is not None and journal is not None

        def _setup_allowed(what: str, command: str) -> bool:
            """Consent gate for ``post_install``. True = it may run.

            Two tiers, sharing one verdict for "I trust this person" with the
            dependency-source gate (:func:`sender_named`):

            - **A nest you packed yourself** (no sender) → run it, but print the
              command verbatim first. Blocking here would block the user from
              their own command; running it silently would hide it.
            - **A nest someone handed you** → **block**, unless the sender's name
              is typed out correctly by hand. This is the only free-text shell
              command in a manifest — one line runs anything, as you, here — so
              somebody else's bytes plus an arbitrary command needs a human nod.

            ``--no-setup`` skips both tiers.
            """
            if opts.no_setup:
                narrate(
                    f"Skipped {what} (--no-setup). The environment may be incomplete:\n"
                    + _setup_disclosure([(what, command)]),
                    stage="S2",
                    level="warning",
                )
                report.setup_skipped.append(what)
                return False
            if not sender_named(handed_off_from, opts.trust_sender):
                raise NestFailure(
                    "S2",
                    ErrorClass.UNTRUSTED_SETUP,
                    f"{handed_off_from} handed you this nest, and it wants to run setup "
                    "commands on this machine.\n  Stopped — nothing was run.\n"
                    "\n  What it wants to run:\n"
                    + _setup_disclosure([(what, command)])
                    + "\n"
                    "\n  Why that matters: this is a plain command line the sender wrote"
                    "\n  into the nest. It runs as you, here. It can read the models you just"
                    "\n  restored, your storage credentials, and whatever else is on this box."
                    "\n"
                    f"\n  You did not pack this nest — {handed_off_from} gave it to you."
                    + (
                        f"\n"
                        f"\n  ⚠ One more thing worth knowing: {handed_off_from} was passing"
                        f"\n    this on too. They did not pack it — it reached them from someone"
                        f"\n    else. So knowing {handed_off_from} does not make this nest safe."
                        f"\n    Ask them first: did you check this one?"
                        if handed_off_relayed
                        else ""
                    )
                    + "\n"
                    "\n  Read the command above. If you understand it and you trust them,"
                    "\n  name them — spell it exactly as shown:"
                    f'\n        --trust-sender "{handed_off_from}"'
                    "\n"
                    "\n  Only want the files, without running anything? Use --no-setup"
                    "\n  (the environment may be incomplete, and the report will say so).",
                )
            narrate(
                f"Running {what} — these came with the nest:\n"
                + _setup_disclosure([(what, command)]),
                stage="S2",
                level="warning",
            )
            return True

        t0 = time.monotonic()
        assets = plan.asset_items
        # ex.map preserves order, so `bad` comes out identical to the serial
        # version — repair reports and failure lists must not reorder just
        # because verification went parallel.
        def _mismatch(it: PlanItem) -> PlanItem | None:
            return it if (not it.dest.is_file() or _sha256_file(it.dest) != it.sha256) else None

        with ThreadPoolExecutor(max_workers=max(1, min(VERIFY_WORKERS, len(assets) or 1))) as ex:
            bad = [it for it in ex.map(_mismatch, assets) if it is not None]
        repaired = 0
        if bad:
            narrate(f"{len(bad)} files did not match — downloading them again", stage="S2", level="warning")
            for it in bad:
                journal.mark_blob(it.sha256, BLOB_PENDING, it.dest)
                it.dest.unlink(missing_ok=True)
                fetch_one(it)
                state["blobs_downloaded"] += 1
                repaired += 1
                narrate(
                    f"Done [repaired]: {it.label}",
                    stage="S2",
                    blob_sha256=it.sha256,
                    blob_path=it.label,
                    blob_status="repaired",
                    blob_role=it.role,
                )
            still = [
                it.label
                for it in bad
                if not it.dest.is_file() or _sha256_file(it.dest) != it.sha256
            ]
            if still:
                raise NestFailure(
                    "S2", ErrorClass.HASH_MISMATCH, f"Still wrong after downloading again: {still}", context={"paths": still}
                )
        state["verify_seconds"] = round(time.monotonic() - t0, 3)

        # Bad-byte structural check: what the step above proved is "the bytes
        # match the manifest", not "the bytes are complete weights". The extreme
        # but real case is a bucket that stores a truncated download or an LFS
        # pointer — sha256 then goes all green right up until ComfyUI crashes on
        # startup. So probe lightly once the bytes have landed: report, never
        # block (capture discipline, and at this point the bytes really do match
        # the nest, so stopping the user leaves them no way forward).
        for it in assets:
            bad = probe_model_bytes(it.dest, it.size_bytes, logical_name=it.label)
            if bad:
                report.integrity_warnings.append(bad)
                narrate(
                    f"{bad} This is not a download problem — the file matches the nest exactly, "
                    f"which means it was already like this when the nest was packed.",
                    stage="S2",
                    level="warning",
                    blob_sha256=it.sha256,
                    blob_path=it.label,
                )

        for dep in mani["code_deps"]:
            name = dep["name"]
            install = target / dep["install_path"]
            sha = dep["archive"]["sha256"]
            marker = f"S2:unpack:{name}"
            if (
                opts.resume
                and journal.stage(marker).get("sha256") == sha
                and install.is_dir()
            ):
                narrate(f"Already unpacked, skipping: {name}", stage="S2")
                continue
            archive = target / ARCHIVES_REL / f"{name}.tar.gz"
            try:
                placed = _extract_strip1(archive, install)
                if placed == 0:
                    # The symlink trap: if the code directory was itself a
                    # symlink at pack time, tar stored the link and not the tree
                    # — **sha256 goes all green** and unpacking lands nothing.
                    # Without this check the user gets an unrelated import error
                    # at startup while the real cause sits on the packing
                    # machine. It is the only thing that catches nests packed by
                    # someone else with an older version or a different tool.
                    raise NestFailure(
                        "S2",
                        ErrorClass.SYMLINK_BROKEN,
                        f"{name} arrived empty. Its archive verifies byte-for-byte, but there "
                        f"is nothing inside it to unpack — which happens when that folder was "
                        f"a symlink on the machine it was packed from: the link gets stored, "
                        f"not the files it points at.\n"
                        f"  Nothing is wrong on this machine, and re-running will not help.\n"
                        f"  Whoever packed it needs to replace the link with the real folder "
                        f"(or pack with the link followed) and pack again.",
                    )
            except PermissionError as e:
                raise NestFailure(
                    "S2", ErrorClass.PERMISSION_DENIED, f"No permission to unpack {name}: {e}"
                ) from e
            except OSError as e:
                klass = (
                    ErrorClass.DISK_FULL if getattr(e, "errno", None) == 28 else ErrorClass.UNKNOWN
                )
                raise NestFailure("S2", klass, f"Could not unpack {name}: {e}") from e
            except (tarfile.TarError, ValueError) as e:
                raise NestFailure("S2", ErrorClass.UNKNOWN, f"Could not unpack {name}: {e}") from e
            post = dep.get("post_install")
            if post and _setup_allowed(f"{name}'s setup commands", post):
                r = runner(["bash", "-c", post], cwd=str(install))
                if r.returncode != 0:
                    raise NestFailure(
                        "S2",
                        ErrorClass.UNKNOWN,
                        f"{name}'s setup commands failed",
                        detail=(r.stderr or "")[-300:],
                    )
            journal.mark_stage(marker, sha256=sha)
        # Land the lockfile where it belongs. The staging copy in the tool area exists
        # only for S3's uv pip sync to read and is not covered by the byte-for-byte
        # guarantee. **After unpacking, not before**: from 2.6 the nest may name a path
        # inside a code folder, and unpacking that folder afterwards would overwrite it.
        lock_landing = plan.lock_landing
        if not lock_landing.is_file() or _sha256_file(lock_landing) != plan.lock_sha256:
            lock_landing.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(target / LOCK_REL, lock_landing)
            if _sha256_file(lock_landing) != plan.lock_sha256:
                raise NestFailure(
                    "S2", ErrorClass.HASH_MISMATCH, f"The lockfile did not land correctly: {lock_landing}"
                )
            narrate(f"Lockfile is back in place: {lock_landing}", stage="S2")

        for _adapter, _staged_rel in _RECIPE_BLOBS:
            _staged = target / _staged_rel
            if _staged.is_file():
                _land_recipe(_adapter, mani, _staged, target, narrate)

        post = mani.get("post_install")
        if post:
            marker_sha = hashlib.sha256(post.encode()).hexdigest()
            if not (
                opts.resume and journal.stage("S2:post_install").get("sha256") == marker_sha
            ):
                if _setup_allowed("this nest's setup commands", post):
                    r = runner(["bash", "-c", post], cwd=str(target))
                    if r.returncode != 0:
                        raise NestFailure(
                            "S2", ErrorClass.UNKNOWN, "This nest's setup commands failed", detail=(r.stderr or "")[-300:]
                        )
                    journal.mark_stage("S2:post_install", sha256=marker_sha)
        # Which spots the user must point back at their own data, **said as soon
        # as the files land** instead of leaving them to guess once training says
        # "No data found".
        pointers = summarise_redactions(mani)
        if pointers:
            report.redactions = pointers
            narrate(
                f"Heads up: {len(pointers)} thing(s) in this nest pointed at your own files, "
                f"which never travel with a nest — they stay yours, on your own disk. "
                f"Point them at your copies before the run will work:",
                stage="S2",
                level="warning",
            )
            for line in pointers:
                narrate(f"  · {line}", stage="S2", level="warning")

        return (
            f"All {len(assets)} files check out"
            + (f" ({repaired} re-downloaded)" if repaired else "")
            + f", {len(mani['code_deps'])} code folders in place, lockfile back where it belongs"
            + (f"; ⚠ {len(report.integrity_warnings)} files look incomplete (see integrity_warnings)"
               if report.integrity_warnings else "")
        )

    # -- S3 deps --
    def s3_deps() -> str:
        assert plan is not None and journal is not None
        venv = target / ".venv"
        py = venv / "bin" / "python"
        if (
            opts.resume
            and journal.stage("S3:deps").get("lock_sha256") == plan.lock_sha256
            and py.exists()
        ):
            return "skipped (lockfile unchanged and the environment is already here)"
        lock_path = target / LOCK_REL
        # [SECURITY-REVIEW] Dependency-source allowlist: the lock was written by
        # the sender, and uv pip sync will happily go to any host it names and
        # install executable bytes. Audit before installing; block untrusted
        # sources outright.
        from .wheels import trusted_lock_hosts

        lock_text = lock_path.read_text(encoding="utf-8", errors="replace")
        # The pack side turned the absolute path an editable install leaves
        # behind into a token; swap it for **this machine's** rebuild root before
        # feeding uv. The lock that went into the nest keeps the token — that is
        # what the byte-for-byte guarantee covers, so this is a separate working
        # copy, never an edit in place.
        if ENV_ROOT_TOKEN in lock_text:
            lock_text = resolve_env_root_token(lock_text, target)
            lock_path = target / f"{STAGING_REL}/requirements.resolved.lock"
            lock_path.write_text(lock_text, encoding="utf-8")
            narrate(
                "This nest was packed from a setup installed in place, so part of its "
                f"dependency list pointed at the folder it lived in. Pointed at {target} instead.",
                stage="S3",
            )
        # Two layers, and the order matters: baseline comes from the standing
        # list alone, and the sender gate reads **that** — fold --trust-host in
        # first and naming a host would switch the sender gate off too, so
        # attacker-supplied instructions saying `--trust-host evil.io` would walk
        # straight through. Only then does this run's --trust-host decide whether
        # we still block.
        baseline_untrusted = audit_lock_urls(lock_text, trusted=trusted_lock_hosts(), env_root=target)
        allow = trusted_lock_hosts() | {h.strip().lower() for h in opts.trust_hosts if h.strip()}
        untrusted = audit_lock_urls(lock_text, trusted=frozenset(allow), env_root=target)
        # For a nest someone handed you: the blanket bypass is never honoured
        # (that exists for automation running its own nests), and beyond naming
        # the host the sender must be named too — what the receiver really has
        # to judge is the **person**, and making them type that name out by hand
        # lands exactly on that judgement.
        sender_ok = sender_named(handed_off_from, opts.trust_sender)
        if baseline_untrusted and handed_off_from and not sender_ok:
            untrusted = baseline_untrusted
            hosts = _hosts_of(untrusted)
            raise NestFailure(
                "S3",
                ErrorClass.UNTRUSTED_SOURCE,
                f"{handed_off_from} handed you this nest, and it wants to install from "
                "servers nobody recognises.\n  Stopped — nothing was installed.\n"
                "\n  Where it wants to install from:\n    "
                + "\n    ".join(u[:120] for u in untrusted[:5])
                + "\n"
                "\n  Why that matters: installing dependencies runs code those servers hand"
                "\n  you, on this machine. It can read the models you just restored, your"
                "\n  storage credentials, and whatever else is here."
                "\n"
                f"\n  You did not pack this nest — {handed_off_from} gave it to you."
                f"\n  Two questions:"
                f"\n      1. Do you recognise the domain above?"
                f"\n      2. Do you trust {handed_off_from}?"
                + (
                    f"\n"
                    f"\n  ⚠ One more thing worth knowing: {handed_off_from} was passing"
                    f"\n    this on too. They did not pack it — it reached them from someone"
                    f"\n    else. So knowing {handed_off_from} does not make this nest safe."
                    f"\n    Ask them first: did you check this one?"
                    if handed_off_relayed
                    else ""
                )
                + "\n"
                "\n  Only go on if both answers are yes. To go on, name both — spell the"
                "\n  name exactly as shown:"
                "\n        "
                + " ".join(f"--trust-host {h}" for h in hosts[:3])
                + f' --trust-sender "{handed_off_from}"'
                + "\n"
                "\n  Unsure about either one? Do not allow it. Ask them why their setup"
                "\n  installs from that domain."
                "\n  (--trust-unsafe-urls, which allows everything at once, is ignored for"
                "\n  nests someone gave you.)",
            )
        if untrusted and not opts.trust_unsafe_urls:
            hosts = _hosts_of(untrusted)
            shown = "\n  ".join(u[:120] for u in untrusted[:5])
            more = f"\n  …and {len(untrusted) - 5} more" if len(untrusted) > 5 else ""
            raise NestFailure(
                "S3",
                ErrorClass.UNTRUSTED_SOURCE,
                "This nest wants to install from servers nobody recognises."
                "\n  Stopped — nothing was installed.\n"
                "\n  Where it wants to install from:\n    "
                + shown.replace("\n  ", "\n    ")
                + more
                + "\n"
                "\n  Why that matters: installing dependencies runs code those servers hand"
                "\n  you, on this machine. It can read everything here — the models you just"
                "\n  restored, your storage credentials, whatever else is on this box."
                "\n"
                "\n  > First answer one question: did you pack this nest, or did someone"
                "\n    give it to you?"
                "\n"
                "\n    - You packed it (a private index at work, say) — name the host"
                "\n      and run this again:"
                + "\n        "
                + " ".join(f"--trust-host {h}" for h in hosts[:3])
                + ("  …" if len(hosts) > 3 else "")
                + "\n"
                "\n    - Someone gave it to you — stop and think: do you trust them?"
                "\n      Do you recognise that domain? If not, do not allow it — go ask"
                "\n      where the nest came from. A nest built to attack you uses exactly"
                "\n      this step, and the restore looks normal the whole time.",
            )
        if untrusted:
            narrate(
                f"⚠ Allowing {len(untrusted)} unrecognised sources because you passed "
                f"--trust-unsafe-urls:"
                + ", ".join(u[:80] for u in untrusted[:3]),
                stage="S3",
                level="warning",
            )
        # idempotence: wipe first (uv hard-fails on a half-dead dir, --clear is a placebo)
        shutil.rmtree(venv, ignore_errors=True)
        r = runner(["uv", "venv", "--python", plan.python_version, str(venv)])
        if r.returncode == 127:
            raise NestFailure("S3", ErrorClass.UNKNOWN, "uv is not available — install it and it must be on PATH")
        if r.returncode != 0:
            raise NestFailure(
                "S3",
                ErrorClass.PYTHON_MISMATCH,
                f"uv could not create the environment (it needs python {plan.python_version}). A machine that cannot provide that version is the most common failure at this stage.",
                detail=(r.stderr or "")[-400:],
            )
        # If the user names where to install from, install from there.
        # **That address goes through the same allowlist** — the same rule as the
        # addresses in the manifest. It is not waved through just because "the
        # user supplied it themselves": they may be typing it off instructions
        # somebody else handed them.
        _deps_env = {"VIRTUAL_ENV": str(venv)}
        if opts.package_source:
            bad_src = audit_lock_urls(f"--index-url {opts.package_source}", trusted=allow)
            if bad_src:
                raise NestFailure(
                    "S3",
                    ErrorClass.UNTRUSTED_SOURCE,
                    f"We don't recognise the place you asked us to install from: "
                    f"{opts.package_source}. Installing from it means running its code on "
                    f"this machine. Name it explicitly if you meant it: "
                    f"--trust-host {urlparse(opts.package_source).hostname or opts.package_source}",
                )
            # uv reads this environment variable to decide where to fetch
            # packages. An environment variable rather than a command-line flag,
            # so the emergency script can use the very same mechanism (it may not
            # add dependencies and has only environment variables to work with).
            _deps_env["UV_DEFAULT_INDEX"] = opts.package_source
            narrate(
                f"Installing dependencies from {opts.package_source} instead of the default. "
                f"Every package is still checked against the fingerprint recorded in the nest, "
                f"so wrong bytes stop the rebuild instead of quietly landing.",
                stage="S3",
            )
        _t_deps = time.monotonic()
        r = runner(["uv", "pip", "sync", str(lock_path)], env=_deps_env)
        if r.returncode != 0:
            # Pinned wheel withdrawn? Fall back to the generic version and try
            # once more (warn, never silently; details in wheels.py)
            fallback = _wheel_fallback(lock_path, client, narrate, report)
            if fallback:
                r = runner(["uv", "pip", "sync", str(fallback)], env=_deps_env)
        if r.returncode != 0:
            stderr = r.stderr or ""
            klass, why = classify_deps_failure(stderr)
            raise NestFailure("S3", klass, why, detail=stderr[-400:])
        # When installing is slow, **volunteer that this switch exists** — the
        # difference between twenty minutes and a whole afternoon. Only when no
        # source was named; nagging someone who already named one is noise.
        _deps_secs = time.monotonic() - _t_deps
        if _deps_secs > SLOW_DEPS_SECONDS and not opts.package_source:
            # This wording must not promise byte checking it cannot deliver: a
            # source switch re-routes exactly the packages that carry no
            # fingerprint, while the few pinned to direct addresses never touch
            # an index at all. It feeds a supply-chain decision — naming a host
            # with --trust-host means "I trust this site", never "I verified
            # these bytes".
            narrate(
                f"Installing dependencies took {int(_deps_secs / 60)} min. If that felt slow, "
                f"where the packages come from is often the reason, and you can point us at a "
                f"closer one: --package-source <address>. Two things to know before you do: "
                f"packages this nest pins to an exact download address are checked against "
                f"their fingerprint, but the rest are fetched by name and version from "
                f"whichever index you name — those bytes are not compared against anything. "
                f"So point this at an index you actually trust; you will also have to name it "
                f"explicitly with --trust-host.",
                stage="S3",
                level="warning",
            )
        # After installing, **ask torch itself**: does the CUDA version actually
        # installed match what the nest declared?
        # Reading the lockfile is not enough — the lock says "what we intend to
        # install", and what ends up installed is another matter (a dead pinned
        # address falling back to a generic build, or a version preinstalled in
        # the image jumping the queue, without the lockfile changing by a single
        # character). If torch is not found we skip, not fail: not every
        # environment installs torch.
        from .doctor import check_torch_runtime_cuda, declared_cuda_tag
        probe = runner([str(venv / "bin" / "python"), "-c",
                        "import torch;print(torch.version.cuda or '')"])
        if probe.returncode == 0:
            # Only a probe that **ran** has anything to say: the last line we get
            # is the CUDA version torch reports about itself (with a CPU-only
            # build it reports an empty string — that is "installed but without
            # CUDA", a real problem).
            # A probe that **did not run** (no torch in the environment at all,
            # which is legal) passes None, meaning "cannot ask, nothing to
            # compare".
            got = (probe.stdout or "").strip().splitlines()
            verdict = check_torch_runtime_cuda(
                got[-1].strip() if got else None,
                declared_cuda_tag(lock_path.read_text(errors="replace")))
            report.checks_after_deps = verdict.reading | {"level": verdict.level,
                                                          "reason": verdict.reason}
            if verdict.level == "reject" and not opts.force:
                # **A hard block, not a warning.** Letting declared and actual
                # CUDA diverge only makes the later failure harder to diagnose —
                # what surfaces is "could not find some library", which nobody
                # reads as a version mismatch. `--force` is the way past it.
                raise NestFailure("S3", ErrorClass.CUDA_BLOCK, verdict.reason,
                                  context=verdict.reading)
            if verdict.level != "pass":
                narrate(f"⚠ {verdict.reason}", stage="S3", level="warning")

        journal.mark_stage("S3:deps", lock_sha256=plan.lock_sha256)
        return (
            f"Python environment ready (python {plan.python_version})"
            + (f"; ⚠ {len(report.wheel_fallbacks)} packages had their pinned download removed upstream, so the generic version was installed instead"
               if report.wheel_fallbacks else "")
        )

    # -- S4 launch --
    # Dispatch by entrypoint.kind: oneshot (runs to completion, verdict = exit
    # code) goes to OneshotRunner, service (long-running, verdict = probe) goes
    # to the launcher. Neither present = the legacy path, so older nests are
    # unaffected.
    def _is_oneshot() -> bool:
        ep = (plan.entrypoint or {}) if plan else {}
        return ep.get("kind") == "oneshot"

    def s4_launch() -> str:
        if opts.skip_launch:
            return "skipped (--skip-launch)"
        assert plan is not None
        py = target / ".venv" / "bin" / "python"
        if _is_oneshot():
            ep = plan.entrypoint or {}
            want = int((ep.get("success") or {}).get("exit_code", 0))
            res = (opts.oneshot_runner or OneshotRunner()).run(
                target, ep, py, evidence / "entrypoint.log"
            )
            report.oneshot = {
                "exit_code": res.exit_code,
                "expected_exit_code": want,
                "seconds": res.seconds,
                "log": str(res.log_path),
            }
            if res.exit_code != want:
                raise NestFailure(
                    "S4",
                    ErrorClass.STARTUP_CRASH,
                    f"This nest's run finished with code {res.exit_code}, and it was packed as "
                    f"one that finishes with {want}. The environment rebuilt correctly — what "
                    f"failed is the run itself. Its log is the real diagnosis: {res.log_path}",
                    detail=_tail(res.log_path),
                    context={"exit_code": res.exit_code, "expected_exit_code": want},
                )
            # **Exit code 0 does not mean it worked**: kohya prints ERROR and
            # exits 0 when it cannot find its data, so the exit code alone would
            # report "did nothing at all" as success. If the nest declares an
            # artifact, that artifact must appear; if it declares none we go by
            # the exit code alone rather than guessing for the user.
            want_art = (ep.get("success") or {}).get("expect_artifact")
            if want_art:
                art = target / want_art
                report.oneshot["expect_artifact"] = want_art
                report.oneshot["artifact_found"] = art.exists()
                if not art.exists():
                    need_data = _looks_like_missing_user_data(res.log_path)
                    report.oneshot["need_user_data"] = need_data
                    if need_data:
                        raise NestFailure(
                            "S4",
                            ErrorClass.NEED_USER_DATA,
                            "Your setup is back — dependencies, paths and the app all check "
                            "out. What it does not have is your data: this recipe points at "
                            "training material that never travels with a nest (it stays "
                            "yours, on your own disk). Put it back where the recipe expects "
                            "it and run this again. What it expected to produce: "
                            f"{want_art}. The run's own log: {res.log_path}",
                            detail=_tail(res.log_path),
                            context={"expect_artifact": want_art, "need_user_data": True},
                        )
                    raise NestFailure(
                        "S4",
                        ErrorClass.STARTUP_CRASH,
                        f"This nest's run exited {res.exit_code} as packed, but it did not "
                        f"produce what it was packed to produce ({want_art}). Finishing "
                        f"quietly without doing the work is a thing some tools do — that is "
                        f"why the nest names the file. Its log: {res.log_path}",
                        detail=_tail(res.log_path),
                        context={"expect_artifact": want_art, "artifact_found": False},
                    )
            return f"The run finished with code {res.exit_code} in {res.seconds:.0f}s, as packed"
        try:
            handle_box["h"] = launcher.launch(
                plan.app_dir, py, evidence / "app-launch.log", entrypoint=plan.entrypoint
            )
        except NestFailure:
            raise
        except Exception as e:
            # The commonest way a cross-machine rebuild fails: files all match, packages
            # all install, and the app dies on a library that belongs to the OS. Read the
            # launch log for it *before* falling back to "would not start" — that phrase
            # sends people to re-check files that are already correct.
            _log = evidence / "app-launch.log"
            _libs = missing_system_libraries(
                _tail(_log, _SYSLIB_SCAN_CHARS) if _log.exists() else None
            ) or missing_system_libraries(str(e))
            if _libs:
                _lib = _libs[0]
                raise NestFailure(
                    "S4",
                    ErrorClass.SYSLIB_MISSING,
                    missing_library_advice(_libs, plan.base_image_ref)
                    + f" The app's own log: {_log}",
                    detail=_tail(_log) if _log.exists() else None,
                    context={"missing_system_library": _lib},
                ) from e
            raise NestFailure("S4", ErrorClass.STARTUP_CRASH, f"The app would not start: {e}") from e
        # Hand the recipe to the smoke step **through the handle**, not through the
        # launcher signature: other launchers are injected (the test harness has
        # one) and changing their call shape would break them silently.
        with contextlib.suppress(Exception):
            _recipe = plan.target / RECIPE_REL
            if _recipe.is_file():
                # Only rerun it if the nest says this recipe once produced something.
                # A recipe can land here with no verified_run at all -- someone packed
                # a workflow they were still debugging (2026-08-12 correction) -- and
                # re-running that would report a false failure, not a broken rebuild.
                if (mani.get("adapters") or {}).get("comfyui", {}).get("verified_run"):
                    handle_box["h"].recipe_path = _recipe
                else:
                    handle_box["h"].unverified_note = (
                        "this nest carries no record of this recipe ever having produced "
                        "anything, so there is nothing confirmed to reproduce."
                    )
        return "The app started and is answering"

    # -- S5 smoke --
    def s5_smoke() -> str:
        if opts.skip_launch:
            return "skipped (--skip-launch)"
        if _is_oneshot():
            # A run-to-completion nest has no separate smoke step — the S4 run
            # itself is the evidence (the standard for "it ran" is exit code 0;
            # we do not look at loss, nor at the quality of the output).
            return "not needed: this nest finishes its run rather than staying up"
        try:
            return launcher.smoke(handle_box["h"])
        except NestFailure:
            raise
        except ImageMismatch as e:
            raise NestFailure(
                "S5",
                ErrorClass.IMAGE_MISMATCH,
                f"The test render differs from the original ({e.ssim}, below the {e.threshold} threshold). A side-by-side comparison is in the evidence folder.",
                context={"ssim": e.ssim, "threshold": e.threshold},
            ) from e
        except Exception as e:
            # Read for a missing system library before falling back to the catch-all. This
            # gate, not S4, is where a short machine usually surfaces: the app starts even
            # when an extension could not import, so the break comes when the recipe asks
            # for that extension. Both places are searched -- the app's log holds the
            # loader's own words, the exception often only says the node is unavailable.
            _slog = evidence / "app-launch.log"
            _slibs = missing_system_libraries(str(e)) or missing_system_libraries(
                _tail(_slog, _SYSLIB_SCAN_CHARS) if _slog.exists() else None
            )
            if _slibs:
                _slib = _slibs[0]
                raise NestFailure(
                    "S5",
                    ErrorClass.SYSLIB_MISSING,
                    missing_library_advice(_slibs, plan.base_image_ref)
                    + f" The app's own log: {_slog}",
                    detail=_tail(_slog) if _slog.exists() else None,
                    context={"missing_system_library": _slib},
                ) from e
            raise NestFailure("S5", ErrorClass.UNKNOWN, f"The test render failed: {e}") from e

    # -- main line --
    try:
        load_inputs()
        assert plan is not None
        if opts.check_only:
            # Check without rebuilding: in one minute you know whether you can
            # get this nest in full, rather than renting a machine, running for
            # twenty minutes and only then finding a few files unreachable.
            # **No GPU needed, runs on a laptop**, so it must return before any
            # rebuild action happens.
            if not report.gated:
                narrate("Everything in this nest travels with it — nothing to fetch "
                        "from anywhere else.", stage="S1")
            report.ok = all(g["reach"] == "free" for g in report.gated)
            report.exit_code = (
                int(ExitCode.OK) if report.ok else int(ExitCode.S0_WARNING_UNCONFIRMED)
            )
            return report
        run_stage("S0", s0_precheck)
        run_stage("S1", s1_download, start_extra={"bytes_total": plan.total_bytes})
        run_stage("S2", s2_place)
        run_stage("S3", s3_deps)
        run_stage("S4", s4_launch)
        run_stage("S5", s5_smoke)
    except NestFailure as e:
        failure = e
        if plan is None:
            # prelude failure (no stage_start emitted): still emit the error event
            em.error(e)
            narrate(f"✗ [{e.stage}/{e.error_class}] {e.human}", level="error")
    finally:
        if "h" in handle_box:
            with contextlib.suppress(Exception):
                launcher.shutdown(handle_box["h"])
        if own_client:
            client.close()

    # -- wrap-up: result event + evidence to disk (metrics = restore-metrics.json) --
    secs = {s.name: s.seconds for s in report.stages}
    report.metrics = {
        "transfer_seconds": state["transfer_seconds"],
        "transfer_bytes": state["transfer_bytes"],
        "deps_seconds": secs.get("S3", 0.0),
        "verify_seconds": state["verify_seconds"],
        "total_seconds": round(time.monotonic() - t_run, 3),
        "_note": (
            "transfer_* covers the large-file stage only, counting bytes actually "
            "downloaded this run; speed = transfer_bytes / transfer_seconds. Same "
            "definition as restore-metrics.json."
        ),
    }
    report.blobs_total = len(plan.items) if plan else 0
    report.blobs_downloaded = state["blobs_downloaded"]
    report.blobs_cached = state["blobs_cached"]
    report.ok = failure is None
    report.exit_code = int(ExitCode.OK) if failure is None else failure.exit_code
    if failure:
        report.failure = failure.to_error_object()

    with contextlib.suppress(OSError):
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / "restore-metrics.json").write_text(
            json.dumps(report.metrics, ensure_ascii=False, indent=2)
        )
        if failure:
            (evidence / "error.json").write_text(
                json.dumps(report.failure, ensure_ascii=False, indent=2)
            )

    if report.ok:
        narrate(
            f"✅ Done: {report.blobs_downloaded} files downloaded, {report.blobs_cached} already here. "
            f"Took {report.metrics['total_seconds']}s. Logs and evidence: {evidence}"
        )
        if report.redactions:
            narrate(
                f"One thing still needs you: {len(report.redactions)} place(s) in this nest "
                f"point at your own files. Everything else is back."
            )
        # The machine-library shortfall is spotted before the download and said once,
        # up there. On a big nest that line is half an hour and a thousand lines of
        # progress ago, and the last thing on screen would be a plain "Done" — which
        # is how a run that will lose whole plugins reads as a clean success.
        # Measured 2026-08-12: three restores on a machine short of one library came
        # back byte-perfect, started, answered — and could not run their own recipe.
        # So the closing word carries it too. Still a warning, never a refusal
        # (2026-07-15 ruling: this leg informs, it does not block).
        _short = _libs_the_working_run_used_but_this_machine_lacks(report.precheck)
        if _short:
            narrate(
                f"Read this before you call it done: every byte is back, but this machine is "
                f"missing {len(_short)} library file(s) the working run used "
                f"({', '.join(_short[:5])}). Your files are fine — these belong to the machine's "
                f"operating system and no nest can carry them. Until they are here, parts of this "
                f"environment load silently as nothing: it will start and answer, and your own "
                f"workflow will be the thing that fails. "
                + missing_library_advice(_short, plan.base_image_ref),
                level="warn",
            )
    else:
        assert failure is not None
        narrate(
            f"[{failure.stage}/{failure.error_class}] {failure.human}"
            f"(exit {failure.exit_code}. Run the same command again to carry on where it stopped. Logs and evidence: {evidence})",
            level="error",
        )
        # Point the way, do not solicit: tell the user **that this thing exists**
        # while the thing itself stays on their own machine.
        # No email address and no link appears in this sentence — either would
        # read as "send us your logs".
        narrate(
            f"To ask us about this: `renest support --dir {target}` prints a readable, "
            f"redacted summary you can check and then paste into a ticket. "
            f"It stays on this machine until you paste it.",
            level="error",
        )
    em.result(
        ok=report.ok,
        exit_code=report.exit_code,
        nest_id=report.nest_id,
        stages={s.name: s.seconds for s in report.stages},
        metrics=report.metrics,
        # For a training nest the exit code of that run is the headline fact, so
        # it belongs on the event stream and not only in the logs.
        oneshot=report.oneshot,
        redactions=report.redactions,
        # The CUDA version torch reports after install versus what the nest
        # declared. A check nobody can see is a check that does not exist, so it
        # goes on the stream too, not only onto the report object.
        checks_after_deps=report.checks_after_deps,
        evidence_dir=str(evidence),
        blobs={
            "total": report.blobs_total,
            "downloaded": report.blobs_downloaded,
            "cached": report.blobs_cached,
        },
    )
    return report


# --------------------------------------------------------------------------
# CLI adapter (wired from renest.cli)
# --------------------------------------------------------------------------
def add_arguments(parser: argparse.ArgumentParser) -> None:
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--manifest",
        help="the nest manifest — a file on this machine, or a URL "
        "(a signed link works, which is how private buckets are read)",
    )
    src.add_argument("--grant", help="your restore code — either the file itself or a URL pointing at it")
    parser.add_argument(
        "--no-report", action="store_true",
        help="stop sending progress back to your drive. What goes back: which gate it is in, "
             "how fast, how it ended, and facts about this machine (GPU, driver, free space). "
             "Never: your file names or paths, the raw error text from other programs, or which "
             "host the files came from. On by default when the code is a URL; if it fails it "
             "goes quiet and never affects the restore",
    )
    parser.add_argument("--dir", required=True, help="where to rebuild everything")
    parser.add_argument("--blob-base", default="", help="base URL for the files, when the nest lists no sources and you have no restore code")
    parser.add_argument("--skip-precheck", action="store_true")
    parser.add_argument("--force", action="store_true", help="carry on even if this machine failed the checks")
    parser.add_argument(
        "--resume", action=argparse.BooleanOptionalAction, default=True, help="carry on where a previous run stopped (on by default)"
    )
    parser.add_argument("--reverify", action="store_true", help="re-check files an earlier run already confirmed")
    parser.add_argument("--skip-launch", action="store_true", help="rebuild only, do not start ComfyUI")
    parser.add_argument(
        "--package-source",
        default="",
        metavar="ADDRESS",
        help="install dependencies from here instead of the default place. Use it when the "
        "default is slow for you — on one real machine the difference was 37x. Every "
        "package is still checked against the fingerprint recorded in the nest, and the "
        "address itself has to be one we recognise (or name it with --trust-host)",
    )
    parser.add_argument(
        "--trust-host",
        action="append",
        default=[],
        metavar="HOST",
        help="allow one named server to install from (repeatable). Blocked by default: "
        "installing dependencies runs that server's code on this machine",
    )
    parser.add_argument(
        "--trust-sender",
        default="",
        metavar="NAME",
        help="confirm you trust whoever handed you this nest (spell the name as the "
        "restore code shows it). Required when a nest someone gave you installs from "
        "a server nobody recognises, or wants to run setup commands here",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="only check whether the files that do not travel with this nest can be "
             "fetched on this machine, then stop. Needs no GPU — run it on your laptop "
             "before you rent anything",
    )
    parser.add_argument(
        "--no-setup",
        action="store_true",
        help="do not run any setup commands the nest brought with it. You get the files; "
        "the environment may be incomplete, and the report will say which were skipped",
    )
    parser.add_argument(
        "--trust-unsafe-urls",
        action="store_true",
        help="allow every unrecognised source at once. Meant for automation over your "
        "own nests — as a person, use --trust-host so you see what you are trusting",
    )
    parser.add_argument("--retry-rounds", type=int, default=DEFAULT_RETRY_ROUNDS)
    parser.add_argument("--ssim-threshold", type=float, default=DEFAULT_SSIM_THRESHOLD)


def run_from_args(args: argparse.Namespace, emitter: EventEmitter) -> int:
    opts = RestoreOptions(
        skip_precheck=args.skip_precheck,
        force=args.force,
        resume=args.resume,
        reverify=args.reverify,
        json_events=args.json,
        # **A person watching a terminal gets told what is happening; a pipe does not.**
        # Restoring a real nest is minutes of silence otherwise -- 12 GB of transfer, then
        # a dependency install -- and the one command we hand people printed nothing at all
        # until it was over. Watched live on 2026-08-10: the founder pasted the command,
        # saw a blank terminal for minutes, and reasonably concluded it had hung. Silence
        # reads as "broken", and the fix costs nothing: the narration already exists, it
        # was merely gated behind a flag nobody passes. `--json` keeps machine output
        # clean, and a pipe or redirect stays quiet as before.
        verbose=args.verbose or (not args.json and sys.stderr.isatty()),
        verbose_explicit=args.verbose,
        skip_launch=args.skip_launch,
        trust_unsafe_urls=args.trust_unsafe_urls,
        trust_hosts=tuple(args.trust_host),
        trust_sender=args.trust_sender,
        package_source=args.package_source,
        no_setup=args.no_setup,
        check_only=args.check_only,
        blob_base=args.blob_base,
        retry_rounds=args.retry_rounds,
        ssim_threshold=args.ssim_threshold,
        no_report=args.no_report,
    )
    source = args.manifest if args.manifest else args.grant
    report = restore(source, args.dir, opts)
    if not args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    # Stale facts are how a rebuild gets refused on a machine that would have worked, so
    # the one place worth saying it is right where the rebuild just ended. On stderr, and
    # it never blocks -- reading a date must not be able to fail a restore.
    from .update_rules import warn_if_stale

    warn_if_stale(sys.stderr)
    return report.exit_code


def _telemetry_sink():
    """Observer for anonymous usage data. **Exists only if the user answered
    yes**, otherwise None.

    It is wrapped separately because "read the configuration" can itself raise
    (corrupt file, lost permissions) — a restore must not die because a side
    feature could not read its config. It hangs off the fanout rather than
    replacing the sink: the grant-code uplink (report.py) has to keep working as
    usual, and the two are unrelated.
    """
    try:
        from .config import load_config
        from .telemetry import restore_sink

        return restore_sink(load_config())
    except Exception:  # noqa: BLE001
        return None
