"""Local HTTP service for the ComfyUI plugin bridge.

A loopback-only JSON service the ComfyUI plugin calls to pack / restore / list nests,
built on the stdlib :mod:`http.server` with a hand-written router so the CLI stays
``uv tool``-installable with no heavy dependencies.

Frozen contract: ``127.0.0.1:7799``, prefix ``/api/v1``; every endpoint but
``GET /health`` needs ``Authorization: Bearer <token>``, read from
``~/.config/renest/serve.token`` (0600) or ``RENEST_TOKEN_FILE`` on **every** request
so it can be rotated without restarting ComfyUI. One in-process worker (queue cap 8,
over-cap 429); jobs persist to the state dir and become ``interrupted`` on restart.

Credentials never travel over HTTP, even on loopback: the plugin passes references,
serve resolves its own env / grant file.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import hmac
import json
import os
import queue
import re
import secrets
import sys
import tempfile
import threading
import urllib.parse
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

import platformdirs

from . import MANIFEST_VERSIONS, __version__
from .config import APP_NAME, ConfigError, CredentialSource, resolve_credentials
from .errors import ExitCode
from .events import EventEmitter

__all__ = [
    "API_PREFIX",
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "ENV_TOKEN_FILE",
    "LOG_TAIL_LINES",
    "MAX_QUEUE",
    "Job",
    "ServeApp",
    "ServeError",
    "QueueFullError",
    "resolve_token_path",
    "default_out_dir",
    "ensure_token",
    "read_token_file",
    "make_server",
    "make_handler",
    "add_arguments",
    "run_from_args",
]

DEFAULT_HOST = "127.0.0.1"  # loopback only — never bind a routable interface
DEFAULT_PORT = 7799
API_PREFIX = "/api/v1"
ENV_TOKEN_FILE = "RENEST_TOKEN_FILE"  # frozen cross-module contract name (the plugin reads it)
LOG_TAIL_LINES = 100  # `logs_tail` returns the last N lines
MAX_QUEUE = 8  # a POST over this cap gets 429

#: terminal job states (no further transitions)
_TERMINAL = frozenset({"succeeded", "failed", "interrupted", "cancelled"})

_JOB_RE = re.compile(rf"^{re.escape(API_PREFIX)}/jobs/([^/]+)$")

# CORS allow-list: loopback origins only (the ComfyUI front-end JS and other local
# plugins). Never a wildcard — these requests carry an Authorization header.
_LOOPBACK_ORIGIN_RE = re.compile(r"^https?://(127\.0\.0\.1|localhost)(:\d+)?$")


def _iso_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _env_hints(body: dict) -> dict:
    """Pass the job's "shape of the environment" hints straight through to pack.

    Only known keys are forwarded — the request body must never be able to inject
    arbitrary keyword arguments into the pack engine.
    """
    hints = {}
    for key in ("comfyui_dir", "env_python"):
        value = body.get(key)
        if isinstance(value, str) and value:
            hints[key] = value
    return hints


def default_out_dir(target: str | os.PathLike[str], *, create: bool = True) -> Path:
    """Where a nest lands when the job did not name a destination.

    Never the system temp dir: a nest the OS sweeps away, in a path nothing told the
    user about, is one they can neither find nor keep.

    It lands next to the environment that was packed, ``<environment dir>/
    renest-nests/`` — the volume the user already chose for big files, which on a
    cloud pod is the mounted persistent disk rather than a home directory wiped at
    boot. The environment dir is the target itself, unless the target is the ComfyUI
    source tree (``main.py`` + ``custom_nodes/``), in which case go one level up:
    ComfyUI's updater scans its own directory.

    If that spot is not writable, fall back to the per-user data dir — a destination
    problem must never be the reason a pack fails.
    """
    t = Path(target).resolve()
    anchor = t.parent if ((t / "main.py").is_file() and (t / "custom_nodes").is_dir()) else t
    if anchor.parent == anchor:  # target sits at the filesystem root (installs like /ComfyUI)
        anchor = Path(platformdirs.user_data_dir(APP_NAME))
    out = anchor / "renest-nests"
    fallback = Path(platformdirs.user_data_dir(APP_NAME)) / "nests"
    if not create:  # preview answers "where would it land" and must not write a single byte
        return out if os.access(anchor, os.W_OK) else fallback
    try:
        out.mkdir(parents=True, exist_ok=True)
        probe = out / ".writable"
        probe.touch()
        probe.unlink()
    except OSError:
        out = fallback
        out.mkdir(parents=True, exist_ok=True)
    return out


# --------------------------------------------------------------------------
# token (0600, atomic, lazy-read)
# --------------------------------------------------------------------------
def resolve_token_path(cli_path: str | os.PathLike[str] | None = None) -> Path:
    """Resolve the serve token path: ``--token-file`` > ``RENEST_TOKEN_FILE`` env >
    default ``~/.config/renest/serve.token`` (the frozen token-path contract)."""
    if cli_path:
        return Path(cli_path)
    env = os.environ.get(ENV_TOKEN_FILE)
    if env:
        return Path(env)
    return Path(platformdirs.user_config_dir(APP_NAME)) / "serve.token"


def read_token_file(path: Path) -> str | None:
    """Read the token content (stripped). Missing/unreadable → ``None``."""
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return text or None


def ensure_token(path: Path) -> str:
    """Return the existing token or mint a fresh 32-byte hex one, written 0600.

    Creates via ``os.open`` with mode 0600 and an atomic ``os.replace``; a
    ``chmod`` backstop keeps it 0600 even if the umask widened the tmp file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = read_token_file(path)
    if existing:
        return existing
    token = secrets.token_hex(32)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(token)
    os.replace(tmp, path)  # atomic cross-platform rename
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
    return token


# --------------------------------------------------------------------------
# errors
# --------------------------------------------------------------------------
class ServeError(Exception):
    """A request-shaped failure carrying an HTTP status + human message."""

    def __init__(self, status: int, human: str) -> None:
        self.status = status
        self.human = human
        super().__init__(human)


class QueueFullError(ServeError):
    """Queue at capacity — maps to HTTP 429."""

    def __init__(self) -> None:
        super().__init__(429, f"Job queue is full (max {MAX_QUEUE}); try again shortly")


class _JobCancelled(Exception):
    """Raised inside the event sink to unwind a running job cooperatively."""


# --------------------------------------------------------------------------
# job
# --------------------------------------------------------------------------
class Job:
    """One pack/restore job. The object shape is the frozen job schema;
    ``progress`` mirrors the four frozen progress fields of the event stream."""

    def __init__(self, id: str, kind: str, params: dict, log_path: Path) -> None:
        self.id = id
        self.kind = kind  # "pack" | "restore"
        self.params = params
        self.state = "queued"  # queued|running|succeeded|failed|interrupted|cancelled
        self.created_at = _iso_now()
        self.started_at: str | None = None
        self.finished_at: str | None = None
        self.stage: str | None = None  # restore S0..S5 / pack P1..P4
        self.progress: dict = {
            "percent": 0.0,
            "bytes_done": 0,
            "bytes_total": 0,
            "speed_mbps": 0.0,
        }
        self.logs: collections.deque[str] = collections.deque(maxlen=LOG_TAIL_LINES)
        self.result: dict | None = None
        self.error: dict | None = None
        self.log_path = log_path
        self.cancel_requested = threading.Event()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "state": self.state,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stage": self.stage,
            "progress": self.progress,
            "logs_tail": list(self.logs),
            "result": self.result,
            "error": self.error,
        }


# --------------------------------------------------------------------------
# app
# --------------------------------------------------------------------------
class ServeApp:
    """Serve state: token, job store, single-worker queue, local nest registry.

    ``pack_fn`` / ``restore_fn`` / ``creds_fn`` are injection seams (tests pass
    fakes; production defaults to the real modules) — the HTTP layer stays
    testable without touching the network or a real ComfyUI.
    """

    def __init__(
        self,
        *,
        token_file: Path,
        state_dir: Path | None = None,
        pack_fn: Callable[..., Any] | None = None,
        restore_fn: Callable[..., Any] | None = None,
        creds_fn: Callable[..., Any] | None = None,
    ) -> None:
        self.token_file = Path(token_file)
        self.state_dir = Path(state_dir) if state_dir else Path(platformdirs.user_state_dir(APP_NAME))
        self.jobs_dir = self.state_dir / "jobs"
        self.registry_path = self.state_dir / "nests.json"
        self.jobs: dict[str, Job] = {}
        self._queue: queue.Queue[str | None] = queue.Queue()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._run_worker, name="renest-serve-worker", daemon=True)
        self._pack_fn = pack_fn or _default_pack_fn
        self._restore_fn = restore_fn or _default_restore_fn
        self._creds_fn = creds_fn or resolve_credentials
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self._recover_jobs()

    # -- lifecycle ----------------------------------------------------------
    def ensure_token(self) -> str:
        return ensure_token(self.token_file)

    def read_token(self) -> str | None:
        """Lazy per-request read (never cached): supports token rotation with no
        restart."""
        return read_token_file(self.token_file)

    def start(self) -> None:
        if not self._worker.is_alive():
            self._worker.start()

    def stop(self) -> None:
        self._stop.set()
        self._queue.put(None)  # wake the worker so it can exit
        if self._worker.is_alive():
            self._worker.join(timeout=5)

    # -- recovery / persistence --------------------------------------------
    def _recover_jobs(self) -> None:
        """Load persisted jobs; any left queued/running (serve died mid-flight)
        become ``interrupted``."""
        for jf in sorted(self.jobs_dir.glob("*.json")):
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            job = Job(data["id"], data.get("kind", ""), {}, self.jobs_dir / f"{data['id']}.log")
            for k in ("created_at", "started_at", "finished_at", "stage", "result", "error"):
                setattr(job, k, data.get(k))
            job.progress = data.get("progress", job.progress)
            for line in data.get("logs_tail", []):
                job.logs.append(line)
            state = data.get("state", "interrupted")
            job.state = "interrupted" if state in ("queued", "running") else state
            self.jobs[job.id] = job

    def _persist(self, job: Job) -> None:
        with self._lock:
            tmp = self.jobs_dir / f"{job.id}.json.tmp"
            tmp.write_text(json.dumps(job.to_dict(), ensure_ascii=False, indent=1), encoding="utf-8")
            os.replace(tmp, self.jobs_dir / f"{job.id}.json")

    # -- queue / submission -------------------------------------------------
    def _active_count(self) -> int:
        return sum(1 for j in self.jobs.values() if j.state in ("queued", "running"))

    def submit(self, kind: str, params: dict) -> Job:
        with self._lock:
            if self._active_count() >= MAX_QUEUE:
                raise QueueFullError()
            job_id = "job_" + secrets.token_hex(12)
            job = Job(job_id, kind, params, self.jobs_dir / f"{job_id}.log")
            self.jobs[job_id] = job
        self._persist(job)
        self._queue.put(job_id)
        return job

    def get_job(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    def cancel(self, job_id: str) -> dict | None:
        """Cancel semantics: queued → immediate ``cancelled``;
        running → request cooperative abort (unwinds at the next event boundary,
        state settles to ``cancelled`` when the run returns); terminal → no-op."""
        with self._lock:
            job = self.jobs.get(job_id)
            if job is None:
                return None
            if job.state == "queued":
                job.cancel_requested.set()
                job.state = "cancelled"
                job.finished_at = _iso_now()
            elif job.state == "running":
                job.cancel_requested.set()
        self._persist(job)
        return {"id": job.id, "state": job.state, "cancel_requested": job.cancel_requested.is_set()}

    # -- health / nests ------------------------------------------------------
    def _storage(self) -> tuple[bool, str | None]:
        try:
            creds = self._creds_fn()
        except Exception:  # never let a credential probe crash /health
            return False, None
        if creds.source == CredentialSource.BUCKET_KEY:
            return True, "byos"
        if creds.source == CredentialSource.GRANT:
            return True, "managed"
        return False, None

    def health(self) -> dict:
        configured, kind = self._storage()
        return {
            "status": "ok",
            "version": __version__,
            "manifest_versions": list(MANIFEST_VERSIONS),
            "queue_depth": self._active_count(),
            "storage_configured": configured,
            "storage_kind": kind,
        }

    def _load_registry(self) -> list[dict]:
        try:
            data = json.loads(self.registry_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        return data if isinstance(data, list) else []

    def _save_registry(self, rows: list[dict]) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.registry_path.with_name(self.registry_path.name + ".tmp")
        tmp.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, self.registry_path)

    def list_nests(self) -> list[dict]:
        """Local registry only — never queries the bucket. Listing bucket contents
        would make this an asset browser, which is out of scope by design.
        Populated by pack/restore jobs that ran through this serve process."""
        return self._load_registry()

    def _record_nest(self, kind: str, report: Any, name: str | None) -> None:
        nest_id = getattr(report, "nest_id", "") or ""
        if not nest_id:
            return
        _configured, storage_kind = self._storage()
        # path = where the nest landed on this machine, so the registry can answer
        # "where is my nest?" without a lookup elsewhere.
        manifest_path = getattr(report, "manifest_path", "") or ""
        entry = {
            "id": nest_id,
            "name": name or nest_id,
            "size_bytes": int(getattr(report, "total_bytes", 0) or 0),
            "created_at": _iso_now(),
            "storage_kind": storage_kind,
            "path": str(Path(manifest_path).parent) if manifest_path else "",
        }
        with self._lock:
            rows = [b for b in self._load_registry() if b.get("id") != nest_id]
            rows.append(entry)
            self._save_registry(rows)

    # -- pack dry-run (synchronous preview) ---------------------------------
    def _resolve_spec(self, body: dict) -> tuple[dict | None, dict | str | None]:
        """Resolve the pack input. Returns ``(spec, workflow)`` — exactly one is
        non-None. A ready pack-spec comes inline (``spec``) or by path
        (``spec_path``). Otherwise the target-only path: a ``workflow`` (inline
        API-format dict or a path) whose item list pack reverse-infers via
        capture. Neither present → 400 (needs a spec or a workflow)."""
        spec = body.get("spec")
        if isinstance(spec, dict):
            return spec, None
        spec_path = body.get("spec_path")
        if spec_path:
            try:
                return json.loads(Path(spec_path).read_text(encoding="utf-8")), None
            except (OSError, json.JSONDecodeError) as e:
                raise ServeError(400, f"Cannot read spec_path: {e}") from e
        workflow = body.get("workflow")
        if isinstance(workflow, (dict, str)) and workflow:
            return None, workflow  # capture reverse-infers from target + workflow
        raise ServeError(
            400,
            "pack needs a pack-spec or a workflow: send spec (inline) or spec_path, "
            "or send workflow (API format) and capture will work out the item list "
            "from the target.",
        )

    def pack_dry_run(self, body: dict) -> dict:
        target = body.get("target")
        if not target:
            raise ServeError(400, "Missing target")
        spec, workflow = self._resolve_spec(body)
        with tempfile.TemporaryDirectory() as tmp:
            report = self._pack_fn(
                target, spec, tmp, dry_run=True, no_fingerprint=True, workflow=workflow,
                **_env_hints(body),
            )
        if not getattr(report, "ok", False):
            raise ServeError(400, "; ".join(f for f in report.findings if f) or "dry run failed")
        inv = report.inventory
        named = body.get("name") or (spec or {}).get("name")
        return {
            # When nobody names it, put the date in the name — otherwise every nest
            # on the machine ends up called "ComfyUI".
            "default_name": named or f"{Path(str(target)).name} {_iso_now()[:10]}",
            "items": {
                "models": [i for i in inv if i.get("role") == "asset"],
                "nodes": [i for i in inv if i.get("role") == "code_dep"],
                "deps": [i for i in inv if i.get("role") == "python_lock"],
            },
            "size_estimate_bytes": report.total_bytes,
            # The confirmation sheet must also say what is **not** going in: a custom
            # node dropped in as a plain unzip has no recoverable origin, so capture
            # cannot pack it. Drop these findings and the list looks complete while
            # the nest is missing a node.
            "warnings": [f for f in (getattr(report, "findings", None) or []) if f],
            # Where a real pack would put the nest — so the user knows the destination
            # before pressing confirm.
            "out_dir": str(
                body.get("out") or body.get("dest") or default_out_dir(target, create=False)
            ),
        }

    # -- worker -------------------------------------------------------------
    def _run_worker(self) -> None:
        while not self._stop.is_set():
            try:
                job_id = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if job_id is None:
                break
            job = self.jobs.get(job_id)
            if job is None:
                continue
            if job.cancel_requested.is_set() or job.state != "queued":
                continue  # cancelled while queued, or already handled
            self._execute(job)

    def _make_sink(self, job: Job) -> Callable[[dict], None]:
        def sink(event: dict) -> None:
            if job.cancel_requested.is_set():
                raise _JobCancelled()
            self._on_event(job, event)

        return sink

    def _on_event(self, job: Job, event: dict) -> None:
        et = event.get("type")
        if et == "stage_start":
            job.stage = event.get("stage", job.stage)
        elif et == "progress":
            job.stage = event.get("stage", job.stage)
            job.progress = {
                "percent": event.get("percent", 0.0),
                "bytes_done": event.get("bytes_done", 0),
                "bytes_total": event.get("bytes_total", 0),
                "speed_mbps": event.get("speed_mbps", 0.0),
            }
        elif et == "error":
            job.error = {k: v for k, v in event.items() if k not in ("type", "ts")}
        line = json.dumps(event, ensure_ascii=False)
        job.logs.append(line)
        with contextlib.suppress(OSError):
            with job.log_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

    def _execute(self, job: Job) -> None:
        job.state = "running"
        job.started_at = _iso_now()
        if job.kind == "pack":
            job.stage = "P1"
        self._persist(job)
        try:
            report = self._run_pack(job) if job.kind == "pack" else self._run_restore(job)
        except _JobCancelled:
            self._settle_cancelled(job)
            return
        except Exception as e:  # backstop: a crash still yields a truthful job
            job.state = "failed"
            job.error = {
                "stage": job.stage or "?",
                "error_class": "UNKNOWN",
                "detail": f"{type(e).__name__}: {e}",
                "human": str(e),
            }
            job.finished_at = _iso_now()
            self._persist(job)
            return
        if job.cancel_requested.is_set():
            # cancel landed during the run: the module converted it to a stage
            # failure, but the operator intent was cancel → settle as cancelled.
            self._settle_cancelled(job)
            return
        self._settle_report(job, report)

    def _settle_cancelled(self, job: Job) -> None:
        job.state = "cancelled"
        job.finished_at = _iso_now()
        self._persist(job)

    def _settle_report(self, job: Job, report: Any) -> None:
        ok = getattr(report, "ok", False) and int(getattr(report, "exit_code", 1)) == 0
        job.finished_at = _iso_now()
        if ok:
            job.state = "succeeded"
            job.result = report.to_dict()
            if job.kind == "pack" and job.params.get("shutdown_after"):
                # advisory only: serve records intent, never kills the host itself
                job.result["shutdown_at"] = _iso_now()
            self._record_nest(job.kind, report, job.params.get("name"))
        else:
            job.state = "failed"
            job.error = getattr(report, "failure", None) or {
                "stage": job.stage or "?",
                "error_class": "UNKNOWN",
                "detail": "The job failed but carried no error object",
                "human": "Job failed",
            }
        self._persist(job)

    def _run_pack(self, job: Job) -> Any:
        body = job.params
        spec, workflow = self._resolve_spec(body)
        # ``out`` = the local folder the nest lands in (as the CLI ``--out``); left
        # empty, ``default_out_dir`` puts it beside the environment, never in temp.
        # ``dest`` is the old name, kept for compatibility only -- it collides with
        # the CLI ``--dest``, which means "which cloud to upload to".
        dest = body.get("out") or body.get("dest") or str(default_out_dir(body["target"]))
        emitter = EventEmitter(json_mode=False, sink=self._make_sink(job))
        return self._pack_fn(
            body["target"],
            spec,
            dest,
            no_fingerprint=bool(body.get("no_fingerprint", False)),
            workflow=workflow,
            emitter=emitter,
            # The plugin runs inside the application process and reports the real
            # shape of the environment; the engine never guesses. comfyui_dir = the
            # source tree (not the data dir on the desktop build); env_python = the
            # running interpreter, read live when there is no lock file.
            **_env_hints(body),
        )

    def _run_restore(self, job: Job) -> Any:
        body = job.params
        return self._restore_fn(body, self._make_sink(job))


# --------------------------------------------------------------------------
# default (production) executors — call the real modules read-only
# --------------------------------------------------------------------------
def _default_pack_fn(*args: Any, **kwargs: Any) -> Any:
    from .pack import pack  # local import: keeps `serve` import light

    return pack(*args, **kwargs)


def _default_restore_fn(body: dict, sink: Callable[[dict], None]) -> Any:
    from .restore import RestoreOptions, restore

    nest_ref = body.get("nest_ref")
    target = body.get("target")
    verify_level = body.get("verify_level")
    opts = RestoreOptions(
        skip_precheck=bool(body.get("skip_doctor", False)),
        force=bool(body.get("force", False)),
        resume=True,  # same as --resume: continue an earlier run of this nest + target
        skip_launch=(verify_level == "none"),
        json_events=False,
        event_sink=sink,
    )
    return restore(nest_ref, target, opts)


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------
def make_handler(app: ServeApp) -> type[BaseHTTPRequestHandler]:
    """Build a request handler class bound to ``app``."""

    class _Handler(BaseHTTPRequestHandler):
        server_version = f"renest-serve/{__version__}"

        def log_message(self, *_args: Any) -> None:  # silence default stderr spam
            pass

        # -- helpers --
        def _cors_origin(self) -> str | None:
            origin = self.headers.get("Origin", "")
            return origin if _LOOPBACK_ORIGIN_RE.match(origin) else None

        def _send(self, code: int, payload: dict) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            origin = self._cors_origin()
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            self.end_headers()
            self.wfile.write(body)

        # CORS preflight: browsers send it without an Authorization header, so it
        # must not require auth.
        def do_OPTIONS(self) -> None:
            # Deliberately unauthenticated: a browser preflight never carries the
            # Authorization header, so requiring a token here would block every
            # browser call. Do not copy this exemption into any other handler.
            origin = self._cors_origin()
            self.send_response(204)
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
                self.send_header("Access-Control-Max-Age", "600")
                self.send_header("Vary", "Origin")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _authed(self) -> bool:
            token = self.app.read_token()
            if not token:
                return False
            header = self.headers.get("Authorization", "")
            prefix = "Bearer "
            if not header.startswith(prefix):
                return False
            return hmac.compare_digest(header[len(prefix):], token)

        def _require_auth(self) -> bool:
            if self._authed():
                return True
            self._send(401, {"error": "Not authorized: send Authorization: Bearer <token>"})
            return False

        def _read_json(self) -> dict | None:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            if not raw:
                return {}
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                return None
            return data if isinstance(data, dict) else None

        # -- verbs --
        def do_GET(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            if path == f"{API_PREFIX}/health":
                self._send(200, self.app.health())
                return
            if not self._require_auth():
                return
            if path == f"{API_PREFIX}/nests":
                self._send(200, {"nests": self.app.list_nests()})
                return
            m = _JOB_RE.match(path)
            if m:
                job = self.app.get_job(m.group(1))
                if job is None:
                    self._send(404, {"error": "No such job"})
                    return
                self._send(200, job.to_dict())
                return
            self._send(404, {"error": "Unknown path"})

        def do_POST(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            if not self._require_auth():
                return
            if path not in (f"{API_PREFIX}/pack", f"{API_PREFIX}/restore"):
                self._send(404, {"error": "Unknown path"})
                return
            body = self._read_json()
            if body is None:
                self._send(400, {"error": "Request body is not a valid JSON object"})
                return
            if path == f"{API_PREFIX}/pack":
                self._handle_pack(body)
            else:
                self._handle_restore(body)

        def do_DELETE(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            if not self._require_auth():
                return
            m = _JOB_RE.match(path)
            if not m:
                self._send(404, {"error": "Unknown path"})
                return
            result = self.app.cancel(m.group(1))
            if result is None:
                self._send(404, {"error": "No such job"})
                return
            self._send(200, result)

        # -- handlers --
        def _handle_pack(self, body: dict) -> None:
            if not body.get("target"):
                self._send(400, {"error": "Missing target"})
                return
            if body.get("dry_run"):
                try:
                    self._send(200, self.app.pack_dry_run(body))
                except ServeError as e:
                    self._send(e.status, {"error": e.human})
                return
            self._enqueue("pack", body)

        def _handle_restore(self, body: dict) -> None:
            if not body.get("nest_ref") or not body.get("target"):
                self._send(400, {"error": "Missing nest_ref or target"})
                return
            self._enqueue("restore", body)

        def _enqueue(self, kind: str, body: dict) -> None:
            try:
                job = self.app.submit(kind, body)
            except QueueFullError as e:
                self._send(e.status, {"error": e.human})
                return
            self._send(202, {"job_id": job.id})

    _Handler.app = app  # type: ignore[attr-defined]
    return _Handler


def make_server(app: ServeApp, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    """Build (but do not serve) a threading HTTP server bound to ``host:port``.
    ``port=0`` binds an ephemeral port (tests)."""
    return ThreadingHTTPServer((host, port), make_handler(app))


# --------------------------------------------------------------------------
# CLI adapter
# --------------------------------------------------------------------------
def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--port", type=int, default=None, help="port to listen on (default 7799)")
    parser.add_argument("--host", default=DEFAULT_HOST, help=argparse.SUPPRESS)  # loopback only
    parser.add_argument(
        "--token-file", default=None, help="path to the token file (default ~/.config/renest/serve.token)"
    )


def run_from_args(args: argparse.Namespace, emitter: EventEmitter) -> int:
    port = args.port
    if port is None:
        from .config import load_config

        try:
            port = load_config().serve_port
        except ConfigError:
            port = DEFAULT_PORT
    token_path = resolve_token_path(getattr(args, "token_file", None))
    app = ServeApp(token_file=token_path)
    app.ensure_token()
    app.start()
    try:
        server = make_server(app, args.host, port)
    except OSError as e:
        print(f"✗ Cannot listen on port {port}: {e}. Pick another one with --port.", file=sys.stderr)
        app.stop()
        return int(ExitCode.USAGE)
    print(f"renest serve is listening on http://{args.host}:{port}{API_PREFIX} (loopback only)", file=sys.stderr)
    print(
        f"Token file: {token_path} (0600). The plugin reads the same file, "
        f"or point it there with {ENV_TOKEN_FILE}.",
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Interrupted; stopping serve", file=sys.stderr)
    finally:
        server.shutdown()
        server.server_close()
        app.stop()
    return int(ExitCode.OK)
