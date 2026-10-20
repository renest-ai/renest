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
import time
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
    "is_loopback_host",
    "make_server",
    "make_handler",
    "add_arguments",
    "run_from_args",
]

DEFAULT_HOST = "127.0.0.1"  # loopback only — never bind a routable interface
DEFAULT_PORT = 7799
API_PREFIX = "/api/v1"
ENV_TOKEN_FILE = "RENEST_TOKEN_FILE"  # serve honours it; the panel stopped reading it in 0.1.7 (pointer file instead)
LOG_TAIL_LINES = 100  # `logs_tail` returns the last N lines
MAX_QUEUE = 8  # a POST over this cap gets 429

#: terminal job states (no further transitions)
_TERMINAL = frozenset({"succeeded", "failed", "interrupted", "cancelled"})

_JOB_RE = re.compile(rf"^{re.escape(API_PREFIX)}/jobs/([^/]+)$")
_TAKEBACK_SESSION_RE = re.compile(rf"^{re.escape(API_PREFIX)}/takeback/sessions/([A-Za-z0-9_-]{{1,64}})$")
#: How long a take-back session (the approval's token, held in memory) is kept around.
TAKEBACK_SESSION_TTL_S = 3600.0

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
    for key in ("comfyui_dir", "program_dir", "env_python"):
        value = body.get(key)
        if isinstance(value, str) and value:
            hints[key] = value
    return hints


#: Where the local service keeps the installation's id, beside the app (format 2.15).
ENVIRONMENT_ID_REL = Path(".renest") / "environment-id"


def environment_id_for(comfyui_dir: str | os.PathLike[str], *, create: bool) -> str | None:
    """The stable id of the ComfyUI installation at ``comfyui_dir``.

    Minted once (a ULID) and kept in ``<ComfyUI>/.renest/environment-id`` so every nest
    saved from this installation carries the same value and the drive can group them.
    ``create=False`` (a preview) only reads: a preview writes nothing. Any trouble
    reading or writing answers ``None`` -- a nest without the label is still a nest.
    """
    path = Path(comfyui_dir) / ENVIRONMENT_ID_REL
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        text = ""
    if re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", text):
        return text
    if not create:
        return None
    from .pack import ulid  # local import: keeps serve import light

    fresh = ulid()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(fresh, encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        return None
    return fresh


def _workflow_ui(body: dict) -> dict | None:
    """The canvas as the panel sent it (``app.graphToPrompt().workflow``), so the
    restored app's Workflows sidebar can open it. Inline only: a path here would let
    a request have pack read any file on the machine into a nest."""
    ui = body.get("workflow_ui")
    return ui if isinstance(ui, dict) and ui else None


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
    default = Path(platformdirs.user_config_dir(APP_NAME)) / "serve.token"
    chosen = Path(cli_path) if cli_path else None
    if chosen is None:
        env = os.environ.get(ENV_TOKEN_FILE)
        chosen = Path(env) if env else default
    _leave_pointer(chosen, default)
    return chosen


#: Where the panel looks when the token is not in the default place. **The panel
#: cannot read the environment**: the ComfyUI Registry's scanner treats any such
#: read as credential access and flags the release (0.1.5 was flagged for exactly
#: that), which pins every user to an older panel. So the override still exists,
#: it is just written down here instead of being passed through a variable.
POINTER_REL = "token-path"


def _leave_pointer(chosen: Path, default: Path) -> None:
    """Record a non-default token location where the panel can read it."""
    pointer = default.parent / POINTER_REL
    try:
        if chosen == default:
            pointer.unlink(missing_ok=True)
            return
        pointer.parent.mkdir(parents=True, exist_ok=True)
        pointer.write_text(str(chosen), encoding="utf-8")
        pointer.chmod(0o600)
    except OSError:
        # Never fail serving because the hint could not be written.
        pass


#: Where the panel reads the pointer, spelled the way the panel spells it
#: (comfyui-renest/__init__.py, ``_token_candidates``): built from the home folder
#: on every system, never from the environment.
PANEL_POINTER = Path(".config") / "renest" / POINTER_REL


def token_notice(token_path: Path) -> str:
    """The startup line about the token, matching how the panel finds it today.

    It used to say "or point it there with RENEST_TOKEN_FILE"; the panel has not read
    that variable since 0.1.7 (a Registry scanner flags any such read), and finds a
    token kept elsewhere through the pointer file instead (2026-10-03, Spark).
    """
    default = Path(platformdirs.user_config_dir(APP_NAME)) / "serve.token"
    if token_path == default:
        return (f"Token file: {token_path} (0600). The Renest panel in ComfyUI reads it "
                f"from there.")
    pointer = default.parent / POINTER_REL
    if pointer == Path.home() / PANEL_POINTER:
        return (f"Token file: {token_path} (0600). Its location is written to {pointer}, "
                f"which is where the Renest panel in ComfyUI looks for a token kept "
                f"outside the default place.")
    return (f"Token file: {token_path} (0600). The Renest panel in ComfyUI looks for it "
            f"at {default}, or wherever {Path.home() / PANEL_POINTER} names; on this "
            f"system neither points here, so start serve without --token-file for the "
            f"panel to find it.")


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


class _JobFailed(Exception):
    """Ends a job as ``failed`` with a ready error object (no traceback text)."""

    def __init__(self, error: dict) -> None:
        super().__init__(error.get("human", ""))
        self.error = error


#: Said when the panel asks for an upload and this machine has no Renest sign-in.
#: The panel shows the command with a Copy button; keep the command last.
NOT_SIGNED_IN = "This machine is not signed in to Renest. In its terminal, run: renest login"

#: Bounds on how often serve asks whether an upload was approved.
APPROVAL_MIN_INTERVAL_S = 1.0
APPROVAL_MAX_INTERVAL_S = 30.0
#: How long past the approval's own expiry the poll keeps asking (clock skew, one slow
#: last poll).
APPROVAL_DEADLINE_GRACE_S = 5.0
#: Said once per wait, the first time a poll fails for a reason worth retrying.
_SLOW_NETWORK_NOTE = ("The network to the Renest service is slow or dropping; still waiting "
                      "for your approval and trying again.")


def _poll_until_answered(job: Any, poll: Any, *, interval: float, deadline: float,
                         on_slow: Any) -> dict:
    """One approval wait: ``poll()`` until it returns a body or the deadline passes.

    A **transient** failure (timeout, connection error, 429/502/503/504) never ends the
    wait: the gap doubles up to :data:`APPROVAL_MAX_INTERVAL_S`, ``on_slow`` is told
    once, and the next try goes out -- the person is on the approval page, and the
    approval they give must not be lost to one dropped packet (production,
    2026-10-20). A definite refusal is raised as it came. Past the deadline the last
    transient failure is raised, and the caller reads it as a network failure.
    """
    from .approval import ApprovalError

    gap = interval
    said = False
    while True:
        if job.cancel_requested.wait(gap):
            raise _JobCancelled()
        try:
            got = poll()
        except ApprovalError as e:
            if not e.transient or time.monotonic() > deadline:
                raise
            if not said:
                said = True
                on_slow()
            gap = min(gap * 2, APPROVAL_MAX_INTERVAL_S)
            continue
        gap = interval
        return got


def _failure(stage: str, error_class: str, human: str,
             actions: list[dict] | None = None) -> dict:
    out = {"stage": stage, "error_class": error_class, "detail": human, "human": human}
    if actions:
        # Ways forward the Renest service offered (``[{"label", "url"}]``, web pages
        # only -- approval._actions dropped anything else); the panel shows them as links.
        out["actions"] = list(actions)
    return out


def _approval_refusal(stage: str, e: Any) -> dict:
    """A refusal from the approval endpoints, as the job's error.

    401 stays ``NOT_SIGNED_IN`` (the panel answers it with ``renest login``); any other
    refusal the service named keeps the service's own code, sentence and ways forward,
    so a paywall reads as a paywall and not as "the upload was not approved".
    """
    if e.status == 401:
        return _failure(stage, "NOT_SIGNED_IN", e.human)
    if getattr(e, "transient", False):
        # Not an answer at all: the service was never reached. Said as a network
        # failure (production 2026-10-20: it read as "the upload was not approved").
        return _failure(stage, "NETWORK_INTERRUPTED", e.human)
    return _failure(stage, e.code or "UPLOAD_NOT_APPROVED", e.human, e.actions)


#: Said when a job ends red and nothing more specific survived. Never "Job failed":
#: that sentence is how a 402 from the drive reached a person on 2026-10-17.
UNEXPLAINED_FAILURE = ("Packing stopped without saying why. The log below shows the last "
                       "thing it was doing.")


def _job_error(failure: Any, findings: Any, stage: str) -> dict:
    """The job's error object from what a red report carried.

    * a failure object the drive refusal filled in (``context.server_code``) is handed
      on as the service said it: its code, its sentence, its ways forward;
    * any other failure object goes through unchanged;
    * none at all (most ``PackError``s carry only a sentence): the last thing the report
      said, which is that sentence -- dropping it is how "Job failed" happened.
    """
    if isinstance(failure, dict) and failure:
        ctx = failure.get("context") if isinstance(failure.get("context"), dict) else {}
        code = ctx.get("server_code")
        if isinstance(code, str) and code:
            out = dict(failure)
            out["error_class"] = code
            out["human"] = failure.get("human") or failure.get("detail") or UNEXPLAINED_FAILURE
            if ctx.get("actions"):
                out["actions"] = list(ctx["actions"])
            return out
        return failure
    said = [f for f in (findings or []) if isinstance(f, str) and f.strip()]
    human = said[-1] if said else UNEXPLAINED_FAILURE
    return {"stage": stage or "?", "error_class": "UNKNOWN", "detail": human, "human": human}


def _console_base(verify_url: str) -> str | None:
    """The web console's address, read off the approval page the service named.

    The engine has no setting of its own for it, and inventing one would drift from
    the console the person actually approved in.
    """
    try:
        u = urllib.parse.urlsplit(verify_url)
    except ValueError:
        return None
    if u.scheme not in ("https", "http") or not u.netloc:
        return None
    path = u.path
    cut = path.rfind("/approve")
    prefix = path[:cut] if cut >= 0 else ""
    return f"{u.scheme}://{u.netloc}{prefix}"


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
        #: While an upload waits for the person's approval: what the panel shows
        #: (``user_code``, ``verify_url``, ``expires_at``). Never a credential.
        self.approval: dict | None = None
        #: Where the upload landed on the Renest drive; folded into ``result``.
        self.drive: dict | None = None
        #: What became of the local staging after the drive checked the nest
        #: (format-independent; see :mod:`renest.staging`). Folded into ``result``.
        self.local_copy: dict | None = None

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
            "approval": self.approval,
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
        signin_token_fn: Callable[[], str | None] | None = None,
        origin: str | None = None,
        http_client_fn: Callable[[], Any] | None = None,
        uploader_cls: Callable[..., Any] | None = None,
        approval_min_interval: float = APPROVAL_MIN_INTERVAL_S,
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
        # Upload path (panel → Renest drive). The sign-in token is read fresh for each
        # job and the upload-once token never leaves the job's own stack frame.
        self._signin_token_fn = signin_token_fn or _default_signin_token
        self._origin = origin
        self._http_client_fn = http_client_fn or _default_http_client
        self._uploader_cls = uploader_cls
        self._approval_min_interval = approval_min_interval
        #: What the last preview already read, kept for the pack behind the
        #: button. One slot, keyed by target -- see :meth:`_read_record_for`.
        self._read_record: tuple[str, Any] | None = None
        #: [SECURITY-REVIEW] Take-back sessions (the panel's "Take back", 2026-10-19):
        #: session id -> the take-back-once token the person approved in their browser,
        #: plus what it may be used for. **Memory only**: never persisted, never in a job's
        #: params, logs or result. Dropped when the session is closed or expires.
        self._takeback: dict[str, dict] = {}
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self._recover_jobs()

    def _read_record_for(self, target: Any) -> Any:
        """The record of "already hashed this file" shared by the confirm page's
        preview and the pack that follows it.

        The preview is a dry run and a dry run writes nothing to the user's
        folder, so nothing on disk can carry those hashes over -- without this
        the pack behind the button reads every weight a second time (measured
        2026-08-30: 2.00x). Kept in memory only, and only for the target it was
        built from: the record pins itself to one folder's file the first time it
        is used, so handing it to a different target would save it in the wrong
        place. An entry is still believed only while size, time and inode all
        match, so a stale record costs a re-read, never a wrong fingerprint.
        """
        from .pack import HashCache

        key = str(Path(str(target)).resolve())
        with self._lock:
            if self._read_record is None or self._read_record[0] != key:
                self._read_record = (key, HashCache(None))
            return self._read_record[1]

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
            if job.state == "interrupted" and not job.error:
                # Said here, once, so the panel never has to show "did not say why".
                job.error = {"stage": job.stage or "?", "error_class": "INTERRUPTED",
                             "detail": "renest serve stopped while this job was running",
                             "human": "The Renest engine stopped while this was running. "
                                      "Nothing was finished by half; start it again."}
            self.jobs[job.id] = job

    def _persist(self, job: Job) -> None:
        with self._lock:
            tmp = self.jobs_dir / f"{job.id}.json.tmp"
            tmp.write_text(json.dumps(job.to_dict(), ensure_ascii=False, indent=1), encoding="utf-8")
            os.replace(tmp, self.jobs_dir / f"{job.id}.json")

    @staticmethod
    def _cancellable_sleep(job: Any) -> Any:
        """A sleep for retries that a cancel cuts short."""
        def sleep(seconds: float) -> None:
            if job.cancel_requested.wait(seconds):
                raise _JobCancelled()
        return sleep

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

    def _record_nest(self, kind: str, report: Any, name: str | None,
                     extra: dict | None = None) -> None:
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
            **(extra or {}),
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
                workflow_ui=_workflow_ui(body),
                hash_cache=self._read_record_for(target),
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
            if job.kind == "pack":
                report = self._run_pack(job)
            elif job.kind == "takeback_session":
                report = self._run_takeback_session(job)
            elif job.kind == "takeback":
                report = self._run_takeback(job)
            else:
                report = self._run_restore(job)
        except _JobCancelled:
            self._settle_cancelled(job)
            return
        except _JobFailed as e:
            job.state = "failed"
            job.approval = None
            job.error = e.error
            if job.local_copy:
                job.error = {**job.error, "local_copy": job.local_copy}
            job.finished_at = _iso_now()
            self._persist(job)
            return
        except Exception as e:  # backstop: a crash still yields a truthful job
            job.state = "failed"
            job.error = {
                "stage": job.stage or "?",
                "error_class": "UNKNOWN",
                "detail": f"{type(e).__name__}: {e}",
                "human": str(e) or f"{type(e).__name__}. {UNEXPLAINED_FAILURE}",
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
        job.approval = None
        job.state = "cancelled"
        job.finished_at = _iso_now()
        self._persist(job)

    def _settle_report(self, job: Job, report: Any) -> None:
        if job.kind in ("takeback_session", "takeback"):
            # These two hand back a plain dict and never a PackReport; a failure is
            # raised as _JobFailed before this point.
            job.state = "succeeded"
            job.result = dict(report)
            job.finished_at = _iso_now()
            self._persist(job)
            return
        ok = getattr(report, "ok", False) and int(getattr(report, "exit_code", 1)) == 0
        job.finished_at = _iso_now()
        if ok:
            job.state = "succeeded"
            job.result = report.to_dict()
            if job.drive:
                job.result["drive"] = job.drive
            if job.local_copy:
                job.result["local_copy"] = job.local_copy
                if job.local_copy.get("released"):
                    # The path pack reported no longer exists; a success page that shows
                    # it would send the person to an empty folder.
                    job.result.pop("manifest_path", None)
            if job.kind == "pack" and job.params.get("shutdown_after"):
                # advisory only: serve records intent, never kills the host itself
                job.result["shutdown_at"] = _iso_now()
            if not (job.local_copy or {}).get("released"):
                pending = (job.drive or {}).get("verdict") == "pending"
                # A save the drive has not finished checking keeps its staging; the row
                # remembers that, so the next take-back session (whose token can see which
                # versions are checked) can let it go -- see _sweep_pending_staging.
                self._record_nest(job.kind, report, job.params.get("name"), extra=(
                    {"verdict": "pending", "nest_version_id": (job.drive or {}).get("nest_version_id")}
                    if pending else None))
        else:
            job.state = "failed"
            job.error = _job_error(getattr(report, "failure", None),
                                   getattr(report, "findings", None), job.stage or "?")
        self._persist(job)

    def _run_pack(self, job: Job) -> Any:
        if job.params.get("upload") is True:
            return self._run_pack_upload(job)
        return self._pack_once(job)

    # -- upload to the Renest drive, approved once in the person's browser ------
    def signed_in(self) -> bool:
        return bool(self._signin_token())

    def _signin_token(self) -> str | None:
        try:
            return self._signin_token_fn() or None
        except Exception:  # an unreadable config is "not signed in", never a crash
            return None

    def _api_origin(self) -> str:
        if self._origin:
            return self._origin
        from .update_rules import DEFAULT_ORIGIN

        return os.environ.get("RENEST_ORIGIN") or DEFAULT_ORIGIN

    def _run_pack_upload(self, job: Job) -> Any:
        """Pack, then upload to the Renest drive under an approval given in the browser.

        [SECURITY-REVIEW] Order matters: (1) no sign-in, stop before reading a byte;
        (2) ask the service for an approval naming this nest and its size; (3) wait
        for the person to approve it in their own browser; (4) only then hold the
        upload-once token, in this frame's locals and the uploader it is handed to,
        pack + upload with it, and revoke it with ``/finish`` however the run ends.
        The machine's sign-in token is never used to upload, and neither token is
        written to the job, its log, its persisted state or an error.
        """
        from .approval import (
            ApprovalError,
            cancel_upload_approval,
            finish_upload,
            request_upload_approval,
        )
        from .login import machine_label

        signin = self._signin_token()
        if not signin:
            raise _JobFailed(_failure("approval", "NOT_SIGNED_IN", NOT_SIGNED_IN))
        try:
            preview = self.pack_dry_run(job.params)
        except ServeError as e:
            raise _JobFailed(_failure("P1", "UNKNOWN", e.human)) from None
        name = job.params.get("name")
        name = name.strip() if isinstance(name, str) and name.strip() else preview["default_name"]
        size = int(preview.get("size_estimate_bytes") or 0)

        origin = self._api_origin()
        client = self._http_client_fn()
        upload_token: str | None = None
        approval_id: str | None = None
        outcome = "failed"
        try:
            try:
                approval = request_upload_approval(
                    client, origin, signin, nest_name=name, size_bytes=size,
                    machine_label=machine_label())
            except ApprovalError as e:
                # Before anything was read for the upload: a refused plan or a full
                # drive ends here, with the service's own sentence and ways forward.
                raise _JobFailed(_approval_refusal("approval", e)) from None
            approval_id = approval.approval_id
            job.stage = "approval"
            job.approval = {
                "user_code": approval.user_code,
                "verify_url": approval.verify_url,
                "expires_at": datetime.fromtimestamp(
                    time.time() + approval.expires_in, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            self._on_event(job, {"type": "stage_start", "stage": "approval",
                                 "desc": "Waiting for you to approve this upload in your browser"})
            self._persist(job)

            upload_token = self._await_approval(job, client, origin, signin, approval)
            job.approval = None
            job.stage = "P1"
            self._on_event(job, {"type": "stage_end", "stage": "approval",
                                 "desc": "Upload approved in your browser"})
            self._persist(job)

            if self._uploader_cls is not None:
                uploader_cls = self._uploader_cls
            else:
                from .hosted import HostedUploader as uploader_cls

            checking = {"said": False}

            def say(message: str) -> None:
                text = str(message)
                # The drive's own check runs after the bytes are up; on screen that read
                # as "Uploading" for minutes (real-stack acceptance, 2026-10-19). The first
                # word from that phase moves the stage on.
                if not checking["said"] and (text.startswith("Still being checked")
                                             or text.startswith("Hosted storage has it")):
                    checking["said"] = True
                    self._on_event(job, {"type": "stage_start", "stage": "P4",
                                         "desc": "Checking with the drive"})
                    # The upload is over: its last speed must not ride along under
                    # "Checking with the drive".
                    self._on_event(job, {"type": "progress", "stage": "P4", "percent": 100.0,
                                         "bytes_done": job.progress.get("bytes_total", 0),
                                         "bytes_total": job.progress.get("bytes_total", 0),
                                         "speed_mbps": 0.0})
                self._on_event(job, {"type": "info", "stage": "P4" if checking["said"] else "P3",
                                     "human": text})

            uploader = uploader_cls(
                origin, upload_token, nest_name=name, client=client, log=say, notice=say,
                challenges=False, check_name=False, upload_once=True,
            )
            report = self._pack_once(job, uploader=uploader)
            landed = getattr(uploader, "result", None)
            uploader = None  # it holds the upload-once token; let it go with the run
            ok = getattr(report, "ok", False) and int(getattr(report, "exit_code", 1)) == 0
            if job.cancel_requested.is_set():
                outcome = "cancelled"
            elif ok and landed is not None and getattr(landed, "nest_id", None):
                outcome = "succeeded"
                nest_id = str(landed.nest_id)
                base = _console_base(approval.verify_url)
                job.drive = {
                    "nest_id": nest_id,
                    "nest_version_id": getattr(landed, "nest_version_id", None),
                    "version_no": getattr(landed, "version_no", None),
                    "nest_name": getattr(landed, "nest_name", None) or name,
                    "console_url": (f"{base}/nests/{urllib.parse.quote(nest_id, safe='')}"
                                    if base else None),
                }
                # Ruled 2026-10-19: once the drive has **checked** this nest, let go of the
                # staging it left here (its manifest folder and the blobs no other nest in
                # that folder references). The model files are hard links, so until this
                # happens deleting an original frees nothing. Only on "committed": a nest
                # the drive has not finished checking keeps its local copy.
                if getattr(landed, "status", None) == "committed":
                    from .staging import release_local_staging

                    mp = getattr(report, "manifest_path", "") or ""
                    if mp:
                        # What the person may now clear themselves: read before the
                        # staging goes, from the manifest the drive just checked.
                        cleanable = _cleanable_files(mp, job.params.get("comfyui_dir")
                                                     or job.params.get("target"))
                        job.local_copy = release_local_staging(mp)
                        job.local_copy["cleanable_files"] = cleanable
                        # Earlier saves still pending keep their copies: say how many.
                        with self._lock:
                            job.local_copy["pending_earlier"] = sum(
                                1 for r in self._load_registry() if r.get("verdict") == "pending")
                        self._on_event(job, {"type": "info", "stage": "P4", "human": (
                            "The drive has checked this nest; the copy kept beside ComfyUI "
                            "was removed so your disk is yours again."
                            if job.local_copy.get("released") else
                            "The drive has checked this nest; the copy beside ComfyUI "
                            "was left as it is.")})
            elif ok:
                # A pack that says ok without the drive naming where it landed is not
                # a nest anyone can find; never call it saved.
                raise _JobFailed(_failure(
                    "P3", "UNKNOWN",
                    "The nest was packed, but your Renest drive did not confirm where it "
                    "landed. Check the drive before packing again."))
            elif (int(getattr(report, "exit_code", 1)) == int(ExitCode.S2_UNKNOWN)
                  and landed is not None and getattr(landed, "nest_id", None)
                  and getattr(landed, "status", None) == "verifying"):
                # Every byte is up; the drive just did not finish checking within the
                # engine's wait. The job did what it could, so it ends ``succeeded`` with
                # ``verdict: pending`` on the result (a reader of ``state`` must not call
                # it a failure), the staging stays until a later save sees it checked, and
                # the panel says so in its own words -- never the command-line sentence
                # with exit codes and `renest list` (real-stack acceptance, 2026-10-19).
                outcome = "succeeded"
                nest_id = str(landed.nest_id)
                base = _console_base(approval.verify_url)
                job.drive = {
                    "nest_id": nest_id,
                    "nest_version_id": getattr(landed, "nest_version_id", None),
                    "version_no": getattr(landed, "version_no", None),
                    "nest_name": getattr(landed, "nest_name", None) or name,
                    "console_url": (f"{base}/nests/{urllib.parse.quote(nest_id, safe='')}"
                                    if base else None),
                    "verdict": "pending",
                }
                report.ok = True
                report.exit_code = int(ExitCode.OK)
                report.findings = [f for f in (getattr(report, "findings", None) or [])
                                   if "not confirmed yet" not in str(f)]
                self._on_event(job, {"type": "info", "stage": "P4", "human": (
                    "Uploaded — your Renest drive is still checking it. It shows as "
                    "verified in your drive once the check finishes. Do not upload it "
                    "again.")})
            elif (landed is not None and getattr(landed, "status", None) in ("failed", "blocked")
                  and not ok):
                # The drive checked it and said no. Its own reason, in the panel's words;
                # the command-line sentence (`renest list …`, "pack and send again") stays
                # off the screen. Nothing usable was kept on the drive, so the staging
                # here is worth nothing either: let it go now (ruled 2026-10-19: release after the drive confirms).
                status = str(landed.status)
                mp = getattr(report, "manifest_path", "") or ""
                if mp:
                    from .staging import release_local_staging

                    job.local_copy = release_local_staging(mp)
                raise _JobFailed(_failure(
                    "P4", "DRIVE_REJECTED",
                    "Your Renest drive checked this nest and did not accept it"
                    + (" (a file failed its check)." if status == "failed"
                       else " (stopped by a safety rule).")
                    + " Nothing usable was kept there. Press \"Nest this run\" again to "
                      "pack and save it afresh; if it happens twice, write to support."))
            return report
        except _JobCancelled:
            outcome = "cancelled"
            raise
        finally:
            if upload_token is not None and approval_id is not None:
                finish_upload(client, origin, upload_token, approval_id, outcome)
            elif approval_id is not None and signin:
                # Cancelled or failed while the approval was still open: withdraw it, so a
                # token approved a moment too late is revoked by the service, not left to
                # its hard cap. The sign-in token is used here only to withdraw.
                cancel_upload_approval(client, origin, signin, approval_id)
            upload_token = None
            signin = None
            with contextlib.suppress(Exception):
                client.close()

    def _await_approval(self, job: Job, client: Any, origin: str, signin: str,
                        approval: Any) -> str:
        """Poll until the person approves or denies, the request expires, or the job
        is cancelled. Returns the upload-once token; everything else ends the job."""
        from .approval import ApprovalError, poll_upload_approval

        def fail(human: str, error_class: str = "UPLOAD_NOT_APPROVED") -> _JobFailed:
            return _JobFailed(_failure("approval", error_class, human))

        deadline = time.monotonic() + approval.expires_in + APPROVAL_DEADLINE_GRACE_S
        gap = min(max(approval.interval, self._approval_min_interval), APPROVAL_MAX_INTERVAL_S)
        while True:
            # The caller withdraws the approval on the way out (see its finally).
            try:
                got = _poll_until_answered(
                    job, lambda: poll_upload_approval(client, origin, signin, approval.approval_id),
                    interval=gap, deadline=deadline,
                    on_slow=lambda: self._on_event(job, {"type": "warning", "stage": "approval",
                                                         "human": _SLOW_NETWORK_NOTE}))
            except ApprovalError as e:
                raise _JobFailed(_approval_refusal("approval", e)) from None
            status = str(got.get("status") or "")
            if status == "approved":
                token = got.get("upload_token")
                if isinstance(token, str) and token:
                    return token
                raise fail("The upload was approved, but the approval could not be collected. "
                           "Press \"Nest this run\" again to ask once more.")
            if status == "denied":
                raise fail("The upload was denied in the browser. Nothing was uploaded.")
            if status == "expired" or time.monotonic() > deadline:
                raise fail("Nobody approved the upload in time, so nothing was uploaded. "
                           "Press \"Nest this run\" again to ask once more.")
            if status in ("consumed", "finished"):
                raise fail("This approval was already used. Press \"Nest this run\" again to "
                           "ask once more.")
            if status not in ("", "pending"):
                raise fail(f"The approval ended in a state this version does not know "
                           f"({status[:40]}). Nothing was uploaded.")

    def _pack_once(self, job: Job, uploader: Any = None) -> Any:
        body = job.params
        spec, workflow = self._resolve_spec(body)
        # ``out`` = the local folder the nest lands in (as the CLI ``--out``); left
        # empty, ``default_out_dir`` puts it beside the environment, never in temp.
        # ``dest`` is the old name, kept for compatibility only -- it collides with
        # the CLI ``--dest``, which means "which cloud to upload to".
        dest = body.get("out") or body.get("dest") or str(default_out_dir(body["target"]))
        emitter = EventEmitter(json_mode=False, sink=self._make_sink(job))
        extra: dict[str, Any] = {"uploader": uploader} if uploader is not None else {}
        return self._pack_fn(
            body["target"],
            spec,
            dest,
            no_fingerprint=bool(body.get("no_fingerprint", False)),
            workflow=workflow,
            workflow_ui=_workflow_ui(body),
            # The name typed in the panel, so the restored app's Workflows sidebar
            # shows it instead of "renest-workflow".
            workflow_name=body.get("name") if isinstance(body.get("name"), str) else None,
            emitter=emitter,
            # Explicit, not inherited (decided 2026-09-06): the panel path always
            # pins vendor-only versions to direct addresses. A pod that just ran
            # a workflow has network by definition, and a nest sealed from the
            # panel must never be the one that cannot be rebuilt.
            pin_wheels=True,
            # Whatever the confirm page's preview already read, so this pack does
            # not read the same weights all over again.
            hash_cache=self._read_record_for(body["target"]),
            # Format 2.15: every nest saved through this service carries the id of the
            # installation it came from, minted here on first use.
            environment_id=environment_id_for(body.get("comfyui_dir") or body["target"],
                                              create=True),
            # The plugin runs inside the application process and reports the real
            # shape of the environment; the engine never guesses. comfyui_dir = the
            # folder holding the nodes and models; program_dir = ComfyUI's own program
            # tree when the desktop build keeps it apart; env_python = the running
            # interpreter, read live when there is no lock file.
            **_env_hints(body),
            **extra,
        )

    def _run_restore(self, job: Job) -> Any:
        body = job.params
        return self._restore_fn(body, self._make_sink(job))

    # -- take back into the running ComfyUI (the panel's "Take back", 2026-10-19) ------
    def _takeback_session_get(self, session_id: str) -> dict | None:
        with self._lock:
            sess = self._takeback.get(session_id)
            if sess is None:
                return None
            if time.monotonic() > sess["expires_at"]:
                self._takeback.pop(session_id, None)
                return None
            return sess

    def close_takeback_session(self, session_id: str, outcome: str = "succeeded") -> bool:
        """Revoke the session's token at the service and forget it. Idempotent."""
        with self._lock:
            sess = self._takeback.pop(session_id, None)
        if sess is None:
            return False
        from .approval import finish_takeback

        try:
            finish_takeback(sess["client"], sess["origin"], sess["token"], sess["approval_id"],
                            outcome)
        finally:
            sess["token"] = None
            with contextlib.suppress(Exception):
                sess["client"].close()
        return True

    def _run_takeback_session(self, job: Job) -> dict:
        """Ask for a take-back approval, wait for it in the browser, then list this
        account's nests. The token the service hands over stays in this process's
        memory, keyed by a session id the panel uses for the take-back itself.

        [SECURITY-REVIEW] Same order as an upload: (1) no sign-in, stop; (2) ask for
        the approval; (3) wait; (4) only then hold the take-back-once token, in the
        session table, and never in the job.
        """
        from .approval import (
            ApprovalError,
            cancel_takeback_approval,
            list_takeback_nests,
            poll_takeback_approval,
            retry_transient,
            request_takeback_approval,
        )
        from .login import machine_label

        signin = self._signin_token()
        if not signin:
            raise _JobFailed(_failure("approval", "NOT_SIGNED_IN", NOT_SIGNED_IN))
        origin = self._api_origin()
        client = self._http_client_fn()
        approval_id: str | None = None
        token: str | None = None
        try:
            try:
                approval = request_takeback_approval(client, origin, signin,
                                                     machine_label=machine_label())
            except ApprovalError as e:
                raise _JobFailed(_approval_refusal("approval", e)) from None
            approval_id = approval.approval_id
            job.stage = "approval"
            job.approval = {
                "user_code": approval.user_code,
                "verify_url": approval.verify_url,
                "expires_at": datetime.fromtimestamp(
                    time.time() + approval.expires_in, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            self._on_event(job, {"type": "stage_start", "stage": "approval",
                                 "desc": "Waiting for you to approve this take-back in your browser"})
            self._persist(job)

            deadline = time.monotonic() + approval.expires_in + APPROVAL_DEADLINE_GRACE_S
            gap = min(max(approval.interval, self._approval_min_interval), APPROVAL_MAX_INTERVAL_S)
            while True:
                try:
                    got = _poll_until_answered(
                        job, lambda: poll_takeback_approval(client, origin, signin, approval_id),
                        interval=gap, deadline=deadline,
                        on_slow=lambda: self._on_event(job, {"type": "warning", "stage": "approval",
                                                             "human": _SLOW_NETWORK_NOTE}))
                except ApprovalError as e:
                    raise _JobFailed(_approval_refusal("approval", e)) from None
                status = str(got.get("status") or "")
                if status == "approved":
                    tok = got.get("takeback_token")
                    if isinstance(tok, str) and tok:
                        token = tok
                        break
                    raise _JobFailed(_failure("approval", "UPLOAD_NOT_APPROVED",
                                              "The take-back was approved, but the approval could "
                                              "not be collected. Press \"Take back\" again."))
                if status == "denied":
                    raise _JobFailed(_failure("approval", "UPLOAD_NOT_APPROVED",
                                              "The take-back was denied in the browser. Nothing "
                                              "was listed or fetched."))
                if status == "expired" or time.monotonic() > deadline:
                    raise _JobFailed(_failure("approval", "UPLOAD_NOT_APPROVED",
                                              "Nobody approved the take-back in time. Press "
                                              "\"Take back\" again to ask once more."))
                if status not in ("", "pending"):
                    raise _JobFailed(_failure("approval", "UPLOAD_NOT_APPROVED",
                                              f"The approval ended in a state this version does "
                                              f"not know ({status[:40]})."))
            job.approval = None
            job.stage = "list"
            self._on_event(job, {"type": "stage_end", "stage": "approval",
                                 "desc": "Take-back approved in your browser"})
            try:
                # A dropped packet here used to burn the approval the person just gave:
                # a few tries first, and only a failure that outlasts them revokes.
                nests = retry_transient(lambda: list_takeback_nests(client, origin, token),
                                        sleep=self._cancellable_sleep(job))
            except ApprovalError as e:
                # The token was handed over and will not be used: the finally below
                # switches it off (it is still held, so ``token`` is not None there).
                raise _JobFailed(_approval_refusal("list", e)) from None
            self._sweep_pending_staging(job, nests)
            session_id = "tb_" + secrets.token_hex(12)
            with self._lock:
                self._takeback[session_id] = {
                    "token": token, "approval_id": approval_id, "origin": origin,
                    "client": client, "expires_at": time.monotonic() + TAKEBACK_SESSION_TTL_S,
                }
            client = None  # now owned by the session
            token = None
            return {"session_id": session_id, "nests": nests}
        finally:
            if client is not None:
                if token is not None:
                    # Collected but never handed to a session -- listing failed for good,
                    # or the job was cancelled during a retry wait: switch the one-time
                    # token off now rather than leaving it alive until its hard cap
                    # ([SECURITY-REVIEW] every exit path that still holds it ends here).
                    from .approval import finish_takeback

                    with contextlib.suppress(Exception):
                        finish_takeback(client, origin, token, approval_id, "failed")
                    token = None
                elif approval_id is not None and signin:
                    # Cancelled or failed before the token was collected: withdraw the
                    # approval; a no-op on a finished one.
                    cancel_takeback_approval(client, origin, signin, approval_id)
                with contextlib.suppress(Exception):
                    client.close()
            signin = None

    def _sweep_pending_staging(self, job: Job, nests: list[dict]) -> None:
        """Let go of the staging of saves whose check outran the wait, now that the drive
        lists their version as checked. The take-back listing shows only checked head
        versions, so a pending row whose version appears there is confirmed. The machine
        sign-in token has no route to ask a version's status, which is why this waits for
        the next take-back rather than happening at once."""
        checked = {str(n.get("head_version_id")) for n in nests if n.get("head_version_id")}
        if not checked:
            return
        from .staging import release_local_staging

        with self._lock:
            rows = self._load_registry()
        freed = 0
        keep: list[dict] = []
        for row in rows:
            vid = str(row.get("nest_version_id") or "")
            if row.get("verdict") == "pending" and vid in checked and row.get("path"):
                done = release_local_staging(Path(row["path"]) / "manifest.json")
                if done.get("released"):
                    freed += 1
                    continue  # its row goes with it: nothing is left on this machine
            keep.append(row)
        if freed:
            with self._lock:
                self._save_registry(keep)
            self._on_event(job, {"type": "info", "stage": "list", "human": (
                f"The drive has checked {freed} earlier save(s); their copies kept beside "
                f"ComfyUI were removed so your disk is yours again.")})

    def _run_takeback(self, job: Job) -> dict:
        """Compare one saved nest with this machine, and (mode ``fetch``) bring the
        missing files back. Facts only, never overwrites, never installs."""
        from .approval import ApprovalError, retry_transient, takeback_links
        from .restore import _parse_grant, _resolve_grant
        from .takeback import compare, fetch, live_environment, write_report

        body = job.params
        sess = self._takeback_session_get(str(body.get("session_id") or ""))
        if sess is None:
            raise _JobFailed(_failure("P1", "TAKEBACK_SESSION_GONE",
                                      "This take-back session has ended. Press \"Take back\" "
                                      "again to approve a new one."))
        target = body.get("target")
        if not target:
            raise _JobFailed(_failure("P1", "UNKNOWN", "Missing target"))
        comfyui_dir = Path(str(body.get("comfyui_dir") or target)).resolve()
        mode = "fetch" if body.get("mode") == "fetch" else "compare"
        try:
            payload = retry_transient(
                lambda: takeback_links(sess["client"], sess["origin"], sess["token"],
                                       str(body.get("nest_version_id") or "")),
                sleep=self._cancellable_sleep(job))
        except ApprovalError as e:
            raise _JobFailed(_approval_refusal("P1", e)) from None
        try:
            grant = _parse_grant(payload)
            manifest, blobmap = _resolve_grant(grant, sess["client"])
        except Exception as e:  # a NestFailure carries its own sentence
            raise _JobFailed(_failure("P1", "UNKNOWN", str(getattr(e, "human", "") or e)
                                      or "Could not read the saved nest.")) from None
        # [SECURITY-REVIEW] The restore's own landing gate, before a byte is read: a nest
        # may have come from a hand-off, and a files[] entry pointing into site-packages,
        # venv, bin or a custom node's own code would be run, not read, once placed.
        from .takeback import refusal_for

        refused = [(str(f.get("path")), refusal_for(f)) for f in manifest.get("files") or []
                   if isinstance(f, dict) and refusal_for(f) is not None]
        if refused:
            shown = "; ".join(why for _p, why in refused[:3])
            raise _JobFailed(_failure(
                "P1", "NEST_REFUSED",
                f"This nest lists {len(refused)} file(s) that would be placed where files get "
                f"run as code, not read as data, so nothing was fetched: {shown}"))
        self._on_event(job, {"type": "stage_start", "stage": "P1",
                             "desc": "Comparing the saved workflow with this machine"})
        lock_text = _small_blob_text(sess["client"], blobmap,
                                     ((manifest.get("python_lock") or {}).get("lockfile") or {}))
        live = live_environment(comfyui_dir, body.get("env_python"), body.get("node_owners"))
        report = compare(manifest, comfyui_dir, live, hash_cache=self._read_record_for(target),
                         lock_text=lock_text, blobmap=blobmap)
        outcome: dict | None = None
        if mode == "fetch":
            self._on_event(job, {"type": "stage_start", "stage": "P2",
                                 "desc": "Bringing the missing files back and checking them"})

            def say(message: str) -> None:
                self._on_event(job, {"type": "info", "stage": "P2", "human": str(message)})

            outcome = fetch(manifest, blobmap, comfyui_dir, report, client=sess["client"],
                            say=say, emitter=EventEmitter(json_mode=False,
                                                          sink=self._make_sink(job)))
        where = write_report(comfyui_dir, report, outcome)
        return {"mode": mode, "nest_id": manifest.get("id"), "report": report.to_dict(),
                "outcome": outcome, "report_path": str(where)}


def _cleanable_files(manifest_path: str, comfyui_dir: str | None) -> list[dict]:
    """The model files a checked nest carried, as absolute paths on this machine, for the
    success page to list. Only files under the ComfyUI folder; never the nest's own
    recipe, licence texts or escape hatch. Says nothing about other workflows (that needs
    the drive, which a finished upload token can no longer ask)."""
    import json as _json
    from pathlib import PurePosixPath

    try:
        manifest = _json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    app = Path(comfyui_dir).resolve() if comfyui_dir else None
    root = app.parent if app else None
    out: list[dict] = []
    for f in manifest.get("files") or []:
        if not isinstance(f, dict) or str(f.get("root") or "env") != "env":
            continue
        if f.get("kind") in ("workflow", "license_text", "input_asset") or not root:
            continue
        rel = str(f.get("path") or "")
        if not rel or rel.startswith("/") or ".." in PurePosixPath(rel).parts:
            continue
        dest = (root / PurePosixPath(rel)).resolve()
        try:
            dest.relative_to(app)
        except ValueError:
            continue
        if not dest.is_file():
            continue
        blob = f.get("blob") or {}
        out.append({"path": str(dest), "size_bytes": int(blob.get("size_bytes") or 0),
                    "sha256": blob.get("sha256")})
    return out


def _small_blob_text(client: Any, blobmap: dict[str, list[str]], blob: dict,
                     limit: int = 4 * 1024 * 1024) -> str | None:
    """The text of one small blob (the lock), fetched through its signed link and
    checked against its sha256. ``None`` when it is not handed out or does not match."""
    import hashlib

    sha = str(blob.get("sha256") or "")
    urls = blobmap.get(sha) or []
    if not sha or not urls or int(blob.get("size_bytes") or 0) > limit:
        return None
    try:
        r = client.get(urls[0])
    except Exception:
        return None
    if r.status_code != 200 or hashlib.sha256(r.content).hexdigest() != sha:
        return None
    try:
        return r.content.decode("utf-8")
    except UnicodeDecodeError:
        return None


# --------------------------------------------------------------------------
# default (production) executors — call the real modules read-only
# --------------------------------------------------------------------------
def _default_signin_token() -> str | None:
    """This machine's Renest sign-in (``renest login``) or a personal access token."""
    from .config import resolve_token

    return resolve_token()


def _default_http_client() -> Any:
    import httpx

    return httpx.Client()


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
            if path not in (f"{API_PREFIX}/pack", f"{API_PREFIX}/restore",
                            f"{API_PREFIX}/takeback/sessions", f"{API_PREFIX}/takeback"):
                self._send(404, {"error": "Unknown path"})
                return
            body = self._read_json()
            if body is None:
                self._send(400, {"error": "Request body is not a valid JSON object"})
                return
            if path == f"{API_PREFIX}/pack":
                self._handle_pack(body)
            elif path == f"{API_PREFIX}/takeback/sessions":
                if not self.app.signed_in():
                    self._send(409, {"error": NOT_SIGNED_IN, "error_class": "NOT_SIGNED_IN"})
                    return
                self._enqueue("takeback_session", {})
            elif path == f"{API_PREFIX}/takeback":
                if not body.get("target") or not body.get("session_id") \
                        or not body.get("nest_version_id"):
                    self._send(400, {"error": "Missing target, session_id or nest_version_id"})
                    return
                self._enqueue("takeback", body)
            else:
                self._handle_restore(body)

        def do_DELETE(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            if not self._require_auth():
                return
            ts = _TAKEBACK_SESSION_RE.match(path)
            if ts:
                closed = self.app.close_takeback_session(ts.group(1))
                self._send(200, {"closed": closed})
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
            if body.get("upload") is True and not self.app.signed_in():
                # Said before anything is queued or read: nothing can be uploaded
                # until the machine is signed in from its own terminal.
                self._send(409, {"error": NOT_SIGNED_IN, "error_class": "NOT_SIGNED_IN"})
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


def is_loopback_host(host: str) -> bool:
    """Whether binding to ``host`` keeps this service off the network.

    [SECURITY-REVIEW] the only thing standing between these endpoints and the
    internet is that they are not reachable from it. On a rented GPU pod a
    routable bind hands strangers the pack/restore job API.
    """
    import ipaddress

    # "" is not loopback: an empty bind address means every interface.
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


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
    host = getattr(args, "host", DEFAULT_HOST)
    if not is_loopback_host(host):
        print(
            f"✗ renest serve will not listen on {host}. It answers pack and restore "
            f"requests, so it stays on this machine only ({DEFAULT_HOST}). Drop the "
            f"--host option and run: renest serve",
            file=sys.stderr,
        )
        return int(ExitCode.USAGE)
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
        server = make_server(app, host, port)
    except OSError as e:
        print(f"✗ Cannot listen on port {port}: {e}. Pick another one with --port.", file=sys.stderr)
        app.stop()
        return int(ExitCode.USAGE)
    # Report the address actually bound, not the one asked for: with --port 0 the
    # requested port is 0 and the real one is only known after the bind.
    bound_host, bound_port = server.server_address[0], server.server_address[1]
    print(
        f"renest serve is listening on http://{bound_host}:{bound_port}{API_PREFIX} "
        f"(loopback only)",
        file=sys.stderr,
    )
    print(token_notice(token_path), file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Interrupted; stopping serve", file=sys.stderr)
    finally:
        server.shutdown()
        server.server_close()
        app.stop()
    return int(ExitCode.OK)
