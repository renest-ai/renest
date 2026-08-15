"""Direct-upload client for the hosted drive.

The upload stage behind `renest pack --dest hosted`: announce the manifest and
blob list, PUT each part to its presigned URL, then commit. The bytes never
travel through the server.

Commit leaves the version in status ``verifying``, which covers object existence
and the blocklist only — the server does **not** recompute sha256. Byte-level
verification happens on the restore side; ``verifying`` never means "the server
checked your bytes".

[SECURITY-REVIEW] The token comes from env or config and goes out only in the
``Authorization`` header of control-plane calls; presigned storage URLs carry
**no** token, it never lands in a log or an exception, and no bucket key is held.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from xml.sax.saxutils import escape as _xml_escape
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from .errors import ExitCode
from .pack import PackError
from .update_rules import DEFAULT_ORIGIN
from .uplink import UPLINK_CONTRACT_VERSION, machine_facts, scrub_events

__all__ = ["DEFAULT_ORIGIN", "MAX_PARALLEL_PUT", "HostedResult", "HostedUploader",
           "byte_challenge_answers",
           "manifest_blobs",
           "storage_exit_code",
           "store_put", "upload_blob_multipart"]

#: Timeout for control-plane calls: short connect, ordinary read.
_API_TIMEOUT = httpx.Timeout(connect=15.0, read=60.0, write=60.0, pool=15.0)
#: Cap on parallel part uploads — **one shared constant for both upload paths**;
#: do not split it again. Split once, it left hosted at 1 and bring-your-own-
#: storage at 4, so the hosted path ran four times slower than the free one.
#: The 4 is an **engineering** bound, not a **commercial** one: more concurrency
#: makes the "one part failed, abort the whole upload?" path hard to keep
#: correct. The floor keeps it from being **slower** than the tools people
#: already use; gating threads behind a paid tier was **overturned**.
#: Uploads only — never weaken restore-side concurrency to drive conversion.
MAX_PARALLEL_PUT = 4

#: Timeout for storage calls (presigned part PUTs): a 64 MiB part takes a long
#: time on a slow uplink, so read and write get a wide budget.
_STORE_TIMEOUT = httpx.Timeout(connect=15.0, read=600.0, write=600.0, pool=15.0)


@dataclass
class HostedResult:
    """Result of one hosted upload (shown when pack finishes; holds no credential)."""

    upload_session_id: str | None = None
    nest_id: str | None = None
    nest_version_id: str | None = None
    #: The version number humans read (1, 2, 3 ...). An older server does not put
    #: it in the commit response, in which case this is None and the closing
    #: message drops the number instead of inventing one.
    version_no: int | None = None
    #: The nest name actually used this time. For a new nest that is the name we
    #: sent; when adding a version to an existing nest we do not know it (None).
    nest_name: str | None = None
    #: True = this run created a new nest; False = it landed in an existing one.
    created_new_nest: bool = False
    status: str | None = None
    uploaded_blobs: int = 0
    skipped_blobs: int = 0
    uploaded_bytes: int = 0
    # Byte spot check: the server picks a few byte ranges of a local file, and a
    # correct answer means the file does not have to be uploaded.
    # verified_blobs = files skipped this run by answering; verified_bytes = the
    # bytes that therefore never went on the wire.
    verified_blobs: int = 0
    verified_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "upload_session_id": self.upload_session_id,
            "nest_id": self.nest_id,
            "nest_version_id": self.nest_version_id,
            "version_no": self.version_no,
            "nest_name": self.nest_name,
            "created_new_nest": self.created_new_nest,
            "status": self.status,
            "uploaded_blobs": self.uploaded_blobs,
            "skipped_blobs": self.skipped_blobs,
            "uploaded_bytes": self.uploaded_bytes,
            "verified_blobs": self.verified_blobs,
            "verified_bytes": self.verified_bytes,
        }


def manifest_blobs(manifest: dict) -> dict[str, int]:
    """Walk the manifest for every {sha256, size_bytes} pair.

    This is public because the bring-your-own-storage path (:mod:`renest.byos`)
    must enumerate blobs by the **same rule**. With two separate walks, a nest
    published by one side would look like it was missing bytes to the other."""
    wanted: dict[str, int] = {}

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            if set(o) >= {"sha256", "size_bytes"}:
                wanted[o["sha256"]] = o["size_bytes"]
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(manifest)
    return wanted


#: Strip control characters from server-controlled text before it reaches the
#: terminal, so a hostile response cannot inject ANSI/OSC escape sequences.
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _clean(text: object) -> str:
    return _CTRL_RE.sub("", str(text))


#: 401/403 means **this key will not do** (permission, signature, or an expired
#: presigned URL) — never "storage is down". Keep the two apart: in the exit-code
#: table CREDENTIAL_EXPIRED is retryable=**no** and STORAGE_UNAVAILABLE is
#: **yes**, so misfiling one makes automatic retries hammer a permission error
#: that can never succeed while the user is told to try again later.
def storage_exit_code(status: int) -> int:
    if status in (401, 403):
        return int(ExitCode.S1_CREDENTIAL_EXPIRED)
    return int(ExitCode.S1_STORAGE_UNAVAILABLE)


def _error_message(resp: httpx.Response) -> str:
    """Turn the server's error envelope {"error": {code, message}} into plain
    words; if it cannot be parsed, fall back to the status code."""
    try:
        err = resp.json().get("error", {})
        code, message = _clean(err.get("code", "")), _clean(err.get("message", ""))
        if message:
            return f"{message}({code})" if code else message
        if code:
            return code
    except (json.JSONDecodeError, ValueError, AttributeError):
        pass
    return f"HTTP {resp.status_code}"


class HostedUploader:
    """Uploader with the shape ``(blobs_dir, manifest) -> {sha256: size}``, which
    can be injected into pack().

    Parts are uploaded in order (the first version aims at being correct rather
    than fast; resuming an interrupted session over GET /uploads/{id} is separate
    work). ``client`` is an injection seam for tests (httpx.MockTransport);
    in production the client is created here.
    """

    def __init__(
        self,
        origin: str,
        token: str,
        *,
        nest_id: str | None = None,
        nest_name: str | None = None,
        client: httpx.Client | None = None,
        log: Callable[[str], None] | None = None,
        report: bool = True,
    ) -> None:
        self._origin = origin.rstrip("/")
        self._token = token
        self._nest_id = nest_id
        self._nest_name = nest_name
        self._client = client
        self._log = log or (lambda _msg: None)
        self._report_enabled = report
        # After one failed report, this process stops trying (same rule as the
        # restore side).
        self._report_dead = False
        # The machine survey only needs to be collected once.
        self._machine: dict | None = None
        self.result = HostedResult()

    # -- Progress reporting (POST /runs/report-pack, same token as elsewhere) --
    def _report(self, client: httpx.Client, events: list[dict]) -> None:
        """Reporting never blocks and never affects the upload: every exception is
        swallowed, and a failure silently turns reporting off.

        **[SECURITY-REVIEW - outbound allowlist]** Events pass through the
        ``uplink.scrub_events`` gate first, so free text (raw error strings, file
        names) stays on this machine; each batch carries a machine survey (which
        card, which driver version, how much disk is left). The reasoning and the
        full allowlist are in the header of ``uplink.py``.
        """
        if not self._report_enabled or self._report_dead or not self.result.upload_session_id:
            return
        kept = scrub_events(events)
        if not kept:
            return
        if self._machine is None:
            try:
                self._machine = machine_facts()
            except Exception:  # noqa: BLE001 - if it cannot be read, leave it empty
                self._machine = {}
        try:
            resp = client.post(
                f"{self._origin}/api/v1/runs/report-pack",
                json={
                    "upload_session_id": self.result.upload_session_id,
                    # The contract version rides along with every batch so the
                    # server can tell old clients apart. Before this existed the
                    # frozen contract had no version at all, so nothing forced a
                    # version bump when a field was added.
                    "uplink_version": UPLINK_CONTRACT_VERSION,
                    "events": kept,
                    "machine": self._machine,
                },
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=httpx.Timeout(3.0),
            )
            if resp.status_code >= 400:
                self._report_dead = True
        except Exception:  # noqa: BLE001 - reporting is a side path, swallow all
            self._report_dead = True

    # -- Control plane (carries the token) --------------------------------
    def _api(self, client: httpx.Client, method: str, path: str, *, json_body: dict) -> httpx.Response:
        resp = client.request(
            method,
            f"{self._origin}/api/v1{path}",
            json=json_body,
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=_API_TIMEOUT,
        )
        if resp.status_code == 401:
            raise PackError(
                "Your sign-in token is invalid or expired. Generate a new one in the web "
                "console, then put it in RENEST_TOKEN or in auth.token in your config "
                "(you can revoke the old one on the web).",
                exit_code=int(ExitCode.CONFIG_OR_CREDENTIAL),
            )
        if resp.status_code == 404 and self._nest_id and path == "/uploads":
            # The nest the user named does not exist. Do not just relay a bare
            # 404 from the server; spell out both ways forward.
            raise PackError(
                f"Your drive has no nest with id {self._nest_id} — it may have been "
                "deleted, or the id was mistyped. Run `renest nests` to see what's "
                "there, or pack again with --new-nest to start a fresh nest.",
                exit_code=int(ExitCode.USAGE),
            )
        if resp.status_code >= 400:
            raise PackError(f"Hosted storage refused this upload: {_error_message(resp)}")
        return resp

    def _warn_if_name_taken(self, client: httpx.Client, name: str) -> None:
        """Check for a name clash before creating a nest. **Warn only, never
        block**: the server allows duplicate names on purpose (two folders with
        the same name in a drive are fine too), but two nests with the same name
        cannot be told apart by eye, and nine times out of ten the user meant
        "add a version to that nest" rather than "start another one". A failed
        lookup stays silent — the warning is a bonus, and must never stand
        between the user and a finished upload."""
        try:
            resp = client.get(
                f"{self._origin}/api/v1/nests",
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=_API_TIMEOUT,
            )
            if resp.status_code != 200:
                return
            same = [n for n in resp.json() if n.get("name") == name]
        except (httpx.HTTPError, ValueError, AttributeError, TypeError):
            return
        if same:
            existing = same[0]
            self._log(
                f"⚠ Your drive already has a nest called “{name}” "
                f"(id {existing.get('id')}, {existing.get('version_count', '?')} version(s)). "
                "This pack starts a separate new nest with the same name. To add a new "
                f"version to the existing one instead, cancel and pack again with "
                f"--nest-id {existing.get('id')}"
            )

    # -- Storage plane (presigned URLs, no token) --------------------------
    # Both actions live at module level (end of this file) because **the
    # bring-your-own-storage path reuses exactly this code**: who signed the
    # presigned URL does not matter, the protocol is the same.
    # See :func:`upload_blob_multipart`.
    @staticmethod
    def _store_put(client: httpx.Client, url: str, content: bytes) -> httpx.Response:
        return store_put(client, url, content, resumable=True)

    def _upload_blob(self, client: httpx.Client, path: Path, plan: dict) -> int:
        return upload_blob_multipart(client, path, plan, max_parallel=MAX_PARALLEL_PUT)

    # -- Answering a byte spot check. Skipping an upload is **the server's
    # -- verdict**; here we only answer the question, we never ask about the
    # -- contents of the shared pool.
    def _prove_by_spot_check(self, client: httpx.Client, local: Path, sha: str) -> bool:
        """Run one blob through "ask for a challenge, read the local ranges,
        answer"; True means the server judged it passed.

        Failure never raises: anything unexpected returns False and the caller
        falls back to a full upload. This is a bandwidth saving, never a step the
        upload depends on.

        [SECURITY-REVIEW] Trust boundary: the range list comes from the server,
        so its shape is validated before use (range count, each length, no
        negative offsets) — a compromised control plane must not be able to make
        this client read unbounded data. The path read is always derived from a
        **sha declared in this run**, never from one supplied by the server.
        """
        if not local.is_file():
            return False
        try:
            resp = client.post(
                f"{self._origin}/api/v1/possession/challenges",
                json={"blob_sha256": sha},
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=_API_TIMEOUT,
            )
        except httpx.HTTPError:
            return False
        if resp.status_code != 201:
            return False
        try:
            chal = resp.json()
            answers = byte_challenge_answers(local, chal["nonce"], chal["regions"])
        except (KeyError, ValueError, TypeError, OSError):
            return False
        if answers is None:
            return False
        try:
            verdict = client.post(
                f"{self._origin}/api/v1/possession/challenges/{chal['challenge_id']}/response",
                json={"responses": answers},
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=_API_TIMEOUT,
            )
        except httpx.HTTPError:
            return False
        return verdict.status_code == 200 and verdict.json().get("result") == "passed"

    # -- Main flow ---------------------------------------------------------
    def __call__(self, blobs_dir: Path, manifest: dict) -> dict[str, int]:
        client = self._client or httpx.Client()
        try:
            return self._run(client, blobs_dir, manifest)
        except PackError as e:
            # Failures get reported too, but what goes out is the **exit code**,
            # never ``e.human``: that sentence is free text and can carry
            # addresses and paths. One number from a frozen vocabulary
            # classifies the failure just as well and takes nothing with it.
            self._report(
                client, [{"type": "error", "stage": "P3", "exit_code": e.exit_code}]
            )
            raise
        finally:
            if self._client is None:
                client.close()

    def _run(self, client: httpx.Client, blobs_dir: Path, manifest: dict) -> dict[str, int]:
        t0 = time.monotonic()
        wanted = manifest_blobs(manifest)
        # The manifest bytes: byte-for-byte the same serialization pack wrote to
        # disk, which is what content addressing is anchored to.
        manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
        manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()

        try:
            body: dict[str, Any] = {
                "manifest_sha256": manifest_sha,
                "blobs": [{"sha256": h, "size_bytes": s} for h, s in sorted(wanted.items())],
                # Declare that this client can answer byte spot checks. A correct
                # answer skips the upload; failing to answer always falls back to
                # uploading the file in full.
                "challenges": True,
            }
            if self._nest_id:
                body["nest_id"] = self._nest_id
            else:
                bucket = self._api(client, "POST", "/buckets/provision", json_body={}).json()
                name = self._nest_name or str(manifest.get("name") or "") or f"nest-{manifest['id']}"
                self._warn_if_name_taken(client, name)
                body["new_nest"] = {"name": name, "bucket_id": bucket["id"]}
                self.result.nest_name = name
                self.result.created_new_nest = True

            session = self._api(client, "POST", "/uploads", json_body=body).json()
            self.result.upload_session_id = session["upload_session_id"]
            self.result.nest_id = session["nest_id"]
            plans = session["blobs"]

            # Byte spot check: the server names a few byte ranges, we answer from
            # the local copy, and a correct answer skips the upload. If anything
            # cannot be proven, announce once more without challenges so the whole
            # run falls back to full uploads — a saving must never block a finish.
            spot_checks = [p for p in plans
                           if p.get("action") == "challenge_available" and p["sha256"] in wanted]
            if spot_checks:
                self._log(
                    f"Hosted storage wants a spot check on {len(spot_checks)} file(s) "
                    "it already stores — answering from your local copies…"
                )
                unproven = 0
                for plan in spot_checks:
                    sha = str(plan["sha256"])
                    local = blobs_dir / sha[:2] / sha
                    if self._prove_by_spot_check(client, local, sha):
                        self.result.verified_blobs += 1
                        self.result.verified_bytes += wanted[sha]
                        self._log(f"  {sha[:12]} verified — stays home, nothing to upload")
                    else:
                        unproven += 1
                # The saving rides in fields of stage_done, not in an event type
                # of its own: the event vocabulary is a frozen contract and the
                # server allowlist silently drops anything outside it — a
                # home-made "challenge" type never reached the database at all.
                self._report(client, [{
                    "type": "stage_done", "stage": "P3", "duration_s": 0.0,
                    "detail": "possession spot check",
                    "challenge_verified": self.result.verified_blobs,
                    "challenge_unproven": unproven,
                    "challenge_bytes_saved": self.result.verified_bytes,
                }])
                if unproven:
                    self._log(
                        f"Spot check not passed for {unproven} file(s) — "
                        "those will travel in full instead."
                    )
                    retry = dict(body)
                    retry["challenges"] = False
                    retry.pop("new_nest", None)
                    # The nest already exists, do not create a second one.
                    retry["nest_id"] = self.result.nest_id
                    session = self._api(client, "POST", "/uploads", json_body=retry).json()
                    self.result.upload_session_id = session["upload_session_id"]
                    plans = session["blobs"]
                    # After re-announcing, the new session's verdicts are what
                    # count (whatever passed comes back as already_owned).
                elif self.result.verified_bytes:
                    self._log(
                        f"Spot check passed — {self.result.verified_bytes} bytes "
                        "stay home (zero bytes uploaded for those files)."
                    )

            sizes: dict[str, int] = {}
            need = [p for p in plans if p["action"] == "upload"]
            self._log(
                f"Hosted storage says: {len(need)} to upload, "
                f"{len(plans) - len(need)} already there"
            )
            self._report(client, [{
                "type": "stage_start", "stage": "P3",
                "blobs_total": len(plans), "blobs_to_upload": len(need),
                "declared_bytes": sum(wanted.values()),
            }])
            for i, plan in enumerate(plans, 1):
                sha = str(plan["sha256"])
                # [SECURITY-REVIEW] Trust boundary: every sha in the plan must be
                # one this run declared. Without this check a compromised control
                # plane could name an arbitrary string, build a local path from
                # it, and have this tool read and send out an undeclared file.
                if sha not in wanted:
                    raise PackError(
                        f"The server's plan lists a blob we never declared: {_clean(sha)[:12]}. "
                        "That is outside the trust boundary; refusing to continue.",
                        exit_code=int(ExitCode.S1_STORAGE_UNAVAILABLE),
                    )
                local = blobs_dir / sha[:2] / sha
                if plan["action"] == "upload":
                    self._log(f"[{i}/{len(plans)}] Sending {sha[:12]} ({wanted[sha]} bytes)…")
                    tb = time.monotonic()
                    sent = self._upload_blob(client, local, plan)
                    sizes[sha] = sent
                    self.result.uploaded_blobs += 1
                    self.result.uploaded_bytes += sent
                    secs = max(time.monotonic() - tb, 1e-6)
                    self._report(client, [{
                        "type": "progress", "stage": "P3",
                        "blob": sha[:12], "bytes": sent,
                        "seconds": round(secs, 3),
                        "mbps": round(sent / secs / 1e6, 3),
                    }])
                else:
                    # already_owned: the bytes are already stored, so nothing is
                    # uploaded; the local size is still what we reconcile against.
                    sizes[sha] = local.stat().st_size if local.exists() else wanted[sha]
                    self.result.skipped_blobs += 1

            plan_m = session.get("manifest_plan")
            if not plan_m:
                raise PackError(
                    "The server sent no upload plan for the manifest, so this cannot "
                    "be handed over."
                )
            self._store_put(client, plan_m["put_url"], manifest_bytes)

            commit = self._api(
                client,
                "POST",
                f"/uploads/{self.result.upload_session_id}/commit",
                json_body={"manifest_key": plan_m["manifest_key"], "manifest_id": manifest["id"]},
            ).json()
            self.result.nest_version_id = commit["nest_version_id"]
            self.result.status = commit["status"]
            # The version number is the one humans say out loud (1, 2, 3 ...).
            # An older server does not return it, in which case we say no number
            # at all — never a database primary key dressed up as a version.
            vno = commit.get("version_no")
            self.result.version_no = int(vno) if isinstance(vno, int) else None
            human_version = f"version {vno} of" if vno else "a new version of"
            self._log(
                f"Hosted storage has it: {human_version} nest {self.result.nest_id} "
                "(the server is checking it now)"
            )
            self._report(client, [{
                "type": "result", "stage": "P3", "ok": True,
                "nest_id": self.result.nest_id,
                "nest_version_id": self.result.nest_version_id,
                "uploaded_blobs": self.result.uploaded_blobs,
                "skipped_blobs": self.result.skipped_blobs,
                "uploaded_bytes": self.result.uploaded_bytes,
                "seconds": round(time.monotonic() - t0, 3),
            }])
            return sizes
        except httpx.HTTPError as e:
            raise PackError(
                f"Cannot reach hosted storage at {self._origin}: {type(e).__name__}",
                exit_code=int(ExitCode.S1_NETWORK_INTERRUPTED),
            ) from e


# --------------------------------------------------------------------------
# The pure-function half of answering a byte spot check, so test vectors can be
# checked on their own.
# --------------------------------------------------------------------------
#: Shape limits on the range list. Trust boundary: even with a compromised
#: control plane, the client reads at most 16 MiB.
_MAX_CHALLENGE_REGIONS = 16
_MAX_REGION_LENGTH = 1024 * 1024


def byte_challenge_answers(
    path: Path, nonce_hex: str, regions: list[dict]
) -> list[str] | None:
    """Compute the answer for each range as the protocol defines it:
    hex(sha256(nonce || be64(offset) || the bytes of that range)).

    If the range list has the wrong shape (too many ranges, a range too long, a
    negative offset, a nonce that is not hex) this returns None, which refuses to
    answer and falls back to a full upload. If the local file is shorter than a
    range, the short read is used as it is: the answer will be wrong and the
    server will judge it failed, which is the correct outcome of "you do not have
    this file" and not something the client should paper over.
    """
    if not isinstance(regions, list) or not 1 <= len(regions) <= _MAX_CHALLENGE_REGIONS:
        return None
    try:
        nonce = bytes.fromhex(str(nonce_hex))
    except ValueError:
        return None
    if not 1 <= len(nonce) <= 64:
        return None
    answers: list[str] = []
    with path.open("rb") as f:
        for r in regions:
            offset, length = int(r["offset"]), int(r["length"])
            if offset < 0 or not 1 <= length <= _MAX_REGION_LENGTH:
                return None
            f.seek(offset)
            chunk = f.read(length)
            answers.append(
                hashlib.sha256(nonce + offset.to_bytes(8, "big") + chunk).hexdigest()
            )
    return answers


# --------------------------------------------------------------------------
# Storage-plane actions that do not care who signed the URL. The hosted path and
# the bring-your-own-storage path share these: there is no second uploader.
# --------------------------------------------------------------------------
def store_put(
    client: httpx.Client,
    url: str,
    content: bytes,
    *,
    resumable: bool = False,
    explain: Callable[[int, str], str] | None = None,
) -> httpx.Response:
    """PUT one chunk of bytes to a presigned URL. A presigned URL carries its own
    authorization, so **no Authorization header may be added**.

    ``resumable`` changes only the wording, never the behaviour: on the hosted
    path the upload session lives on the server, so running again continues where
    it stopped. The bring-your-own-storage path has no server-side session and
    running again only skips what is already in the bucket, so those users must
    not be promised that it "picks up where it stopped".
    """
    try:
        resp = client.put(url, content=content, timeout=_STORE_TIMEOUT)
    except httpx.HTTPError as e:
        tail = (
            " The session is kept on the server, so running this again picks up where it "
            "stopped."
            if resumable
            else " Run this again and it skips whatever already made it into the bucket."
        )
        raise PackError(
            f"Upload interrupted: {type(e).__name__}.{tail}",
            exit_code=int(ExitCode.S1_NETWORK_INTERRUPTED),
        ) from e
    if resp.status_code >= 300:
        raise PackError(
            f"Storage refused a part: HTTP {resp.status_code}"
            + (" — that's a permissions/signature problem, not an outage."
               if resp.status_code in (401, 403) else ""),
            exit_code=storage_exit_code(resp.status_code),
        )
    return resp


def upload_blob_multipart(
    client: httpx.Client, path: Path, plan: dict, *, max_parallel: int = 1
) -> int:
    """Upload one blob following its multi-part plan; returns the bytes actually
    sent.

    **It does not care who signed the URLs**: ``plan["multipart"]``
    (``part_size`` / ``part_urls`` / ``complete_url``) is accepted whether the
    server signed it or this machine signed it itself (`byos.py`). That is the
    whole point of having a single uploader instead of two.

    ``max_parallel`` caps the number of parts in flight (default 1). Two rules
    the concurrent path must keep:
    - **each worker opens the file and seeks on its own**; a shared handle plus
      concurrent reads silently reads the wrong offset, which is the worst bug
      available here — "passed verification but bytes are missing";
    - **any failed part abandons the rest immediately** and re-raises, so the
      caller can abort the multi-part upload (`byos.S3Uploader` does; otherwise
      leftover parts keep costing storage).
    """
    mp = plan["multipart"]
    part_size = int(mp["part_size"])
    entries = sorted(mp["part_urls"], key=lambda e: int(e["part"]))
    total = path.stat().st_size
    explain = mp.get("explain")
    resumable = bool(mp.get("resumable"))

    def send(entry: dict) -> tuple[int, str, int]:
        n = int(entry["part"])
        offset = (n - 1) * part_size
        with path.open("rb") as f:          # every worker gets its own handle
            f.seek(offset)
            chunk = f.read(part_size)
        if not chunk:
            raise PackError(
                f"Local blob {plan['sha256'][:12]} is shorter than the upload plan "
                f"(part {n} starts past the end of the file). Was the pack directory "
                "changed while we were uploading?",
                exit_code=int(ExitCode.S2_HASH_MISMATCH),
            )
        resp = store_put(client, entry["url"], chunk, resumable=resumable, explain=explain)
        etag = resp.headers.get("ETag", "")
        if not etag:
            raise PackError(
                "Storage returned no ETag for a part, so the finish request cannot be "
                "built. Stopping instead of guessing.",
                exit_code=int(ExitCode.S1_STORAGE_UNAVAILABLE),
            )
        return n, etag, len(chunk)

    parts: list[tuple[int, str]] = []
    sent = 0
    if max_parallel <= 1 or len(entries) <= 1:
        for entry in entries:
            n, etag, size = send(entry)
            parts.append((n, etag))
            sent += size
    else:
        with ThreadPoolExecutor(max_workers=min(max_parallel, len(entries))) as pool:
            futures = {pool.submit(send, e): e for e in entries}
            try:
                for fut in as_completed(futures):
                    n, etag, size = fut.result()
                    parts.append((n, etag))
                    sent += size
            except BaseException:
                # Once a part fails, stop pouring bytes into a multi-part
                # upload that is about to be thrown away.
                for f in futures:
                    f.cancel()
                raise
        parts.sort()                        # the completion XML needs parts in order

    if sent != total:
        # Parts adding up to the wrong length means the plan and the local file
        # disagree; do not finalise half a file.
        raise PackError(
            f"Sent {sent} bytes but the local blob is {total} — the upload plan and the "
            "file on disk disagree. Nothing was finalised.",
            exit_code=int(ExitCode.S2_HASH_MISMATCH),
        )
    parts_xml = "".join(
        f"<Part><PartNumber>{n}</PartNumber><ETag>{_xml_escape(etag)}</ETag></Part>"
        for n, etag in parts
    )
    body = f"<CompleteMultipartUpload>{parts_xml}</CompleteMultipartUpload>"
    try:
        resp = client.post(
            mp["complete_url"],
            content=body.encode("utf-8"),
            headers={"Content-Type": "application/xml"},
            timeout=_STORE_TIMEOUT,
        )
    except httpx.HTTPError as e:
        raise PackError(
            f"Finish request interrupted: {type(e).__name__}",
            exit_code=int(ExitCode.S1_NETWORK_INTERRUPTED),
        ) from e
    # A trap in how S3 behaves: the completion call can return HTTP 200 while
    # carrying an <Error> in the body, and every compatible implementation does
    # the same. Looking only at the status code reads a failure as a success.
    if resp.status_code >= 300 or "<Error>" in resp.text:
        raise PackError(
            f"Could not finish the multi-part upload: HTTP {resp.status_code}",
            exit_code=storage_exit_code(resp.status_code),
        )
    return sent
