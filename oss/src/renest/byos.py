"""Bring-your-own-storage upload: push a packed nest into **your own bucket**
(``renest pack --dest s3``), no account here.

Same protocol as the hosted route with a different signer — :mod:`renest.s3sig`
signs locally, :func:`renest.hosted.upload_blob_multipart` moves the bytes.
Blobs first, ``nests/<id>/manifest.json`` last, so a failed run leaves bytes
nobody can start from rather than a readable half-nest. A dead multi-part upload
is aborted at once: leftover parts cost money and never appear in a listing.

[SECURITY-REVIEW] the bucket key signs inside this process and **never leaves
this machine**: not logged, not in the manifest, not on the wire (requests
carry a presigned URL, no Authorization header). Logged URLs go through
:func:`renest.s3sig.redact_url` — a presigned query is itself a pass until it
expires. Object keys are derived locally from content addressing.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .config import BucketKey
from .errors import ExitCode
from .hosted import (
    MAX_PARALLEL_PUT,
    manifest_blobs,
    storage_exit_code,
    store_put,
    upload_blob_multipart,
)
from .pack import PackError
from .s3sig import S3SigError, presign, redact_url

__all__ = [
    "MAX_PARALLEL_PUT",
    "BucketSelfTest",
    "ByosResult",
    "S3Uploader",
    "SelfTestResult",
    "SelfTestStep",
    "blob_key",
    "explain_storage_failure",
    "manifest_key",
]

#: Part size, the same value the server side uses: 64 MiB for every part except
#: a smaller last one. That one choice satisfies both AWS ("at least 5 MiB") and
#: Cloudflare R2 ("every part except the last must be the same size"), so no
#: per-provider branching is needed anywhere.
PART_SIZE = 64 * 1024 * 1024

# The upload concurrency limit is imported from hosted: both legs must share one
# value. A private copy in each place drifts.

#: How long a presigned URL stays valid. Each blob is signed right before it is
#: sent, so no nest ever shares one very long-lived signature, and six hours is
#: plenty for one large blob on a slow uplink.
DEFAULT_EXPIRES_IN = 6 * 3600

#: Pull UploadId out of the CreateMultipartUpload XML. A regular expression
#: rather than an XML parser: only one field is needed, and S3-compatible
#: services disagree about namespace prefixes. No match = fail, never guess.
_UPLOAD_ID_RE = re.compile(r"<UploadId>([^<]+)</UploadId>")

_STORE_TIMEOUT = httpx.Timeout(connect=15.0, read=600.0, write=600.0, pool=15.0)


def blob_key(sha256: str) -> str:
    """The object key for a blob. **It must be spelled exactly the way the
    restore side spells it**: `restore.py` builds ``{blob_base}/{h[:2]}/{h}``
    and `restore.sh` builds ``$BLOB_BASE/${h:0:2}/$h``, where ``BLOB_BASE``
    defaults to ``<bucket root>/blobs/sha256``. Changing it here means
    publishing the nest somewhere the rebuilding side cannot find it.
    """
    if len(sha256) < 3:
        raise PackError(f"Not a usable sha256: {sha256!r}", exit_code=int(ExitCode.USAGE))
    return f"blobs/sha256/{sha256[:2]}/{sha256}"


def manifest_key(nest_id: str) -> str:
    """The object key for the manifest. The standalone restore script fetches
    ``manifest.json`` from ``NEST_URL=<bucket root>/nests/<id>``."""
    return f"nests/{nest_id}/manifest.json"


@dataclass
class ByosResult:
    """The outcome of one upload to your own bucket. It holds no credentials,
    so it is safe to print or write to disk."""

    uploaded_blobs: int = 0
    skipped_blobs: int = 0
    uploaded_bytes: int = 0
    manifest_published: bool = False
    aborted_uploads: int = 0
    #: Blobs whose leftover parts we also failed to abort. The meter is still
    #: running on those, so the user has to be told.
    abort_failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "uploaded_blobs": self.uploaded_blobs,
            "skipped_blobs": self.skipped_blobs,
            "uploaded_bytes": self.uploaded_bytes,
            "manifest_published": self.manifest_published,
            "aborted_uploads": self.aborted_uploads,
            "abort_failures": list(self.abort_failures),
        }


class S3Uploader:
    """``(blobs_dir, manifest) -> {sha256: size}``. Same signature as
    `HostedUploader`, so it can be injected into pack()."""

    def __init__(
        self,
        bucket_key: BucketKey,
        *,
        client: httpx.Client | None = None,
        log: Callable[[str], None] | None = None,
        expires_in: int = DEFAULT_EXPIRES_IN,
        part_size: int = PART_SIZE,
    ) -> None:
        self._key = bucket_key
        self._client = client
        self._log = log or (lambda _msg: None)
        self._expires_in = expires_in
        self._part_size = part_size
        self.result = ByosResult()

        if not bucket_key.bucket:
            raise PackError(
                "No bucket name. Set it under [storage] in your config file, or in "
                "RENEST_S3_BUCKET.",
                exit_code=int(ExitCode.CONFIG_OR_CREDENTIAL),
            )
        self._region = bucket_key.effective_region()
        if not self._region:
            raise PackError(
                "We can't tell which region to sign for. A wrong region fails as "
                "“signature does not match”, which is nearly impossible to work out from "
                "the error, so we ask up front instead of guessing. Set region under "
                "[storage] (Cloudflare R2 uses the literal value auto).",
                exit_code=int(ExitCode.CONFIG_OR_CREDENTIAL),
            )
        self._addressing = bucket_key.effective_addressing()

    # -- signing ----------------------------------------------------------
    def _sign(self, method: str, key: str, query: dict[str, str] | None = None) -> str:
        try:
            return presign(
                method=method,
                key=key,
                endpoint=self._key.endpoint or "",
                bucket=self._key.bucket or "",
                region=self._region or "",
                access_key=self._key.access_key,
                secret_key=self._key.secret_key,
                addressing=self._addressing,
                expires=self._expires_in,
                query=query,
            )
        except S3SigError as e:
            # A signing precondition that does not hold is a configuration
            # problem, not a network one — do not send the user off to debug
            # their connection.
            raise PackError(str(e), exit_code=int(ExitCode.CONFIG_OR_CREDENTIAL)) from e

    def _explain(self, status: int, body: str) -> str:
        """Status code plus error body -> something the user can act on. The
        wording lives in :func:`explain_storage_failure`; this only passes in
        the region actually in force, because a wrong region is by far the
        most common cause of "the signature is not right"."""
        return explain_storage_failure(status, body, self._region or "", writing=True)

    # -- one blob ---------------------------------------------------------
    def _already_there(self, client: httpx.Client, key: str, size: int) -> bool:
        """Does the bucket already hold this key at this size? That check is what
        "resume" means without a server.

        A failed probe returns False and we upload anyway: re-sending a blob
        that is already there wastes bandwidth, while wrongly concluding "it is
        already there" loses bytes.
        """
        try:
            resp = client.head(self._sign("HEAD", key), timeout=_STORE_TIMEOUT)
        except httpx.HTTPError:
            return False
        if resp.status_code != 200:
            return False
        remote = resp.headers.get("Content-Length")
        if remote is None:
            return False
        try:
            return int(remote) == size
        except ValueError:
            return False

    def _abort_multipart(self, client: httpx.Client, key: str, upload_id: str, sha: str) -> None:
        """Abort the leftover parts. **Without this they keep costing money and
        stay invisible** — they do not appear in an object listing.

        A failed abort does not replace the real failure we report, but it is
        recorded and surfaced anyway: the meter is running on those bytes.
        """
        try:
            resp = client.delete(
                self._sign("DELETE", key, {"uploadId": upload_id}), timeout=_STORE_TIMEOUT
            )
            ok = resp.status_code < 300 or resp.status_code == 404
        except httpx.HTTPError:
            ok = False
        if ok:
            self.result.aborted_uploads += 1
            return
        self.result.abort_failures.append(sha)
        self._log(
            f"⚠ Could not clean up the half-finished upload for {sha[:12]}. Parts already "
            f"sent may keep costing you until your bucket's lifecycle rule removes them. "
            f"Look for “incomplete multipart uploads” in your provider's console."
        )

    def _create_multipart(self, client: httpx.Client, key: str) -> str:
        url = self._sign("POST", key, {"uploads": ""})
        try:
            resp = client.post(url, content=b"", timeout=_STORE_TIMEOUT)
        except httpx.HTTPError as e:
            raise PackError(
                f"Could not start a multi-part upload: {type(e).__name__}",
                exit_code=int(ExitCode.S1_NETWORK_INTERRUPTED),
            ) from e
        if resp.status_code >= 300:
            raise PackError(
                self._explain(resp.status_code, resp.text)
                + f"  (while starting a multi-part upload to {redact_url(url)})",
                exit_code=storage_exit_code(resp.status_code),
            )
        found = _UPLOAD_ID_RE.search(resp.text)
        if not found:
            raise PackError(
                "Your bucket started a multi-part upload but didn't say which one "
                "(no UploadId in the reply), so we can't finish it. Stopping instead of "
                "guessing. This bucket may not be S3-compatible enough — try "
                "`renest doctor --storage`.",
                exit_code=int(ExitCode.S1_STORAGE_UNAVAILABLE),
            )
        return found.group(1)

    def _upload_one(
        self, client: httpx.Client, path: Path, sha: str, size: int, key: str | None = None
    ) -> int:
        """Send one blob; return how many bytes went out (0 when skipped).

        ``key`` is only ever passed by the bucket self-test, which puts its
        test object under ``.renest-selftest/`` instead of the real ``blobs/``
        prefix — but it **must go down the same upload path**, or the self-test
        would not be testing the real thing.
        """
        key = key or blob_key(sha)
        if self._already_there(client, key, size):
            self.result.skipped_blobs += 1
            return 0

        if size <= self._part_size:
            # One part is enough, so a single PUT. Opening a multi-part upload
            # would only add two round trips, and on some S3-compatible
            # services small multi-part uploads run into the minimum part size.
            store_put(client, self._sign("PUT", key), path.read_bytes(), explain=self._explain)
            self.result.uploaded_blobs += 1
            self.result.uploaded_bytes += size
            return size

        upload_id = self._create_multipart(client, key)
        n_parts = max(1, -(-size // self._part_size))  # ceil
        plan = {
            "sha256": sha,
            "multipart": {
                "part_size": self._part_size,
                "part_urls": [
                    {
                        "part": n,
                        "url": self._sign(
                            "PUT", key, {"partNumber": str(n), "uploadId": upload_id}
                        ),
                    }
                    for n in range(1, n_parts + 1)
                ],
                "complete_url": self._sign("POST", key, {"uploadId": upload_id}),
                # There is no server-side session to resume here, so the
                # wording must never promise "we'll pick up where we left
                # off" (see hosted.store_put).
                "resumable": False,
                # When a part PUT fails, turn the status code into something
                # the user can act on instead of echoing back "HTTP 403".
                "explain": self._explain,
            },
        }
        try:
            sent = upload_blob_multipart(client, path, plan, max_parallel=MAX_PARALLEL_PUT)
        except PackError:
            self._abort_multipart(client, key, upload_id, sha)
            raise
        self.result.uploaded_blobs += 1
        self.result.uploaded_bytes += sent
        return sent

    # -- main flow --------------------------------------------------------
    def __call__(self, blobs_dir: Path, manifest: dict) -> dict[str, int]:
        client = self._client or httpx.Client()
        try:
            return self._run(client, blobs_dir, manifest)
        finally:
            if self._client is None:
                client.close()

    def _run(self, client: httpx.Client, blobs_dir: Path, manifest: dict) -> dict[str, int]:
        wanted = manifest_blobs(manifest)
        nest_id = str(manifest.get("id") or "")
        if not nest_id:
            raise PackError(
                "This manifest has no id, so we don't know where to publish it.",
                exit_code=int(ExitCode.S1_MANIFEST_UNSUPPORTED),
            )

        self._log(
            f"Uploading {len(wanted)} files to your own bucket "
            f"({self._key.provider or 'other'} · {self._key.bucket})"
        )

        sizes: dict[str, int] = {}
        for sha, size in sorted(wanted.items()):
            path = blobs_dir / sha[:2] / sha
            if not path.is_file():
                # Missing bytes must not be published. Fail here and now,
                # rather than send one blob short and publish the manifest.
                raise PackError(
                    f"The pack directory is missing the bytes for {sha[:12]}. Nothing was "
                    "published, so the bucket still has no manifest for this nest.",
                    exit_code=int(ExitCode.S2_HASH_MISMATCH),
                )
            self._upload_one(client, path, sha, int(size))
            sizes[sha] = int(size)

        # ---- Atomic publish: reaching this line means not one blob failed (a
        #      failure would have raised), and only now does the manifest land
        #      in the bucket. Its presence means the nest is complete and
        #      fetchable.
        manifest_bytes = _manifest_json_bytes(manifest)
        store_put(client, self._sign("PUT", manifest_key(nest_id)), manifest_bytes)
        self.result.manifest_published = True
        self._log(
            f"Done. {self.result.uploaded_blobs} uploaded, {self.result.skipped_blobs} "
            f"already there. The nest is now readable at nests/{nest_id}/manifest.json"
        )
        return sizes


def _manifest_json_bytes(manifest: dict) -> bytes:
    """The manifest bytes as they land in the bucket. **Byte-for-byte the same
    serialization pack writes to disk**, which is the anchor of content
    addressing, and the same one `hosted.py::_run` uses — if the two ever
    disagree, the manifest's sha256 stops matching."""
    return json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")


# --------------------------------------------------------------------------
# Bucket self-test — how we can say "S3-compatible storage" instead of shipping
# a list of blessed providers.
# --------------------------------------------------------------------------
#: Part size for the self-test. 5 MiB is AWS's hard minimum for any part except
#: the last, so a smaller value would not prove a real multi-part upload.
_SELFTEST_PART = 5 * 1024 * 1024
#: Two full parts plus a small final one = 3 parts, the shape a large file
#: takes. Three is the smallest count that exercises both "every part except
#: the last must be equal in size" (R2) and "the last may be smaller" (AWS).
_SELFTEST_SIZE = 2 * _SELFTEST_PART + 1024

#: The machine-readable error code inside an S3-style error body. It separates
#: "the signature is wrong" from "this key lacks permission": both are HTTP 403,
#: but the fix differs completely (region versus key permissions).
_S3_ERROR_CODE_RE = re.compile(r"<Code>([A-Za-z]+)</Code>")


@dataclass
class SelfTestStep:
    name: str
    ok: bool
    detail: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "ok": self.ok, "detail": self.detail}


@dataclass
class SelfTestResult:
    """The outcome of one bucket self-test. Safe to print: it holds no
    credentials."""

    ok: bool
    steps: list[SelfTestStep] = field(default_factory=list)
    effective: dict = field(default_factory=dict)
    #: The object key left behind when cleanup failed. The user must be told:
    #: we never leave rubbish in their bucket quietly.
    leftover_key: str | None = None

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "steps": [s.to_dict() for s in self.steps],
            "effective": dict(self.effective),
            "leftover_key": self.leftover_key,
        }


def _s3_error_code(text: str) -> str:
    found = _S3_ERROR_CODE_RE.search(text or "")
    return found.group(1) if found else ""


def explain_storage_failure(status: int, body: str, region: str, *, writing: bool) -> str:
    """HTTP status plus error body -> **something the user can act on**.

    Raw codes such as ``SignatureDoesNotMatch`` are deliberately not echoed
    back: they are unreadable to a user, while what they actually mean ("the
    region you configured is wrong") can simply be said out loud.
    """
    code = _s3_error_code(body)
    if code in ("SignatureDoesNotMatch", "AuthorizationHeaderMalformed", "InvalidRequest"):
        return (
            f"The signature was rejected. The usual cause is the wrong region — this run "
            f"signed for “{region}”. Cloudflare R2 wants the literal value “auto”; AWS and "
            f"Backblaze B2 want their real region name. Fix region under [storage]."
        )
    if code in ("NoSuchBucket",):
        return "That bucket does not exist at this endpoint. Check the bucket name and endpoint."
    if code in ("InvalidAccessKeyId",):
        return "This access key is not recognised by that endpoint. Check the key and endpoint."
    if status in (401, 403):
        what = "write to" if writing else "read from"
        return (
            f"The storage refused the request. This key is not allowed to {what} this "
            f"bucket — when you created it, tick read *and* write for this one bucket "
            f"(and, for multi-part uploads, the abort permission too)."
        )
    if status == 404:
        return (
            "The storage answered “not found”. Either the endpoint or bucket name is wrong, "
            "or this key is not allowed to see the bucket (some providers answer “not found” "
            "instead of “forbidden” in that case)."
        )
    if status == 501 or code == "NotImplemented":
        return (
            "This bucket does not support multi-part uploads the way S3 does, so large "
            "files cannot be sent to it. Renest needs an S3-compatible store that supports "
            "multi-part upload."
        )
    return f"The storage answered HTTP {status}{f' ({code})' if code else ''}."


class BucketSelfTest:
    """Run one real round trip against **the user's own bucket**: multi-part
    upload -> check it landed -> fetch it back and compare bytes -> clean up.

    It walks the real upload path rather than doing a HEAD, so a
    half-compatible bucket says no here instead of failing halfway through a
    60 GB upload. Cost: about 10 MiB each way, and the test object is deleted.
    """

    def __init__(
        self,
        bucket_key: BucketKey,
        *,
        client: httpx.Client | None = None,
        log: Callable[[str], None] | None = None,
        now_tag: str | None = None,
    ) -> None:
        self._uploader = S3Uploader(bucket_key, client=client, part_size=_SELFTEST_PART)
        self._key = bucket_key
        self._client = client
        self._log = log or (lambda _msg: None)
        # A random suffix in the object name: two people self-testing the same
        # bucket at the same time must not step on each other.
        tag = now_tag or secrets.token_hex(8)
        self._object_key = f".renest-selftest/{tag}.bin"

    def _sign(self, method: str, query: dict[str, str] | None = None) -> str:
        return self._uploader._sign(method, self._object_key, query)

    def run(self) -> SelfTestResult:
        client = self._client or httpx.Client()
        result = SelfTestResult(
            ok=False,
            effective={
                "provider": self._key.provider or "other",
                "endpoint": self._key.endpoint,
                "bucket": self._key.bucket,
                "region": self._key.effective_region(),
                "addressing": self._key.effective_addressing(),
                "test_object": self._object_key,
                "bytes_each_way": _SELFTEST_SIZE,
            },
        )
        payload = os.urandom(_SELFTEST_SIZE)
        want = hashlib.sha256(payload).hexdigest()
        uploaded = False
        try:
            uploaded = self._step_upload(client, result, payload)
            if uploaded:
                self._step_head(client, result)
                self._step_download(client, result, want)
            result.ok = all(s.ok for s in result.steps)
        finally:
            # Cleanup **runs whether the test passed or failed**: a self-test
            # must not leave rubbish in the user's bucket.
            if uploaded:
                self._step_cleanup(client, result)
            if self._client is None:
                client.close()
        return result

    # -- the individual steps ---------------------------------------------
    def _step_upload(self, client: httpx.Client, result: SelfTestResult, payload: bytes) -> bool:
        name = f"multi-part upload ({_SELFTEST_SIZE // _SELFTEST_PART + 1} parts)"
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "selftest.bin"
            src.write_bytes(payload)
            try:
                # This is the very path large files take: the same
                # _upload_one, not a second copy written for testing.
                self._uploader._upload_one(
                    client, src, hashlib.sha256(payload).hexdigest(), len(payload),
                    key=self._object_key,
                )
            except PackError as e:
                result.steps.append(SelfTestStep(name, False, e.human))
                return False
        result.steps.append(SelfTestStep(name, True, f"{len(payload)} bytes in 3 parts"))
        return True

    def _step_head(self, client: httpx.Client, result: SelfTestResult) -> None:
        name = "check it landed with the right size"
        try:
            resp = client.head(self._sign("HEAD"), timeout=_STORE_TIMEOUT)
        except httpx.HTTPError as e:
            result.steps.append(SelfTestStep(name, False, f"Could not reach the bucket: {type(e).__name__}"))
            return
        if resp.status_code != 200:
            result.steps.append(
                SelfTestStep(name, False, explain_storage_failure(
                    resp.status_code, resp.text, result.effective["region"] or "", writing=False))
            )
            return
        remote = resp.headers.get("Content-Length")
        if remote != str(_SELFTEST_SIZE):
            result.steps.append(SelfTestStep(
                name, False,
                f"The bucket reports {remote} bytes but we sent {_SELFTEST_SIZE}. "
                "The multi-part upload did not assemble correctly on this storage."))
            return
        result.steps.append(SelfTestStep(name, True, f"{remote} bytes"))

    def _step_download(self, client: httpx.Client, result: SelfTestResult, want: str) -> None:
        """Fetch it back and compare the bytes. This step also proves **the
        standalone restore script would work against this bucket**: that
        script pulls bytes with a single presigned GET, which is exactly what
        happens here."""
        name = "download it back with a signed link and compare every byte"
        try:
            resp = client.get(self._sign("GET"), timeout=_STORE_TIMEOUT)
        except httpx.HTTPError as e:
            result.steps.append(SelfTestStep(name, False, f"Could not reach the bucket: {type(e).__name__}"))
            return
        if resp.status_code != 200:
            result.steps.append(
                SelfTestStep(name, False, explain_storage_failure(
                    resp.status_code, resp.text, result.effective["region"] or "", writing=False))
            )
            return
        got = hashlib.sha256(resp.content).hexdigest()
        if got != want:
            result.steps.append(SelfTestStep(
                name, False,
                "What came back is not what we sent. This storage altered the bytes — "
                "Renest cannot guarantee byte-identical restores on it."))
            return
        result.steps.append(SelfTestStep(name, True, "byte-identical"))

    def _step_cleanup(self, client: httpx.Client, result: SelfTestResult) -> None:
        name = "clean up the test object"
        try:
            resp = client.delete(self._sign("DELETE"), timeout=_STORE_TIMEOUT)
            gone = resp.status_code < 300 or resp.status_code == 404
        except httpx.HTTPError:
            gone = False
        if not gone:
            result.leftover_key = self._object_key
            result.ok = False
            result.steps.append(SelfTestStep(
                name, False,
                f"Could not delete the test object. Remove it yourself: {self._object_key} "
                "(this key may be missing the delete permission)."))
            return
        result.steps.append(SelfTestStep(name, True, "removed"))
