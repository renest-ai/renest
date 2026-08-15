"""AWS SigV4 pre-signing, standard library only -- the signing floor for
bring-your-own-storage.

Hand-written rather than boto3: the CLI must stay installable with ``uv tool`` and
free of heavy dependencies, and only one action is ever needed. Pre-signing *is* this
project's credential posture -- the secret key stays on the machine that owns it, and
what leaves is a URL limited in time, object and action. The escape hatch cannot sign
for itself (no openssl in its tool list), so it only consumes URLs signed here.

[SECURITY-REVIEW] This module handles a secret. Three rules: the secret is only ever
a function argument -- never stored, written or logged; error text never carries the
secret or a whole signed URL, so run :func:`redact_url` before displaying one; and
``X-Amz-Expires`` is capped at 7 days, the protocol's own ceiling, refused up front
rather than handing back a URL guaranteed to 403.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import urllib.parse
from dataclasses import dataclass

__all__ = [
    "MAX_EXPIRES_SECONDS",
    "PROVIDER_DEFAULTS",
    "ProviderDefaults",
    "S3SigError",
    "canonical_object_path",
    "infer_region",
    "presign",
    "redact_url",
    "resolve_addressing",
]

#: Hard protocol ceiling for SigV4 query-string pre-signing: 7 days.
MAX_EXPIRES_SECONDS = 7 * 24 * 3600

_ALGORITHM = "AWS4-HMAC-SHA256"
_SERVICE = "s3"
#: The payload stays out of the signature: the body of a multipart PUT is tens
#: of MiB, and reading all of it into memory just to sha256 it is not an option.
_UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"


class S3SigError(Exception):
    """A precondition for signing is not met (no region, expires out of range,
    and so on). Callers map this to exit code 3."""


@dataclass(frozen=True)
class ProviderDefaults:
    """The three configuration values that differ between storage providers; the
    signing algorithm itself is identical for all of them.

    ``region=None`` means the user must state the region. A wrong region surfaces as
    ``SignatureDoesNotMatch``, which nobody diagnoses unaided, so refuse over guess.
    """

    region: str | None
    addressing: str  # "path" | "virtual"
    note: str


#: provider -> defaults. This only feeds default-value inference and the wording
#: of error messages; it never creates a branch in behaviour.
PROVIDER_DEFAULTS: dict[str, ProviderDefaults] = {
    # R2's credential scope uses the literal region "auto", not a geography.
    "r2": ProviderDefaults(region="auto", addressing="path", note="Cloudflare R2"),
    # On AWS the region is baked into the credential scope, so a wrong one fails
    # the signature outright. Addressing is virtual-hosted.
    "aws": ProviderDefaults(region=None, addressing="virtual", note="Amazon S3"),
    # B2's S3-compatible endpoints look like s3.<region>.backblazeb2.com, so the
    # region can be read back out of the endpoint.
    "b2": ProviderDefaults(region=None, addressing="virtual", note="Backblaze B2"),
    "other": ProviderDefaults(region=None, addressing="path", note="S3-compatible store"),
}


def infer_region(endpoint: str | None, provider: str | None) -> str | None:
    """Work the region out of the endpoint where possible, else None so the caller can
    refuse up front. Anything readable from the endpoint should never be typed by hand.

    - R2: the credential scope region is the literal ``auto``, unrelated to the host;
    - AWS: ``s3.us-east-1.amazonaws.com`` and bare ``s3.amazonaws.com`` -> the region
      in the host, or ``us-east-1`` for the legacy global endpoint;
    - B2: ``s3.us-west-004.backblazeb2.com`` -> ``us-west-004``;
    - anything else: do not guess -- a wrong guess is harder to track down than none.
    """
    if provider == "r2":
        return "auto"
    if not endpoint:
        return None
    host = urllib.parse.urlsplit(
        endpoint if "//" in endpoint else f"https://{endpoint}"
    ).netloc.lower()
    if not host:
        return None
    labels = host.split(".")
    if host.endswith("amazonaws.com"):
        # s3.<region>.amazonaws.com / s3-<region>.amazonaws.com / s3.amazonaws.com
        if labels[0].startswith("s3-"):
            return labels[0][3:] or None
        if len(labels) >= 4 and labels[0] == "s3":
            return labels[1]
        if labels[:2] == ["s3", "amazonaws"]:
            return "us-east-1"  # The legacy global endpoint implies us-east-1
        return None
    if host.endswith("backblazeb2.com") and len(labels) >= 4 and labels[0] == "s3":
        return labels[1]
    return None


def resolve_addressing(provider: str | None, addressing: str | None) -> str:
    """Decide the addressing style. An explicit value wins; ``auto`` or nothing
    falls back to the provider default."""
    if addressing and addressing != "auto":
        if addressing not in ("path", "virtual"):
            raise S3SigError(f"Unknown addressing style {addressing!r} (use path or virtual).")
        return addressing
    default = PROVIDER_DEFAULTS.get(provider or "other", PROVIDER_DEFAULTS["other"])
    return default.addressing


def _quote_path_segments(value: str) -> str:
    """URI-encode segment by segment, keeping ``/`` intact.

    S3's canonical URI encodes each segment on its own, a space becomes ``%20`` not
    ``+``, and ``~`` must stay literal -- which is what ``quote`` does by default.
    """
    return urllib.parse.quote(value, safe="/~")


def canonical_object_path(bucket: str, key: str, addressing: str) -> str:
    """The canonical URI, i.e. the path part that goes into the signature.

    - ``path``: ``/<bucket>/<key>``, used when the endpoint is an account-level
      hostname, as with R2;
    - ``virtual``: ``/<key>``, used when the bucket lives in the hostname, as
      with AWS and B2.
    """
    key = key.lstrip("/")
    if not key:
        raise S3SigError("Object key is empty — nothing to sign.")
    if addressing == "path":
        if not bucket:
            raise S3SigError("Path-style addressing needs a bucket name.")
        return "/" + _quote_path_segments(f"{bucket}/{key}")
    return "/" + _quote_path_segments(key)


def _canonical_query(params: dict[str, str]) -> str:
    """The canonical query string: every pair encoded, then sorted by the *encoded* key.

    Sorting on the encoded key is what S3 specifies. Today's keys are plain ASCII so
    both orderings agree, but add one key with a special character and sorting the
    other way would sign silently wrong.
    """
    encoded = [
        (urllib.parse.quote(k, safe=""), urllib.parse.quote(v, safe=""))
        for k, v in params.items()
    ]
    return "&".join(f"{k}={v}" for k, v in sorted(encoded))


def _signing_key(secret_key: str, datestamp: str, region: str) -> bytes:
    def step(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k = step(f"AWS4{secret_key}".encode(), datestamp)
    k = step(k, region)
    k = step(k, _SERVICE)
    return step(k, "aws4_request")


def presign(
    *,
    method: str,
    key: str,
    endpoint: str,
    bucket: str,
    region: str,
    access_key: str,
    secret_key: str,
    addressing: str = "path",
    expires: int = 3600,
    query: dict[str, str] | None = None,
    now: datetime.datetime | None = None,
) -> str:
    """Sign one SigV4 query-string pre-signed URL.

    ``query`` carries S3 sub-resources and action parameters (``{"uploads": ""}`` to
    start a multipart upload, ``{"partNumber": ..., "uploadId": ...}`` to send a
    part). They *must* be signed, or S3's canonical request stops matching ours.

    For the next ``expires`` seconds the returned URL is a pass for that one object
    and action. Never log it or write it into a manifest; see :func:`redact_url`.
    """
    if not endpoint:
        raise S3SigError("No endpoint — set the bucket's endpoint URL first.")
    if not region:
        raise S3SigError(
            "No region for this bucket. A wrong region fails as “signature does not "
            "match”, which is nearly impossible to self-diagnose, so we ask up front. "
            "Cloudflare R2 uses the literal value auto."
        )
    if not access_key or not secret_key:
        raise S3SigError("No bucket key available to sign with.")
    if expires <= 0 or expires > MAX_EXPIRES_SECONDS:
        raise S3SigError(
            f"expires must be between 1 second and 7 days (got {expires}s). "
            "Seven days is the signature format's own ceiling, not our choice."
        )

    parsed = urllib.parse.urlsplit(endpoint if "//" in endpoint else f"https://{endpoint}")
    scheme = parsed.scheme or "https"
    host = parsed.netloc
    if not host:
        raise S3SigError(f"Endpoint {endpoint!r} has no host part.")

    addressing = resolve_addressing(None, addressing)
    if addressing == "virtual":
        if not bucket:
            raise S3SigError("Virtual-hosted addressing needs a bucket name.")
        # The bucket moves into the hostname, so it no longer appears in the
        # canonical URI.
        if not host.startswith(f"{bucket}."):
            host = f"{bucket}.{host}"

    canonical_uri = canonical_object_path(bucket, key, addressing)

    stamp = now or datetime.datetime.now(datetime.UTC)
    amz_date = stamp.strftime("%Y%m%dT%H%M%SZ")
    datestamp = stamp.strftime("%Y%m%d")
    scope = f"{datestamp}/{region}/{_SERVICE}/aws4_request"

    params: dict[str, str] = dict(query or {})
    params.update(
        {
            "X-Amz-Algorithm": _ALGORITHM,
            "X-Amz-Credential": f"{access_key}/{scope}",
            "X-Amz-Date": amz_date,
            "X-Amz-Expires": str(int(expires)),
            "X-Amz-SignedHeaders": "host",
        }
    )
    canonical_query = _canonical_query(params)
    canonical_request = "\n".join(
        [
            method.upper(),
            canonical_uri,
            canonical_query,
            f"host:{host}\n",
            "host",
            _UNSIGNED_PAYLOAD,
        ]
    )
    string_to_sign = "\n".join(
        [
            _ALGORITHM,
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signature = hmac.new(
        _signing_key(secret_key, datestamp, region),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"{scheme}://{host}{canonical_uri}?{canonical_query}&X-Amz-Signature={signature}"


def redact_url(url: str) -> str:
    """Cut a pre-signed URL down to something safe to log: keep up to the path, drop
    the whole query string.

    The query holds ``X-Amz-Credential`` (the access key) and ``X-Amz-Signature`` (a
    pass while valid). Dropping all of it beats enumerating the dangerous parameters.
    """
    return url.split("?", 1)[0]
