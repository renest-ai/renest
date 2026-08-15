"""Multi-source blob resolver: walk the ordered ``files[].blob.sources`` chain —
probe-race the sources → 8-way ranged download → full sha256 verification → fall
back to the next source on any failure.

The race is a probe race (concurrent ``Range: 0-0``) and the winner downloads
first; the final sha256 check means a wrong guess costs a fallback, never bad
data. ``authoritative`` sources carry the existence guarantee, the rest are
hash-verified accelerators — a poisoned source (hash mismatch) is loudly recorded
and skipped, never silently accepted. ``torrent`` / ``magnet`` are skipped and
recorded, not treated as failures. Every step is attributable, and exhaustion
raises :class:`SourcesExhausted` carrying the per-source blame list.

Boundary: this module lives only in the agent layer. The escape hatch
``restore.sh`` never reads ``sources`` and never imports this package.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .events import EventEmitter

__all__ = [
    "PROBE_TIMEOUT_S",
    "DOWNLOAD_TIMEOUT_S",
    "RANGE_WORKERS",
    "SINGLE_STREAM_MAX",
    "UNSUPPORTED_KINDS",
    "Source",
    "BlobSpec",
    "ProbeResult",
    "ResolveReport",
    "SourcesExhausted",
    "classify_source_failures",
    "probe",
    "expand_sources",
    "resolve",
]

PROBE_TIMEOUT_S = 5.0
DOWNLOAD_TIMEOUT_S = 30.0  # per-read timeout (not overall wall clock); 30s stall = dead
RANGE_WORKERS = 8  # measured choice: 8 concurrent ranges
SINGLE_STREAM_MAX = 8 * 1024 * 1024  # below 8 MiB, segmentation is not worth it
UNSUPPORTED_KINDS = frozenset({"torrent", "magnet"})


def expand_sources(sources: list["Source"], region: str | None = None) -> list["Source"]:
    """Add equivalent accelerator doors to a source chain, per the source playbook
    (``data/source-playbook.json``).

    For every source matching a ``host_rewrites`` rule whose regions include the
    current region, append a sibling ``mirror`` source with the host swapped.
    Sources are only added, never removed or reordered: the probe race settles
    which is fastest and the final sha256 settles whether the bytes are right, so
    a useless rewrite costs one extra probe. ``region`` defaults to the
    ``RENEST_REGION`` environment variable; unset means no rewriting. Any error in
    here returns the original chain untouched.
    """
    region = region if region is not None else os.environ.get("RENEST_REGION", "")
    if not region:
        return sources
    try:
        from .rules import SOURCE_PLAYBOOK, load_rules

        rewrites = load_rules(SOURCE_PLAYBOOK)["host_rewrites"]
    except Exception:
        return sources
    out = list(sources)
    existing_urls = {s.url for s in sources}
    for src in sources:
        for rule in rewrites:
            if region not in rule["regions"] or src.host != rule["match_host"]:
                continue
            parts = urlsplit(src.url)
            twin = parts._replace(netloc=rule["replace_host"]).geturl()
            if twin not in existing_urls:
                existing_urls.add(twin)
                out.append(Source(url=twin, kind=rule.get("kind", "mirror"),
                                  note=f"rules rewrite of {src.host}"))
    return out


class SourcesExhausted(RuntimeError):
    """All sources exhausted. ``attribution`` is the per-source blame list
    (JSON-serialisable; feeds the CSV ``fail_class``)."""

    def __init__(self, sha256: str, attribution: list[dict]):
        self.sha256 = sha256
        self.attribution = attribution
        lines = "; ".join(f"{a['host']}({a['kind']}):{a['reason']}" for a in attribution)
        super().__init__(f"blob {sha256[:12]}… ran out of sources: {lines}")


@dataclass
class Source:
    url: str
    kind: str
    note: str = ""

    @property
    def host(self) -> str:
        return urlsplit(self.url).netloc or "<no host>"


@dataclass
class BlobSpec:
    sha256: str
    size_bytes: int
    sources: list[Source]

    @classmethod
    def from_manifest_file(cls, entry: dict) -> BlobSpec:
        blob = entry["blob"]
        return cls(
            sha256=blob["sha256"],
            size_bytes=int(blob["size_bytes"]),
            sources=[
                Source(url=s["url"], kind=s["kind"], note=s.get("note", ""))
                for s in blob.get("sources", [])
            ],
        )


@dataclass
class ProbeResult:
    source: Source
    ok: bool
    ttfb_s: float = float("inf")
    ranges_ok: bool = False
    size: int | None = None
    reason: str = ""
    #: HTTP status code the probe saw (None when there is none, e.g. the connection
    #: itself failed). Kept as a machine-readable integer rather than living only
    #: inside the ``reason`` string, so that the blame classifier
    #: (:func:`classify_source_failures`) never has to parse prose.
    status: int | None = None


@dataclass
class ResolveReport:
    """Measurement record of one successful resolve: transfer speed and what was
    skipped, kept for the transfer statistics."""

    sha256: str
    winner_host: str
    winner_kind: str
    mode: str  # range8 / single
    transfer_seconds: float
    verify_seconds: float
    mbps: float
    skipped: list[dict] = field(default_factory=list)  # sources not used, with reasons


#: Statuses that plainly mean "the thing is not there". 404 = not there;
#: 410 = it was there once and is now gone for good.
_MISSING_STATUSES = frozenset({404, 410})
#: Statuses that plainly mean "this key, or this signature, is no good".
#: **400 is not a typo here**: Cloudflare R2 answers a missing or wrong signature
#: with HTTP 400, not 401/403. Leave it out and that case falls through as
#: retryable, so the retries hammer a signature error that can never succeed.
_DENIED_STATUSES = frozenset({400, 401, 403})
#: Plainly transient failures: worth retrying. Every other 4xx is **not** retried
#: (a 4xx means, by definition, "your request is wrong").
_TRANSIENT_STATUSES = frozenset({408, 425, 429})


def classify_source_failures(attribution: list[dict]) -> tuple[str, str]:
    """A run of source failures → (error_class name, one plain sentence for the user).

    ``NETWORK_INTERRUPTED`` is **retryable**; ``OBJECT_MISSING`` /
    ``CREDENTIAL_EXPIRED`` / ``UNKNOWN`` are not. Calling everything a network
    problem makes the retry hammer a 404 that can never succeed, and sends the user
    off to inspect a network that is fine.

    The order is deliberately conservative: if **any single** source failed
    transiently the verdict is the retryable network class, because a retry really
    might succeed there. Only when none did do we conclude "not retryable".

    **The fallback must be non-retryable too**: an unrecognised 4xx in the network
    class is the worst combination — wrong cause stated *and* retries wasted.

    The 404 wording has to leave room: **some providers answer 404 rather than 403
    when the key lacks listing permission** (AWS S3 without ``s3:ListBucket`` does
    exactly this), so we must not flatly claim the file is not in the bucket.
    """
    if not attribution:
        return "NETWORK_INTERRUPTED", "every source failed"

    def status_of(entry: dict) -> int | None:
        status = entry.get("status")
        if isinstance(status, int):
            return status
        # Cover the older shape that carries no status (its reason holds "HTTP404")
        reason = str(entry.get("reason", ""))
        marker = reason.rfind("HTTP")
        if marker >= 0:
            digits = reason[marker + 4 : marker + 7]
            if digits.isdigit():
                return int(digits)
        return None

    statuses = [status_of(a) for a in attribution]
    # Transient = the connection never happened (no status code at all) / an
    # explicit retry signal / any 5xx. One of them is enough to conservatively
    # call the whole run retryable.
    if any(s is None or s in _TRANSIENT_STATUSES or 500 <= s <= 599 for s in statuses):
        return "NETWORK_INTERRUPTED", "every source failed"
    if any(s in _DENIED_STATUSES for s in statuses):
        return (
            "CREDENTIAL_EXPIRED",
            "the storage refused the key or the signed link. Either it expired, or the "
            "request was not signed at all (a private bucket cannot be read from a plain "
            "URL — it needs a signed one). Retrying will not help",
        )
    if all(s in _MISSING_STATUSES for s in statuses):
        return (
            "OBJECT_MISSING",
            "the storage says this file is not there. Either it was never finished "
            "uploading, or you are pointed at the wrong bucket or folder, or this key "
            "is not allowed to see it (some providers answer \u201cnot found\u201d instead of "
            "\u201cforbidden\u201d when the key cannot list the bucket). This is not a network "
            "problem — retrying will not make the file appear",
        )
    return (
        "UNKNOWN",
        "the storage rejected the request. This is not a network problem, so retrying "
        "will not help — the addresses or the signature are wrong",
    )


def _redact(url: str) -> str:
    """Strip the query string from any logged/attributed URL (presigned
    strings are close kin to credentials — never persisted)."""
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}{p.path}"


def probe(client: httpx.Client, src: Source) -> ProbeResult:
    """``Range: 0-0`` probe: measures time-to-first-byte, confirms range
    support and total size along the way."""
    t0 = time.monotonic()
    try:
        r = client.get(src.url, headers={"Range": "bytes=0-0"}, timeout=PROBE_TIMEOUT_S)
    except httpx.HTTPError as e:
        return ProbeResult(src, ok=False, reason=f"probe:{type(e).__name__}")
    ttfb = time.monotonic() - t0
    if r.status_code == 206:
        cr = r.headers.get("content-range", "")  # bytes 0-0/12345
        tail = cr.rsplit("/", 1)[-1]
        size = int(tail) if "/" in cr and tail.isdigit() else None
        return ProbeResult(src, ok=True, ttfb_s=ttfb, ranges_ok=True, size=size)
    if r.status_code == 200:
        cl = r.headers.get("content-length")
        return ProbeResult(
            src, ok=True, ttfb_s=ttfb, ranges_ok=False, size=int(cl) if cl and cl.isdigit() else None
        )
    return ProbeResult(src, ok=False, reason=f"probe:HTTP{r.status_code}", status=r.status_code)


class _Progress:
    """Thread-safe byte counter that fans out to a frozen ``progress`` event."""

    def __init__(
        self,
        emitter: EventEmitter | None,
        *,
        stage: str,
        total: int,
        host: str,
        started: float,
    ) -> None:
        self._emitter = emitter
        self._stage = stage
        self._total = max(total, 1)
        self._host = host
        self._started = started
        self._done = 0
        self._lock = threading.Lock()

    def add(self, n: int) -> None:
        if self._emitter is None:
            return
        with self._lock:
            self._done += n
            done = self._done
        elapsed = max(time.monotonic() - self._started, 1e-6)
        self._emitter.progress(
            self._stage,
            percent=round(done * 100 / self._total, 1),
            bytes_done=done,
            bytes_total=self._total,
            speed_mbps=round(done * 8 / 1e6 / elapsed, 1),
            active_sources=[self._host],
        )


def _download_single(client: httpx.Client, src: Source, dest: Path, prog: _Progress) -> None:
    with client.stream("GET", src.url, timeout=DOWNLOAD_TIMEOUT_S) as r:
        r.raise_for_status()
        with dest.open("wb") as f:
            for chunk in r.iter_bytes(chunk_size=1 << 20):
                f.write(chunk)
                prog.add(len(chunk))


def _download_range8(
    client: httpx.Client, src: Source, dest: Path, size: int, prog: _Progress
) -> None:
    """8-way ranged concurrency, each seeking into the same pre-sized file
    (our own engine)."""
    with dest.open("wb") as f:
        f.truncate(size)
    bounds = [
        (i * size // RANGE_WORKERS, (i + 1) * size // RANGE_WORKERS - 1)
        for i in range(RANGE_WORKERS)
    ]

    def fetch_part(lo: int, hi: int) -> None:
        with client.stream(
            "GET", src.url, headers={"Range": f"bytes={lo}-{hi}"}, timeout=DOWNLOAD_TIMEOUT_S
        ) as r:
            if r.status_code != 206:
                raise httpx.HTTPStatusError(
                    f"expected HTTP 206, got {r.status_code}", request=r.request, response=r
                )
            with dest.open("r+b") as f:
                f.seek(lo)
                for chunk in r.iter_bytes(chunk_size=1 << 20):
                    f.write(chunk)
                    prog.add(len(chunk))

    with ThreadPoolExecutor(max_workers=RANGE_WORKERS) as ex:
        futures = [ex.submit(fetch_part, lo, hi) for lo, hi in bounds]
        for fut in futures:
            fut.result()  # any segment failure -> raises, whole source discarded, next source


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def resolve(
    blob: BlobSpec,
    dest: Path,
    client: httpx.Client | None = None,
    *,
    emitter: EventEmitter | None = None,
    stage: str = "S1",
) -> ResolveReport:
    """Resolve one blob along its source chain into ``dest``; return the
    measurement record. Raises :class:`SourcesExhausted` when all sources fail.

    ``dest`` write guarantee: on success ``dest`` is the verified complete
    file; every failure path clears the partial artefact.

    ``emitter``: optional frozen :class:`~renest.events.EventEmitter`; when given,
    ``progress`` events (all five contract fields) stream as bytes land.
    """
    blob = BlobSpec(blob.sha256, blob.size_bytes, expand_sources(blob.sources))
    if not blob.sources:
        raise SourcesExhausted(
            blob.sha256,
            [{"host": "-", "kind": "-", "url": "-", "reason": "the manifest lists no sources"}],
        )
    own_client = client is None
    client = client or httpx.Client(follow_redirects=True)
    attribution: list[dict] = []
    skipped: list[dict] = []

    def _log(msg: str, **extra: object) -> None:
        if emitter is not None:
            emitter.log(msg, stage=stage, **extra)

    try:
        usable = []
        for s in blob.sources:
            if s.kind in UNSUPPORTED_KINDS:
                _log(f"Skipping {s.host}: kind={s.kind} is not supported in v1", level="warning")
                skipped.append({"host": s.host, "kind": s.kind, "reason": "kind not supported"})
            else:
                usable.append(s)
        if not usable:
            raise SourcesExhausted(blob.sha256, skipped or attribution)

        # -- probe race: concurrent Range 0-0; live sources sorted by TTFB,
        #    dead sources demoted to the tail (not dropped) --
        with ThreadPoolExecutor(max_workers=min(8, len(usable))) as ex:
            probes = list(ex.map(lambda s: probe(client, s), usable))
        alive = sorted((p for p in probes if p.ok), key=lambda p: p.ttfb_s)
        dead = [p for p in probes if not p.ok]
        for p in alive:
            _log(
                f"Probe {p.source.host}({p.source.kind}): first byte {p.ttfb_s * 1000:.0f}ms, "
                f"ranges={'yes' if p.ranges_ok else 'no'}"
            )
        for p in dead:
            _log(
                f"Probe {p.source.host}({p.source.kind}): {p.reason}; moved to the back "
                "of the line",
                level="warning",
            )

        # -- try in order: download → size check → full sha256 verification --
        for p in alive + dead:
            src = p.source
            started = time.monotonic()
            prog = _Progress(
                emitter, stage=stage, total=blob.size_bytes, host=src.host, started=started
            )
            try:
                if p.ranges_ok and p.size and p.size >= SINGLE_STREAM_MAX:
                    mode = "range8"
                    _download_range8(client, src, dest, p.size, prog)
                else:
                    mode = "single"
                    _download_single(client, src, dest, prog)
                t_xfer = time.monotonic() - started

                landed = dest.stat().st_size
                if landed != blob.size_bytes:
                    raise ValueError(
                        f"Wrong size: landed {landed} bytes, manifest says {blob.size_bytes}"
                    )

                t1 = time.monotonic()
                got = _sha256_file(dest)
                t_verify = time.monotonic() - t1
                if got != blob.sha256:
                    # poison source: loudly recorded, never silently accepted
                    raise ValueError(
                        f"Byte check failed (bad source): got {got[:12]}…, "
                        f"expected {blob.sha256[:12]}…"
                    )

                mbps = round(landed * 8 / 1e6 / t_xfer, 1) if t_xfer > 0 else 0.0
                _log(
                    f"✓ {src.host}({src.kind}) {mode} {t_xfer:.1f}s {mbps} Mbps "
                    f"+ byte check {t_verify:.1f}s"
                )
                return ResolveReport(
                    sha256=blob.sha256,
                    winner_host=src.host,
                    winner_kind=src.kind,
                    mode=mode,
                    transfer_seconds=round(t_xfer, 3),
                    verify_seconds=round(t_verify, 3),
                    mbps=mbps,
                    skipped=skipped,
                )
            except (httpx.HTTPError, ValueError, OSError) as e:
                dest.unlink(missing_ok=True)  # partial / poisoned result cleared
                reason = (
                    p.reason
                    if (not p.ok and isinstance(e, httpx.HTTPError))
                    else f"{type(e).__name__}:{e}"
                )
                _log(f"✗ {src.host}({src.kind}): {reason}; trying the next source", level="warning")
                attribution.append(
                    {
                        "host": src.host,
                        "kind": src.kind,
                        "url": _redact(src.url),
                        "reason": str(reason)[:200],
                        "status": p.status,
                    }
                )

        raise SourcesExhausted(blob.sha256, attribution + skipped)
    finally:
        if own_client:
            client.close()


def sources_from_urls(urls: Sequence[str], *, first_authoritative: bool = True) -> list[Source]:
    """Build a source chain from a bare URL list (restore-grant blobmap).

    The first URL is treated as authoritative (it carries the existence
    guarantee); the rest are hash-verified mirror accelerators.
    """
    out: list[Source] = []
    for i, url in enumerate(urls):
        kind = "authoritative" if (first_authoritative and i == 0) else "mirror"
        out.append(Source(url=url, kind=kind, note="restore-grant blobmap"))
    return out
