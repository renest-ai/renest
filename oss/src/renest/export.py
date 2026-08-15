"""``renest export`` — take a complete copy of a nest out of your Renest drive.

Whatever lands on the hosted drive must have a full self-serve way out: no
ransom, no waiting. Two roads, and neither lets the server hold your bucket key:

- ``--out DIR`` alone: download the nest to this machine in the open drive layout
  (``nests/<id>/manifest.json`` + ``blobs/sha256/<xx>/<hash>``), every byte
  sha256-verified;
- add ``--dest s3``: push that archive on into your own S3-compatible bucket,
  signed with the key on THIS machine (0600 config or RENEST_S3_*). The server
  only signs short-lived GET links for its own storage; it never sees your key.

Afterwards ``renest presign`` signs restore links from that bucket, so the copy plus
the escape script survives us. Export is never slowed or capped: same engine as restore.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

import httpx

from .byos import S3Uploader
from .config import ConfigError, CredentialSource, resolve_credentials, resolve_token
from .download import BlobSpec, SourcesExhausted, resolve, sources_from_urls
from .errors import ExitCode, NestFailure
from .events import EventEmitter
from .hosted import DEFAULT_ORIGIN, _error_message, manifest_blobs
from .pack import PackError
from .restore import _exchange_envelope, _parse_grant, _resolve_grant

__all__ = ["add_arguments", "run_from_args"]

#: Control-plane timeout, same figure as ``renest list`` — a metadata call that
#: hangs longer than this is better reported than waited on.
_TIMEOUT = 30.0


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--nest",
        required=True,
        metavar="NEST_ID",
        help="the nest to export (ids are in the second column of `renest list`)",
    )
    parser.add_argument(
        "--version",
        type=int,
        metavar="N",
        help="which version to export (default: the latest fully verified one)",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="local folder for the exported archive (open drive layout: nests/ + "
        "blobs/). For a bucket export this is also the staging area — files "
        "already here and verified are not downloaded again",
    )
    parser.add_argument(
        "--dest",
        choices=["s3"],
        help='also push the archive into your own S3-compatible bucket ("s3"). '
        "Needs a bucket key on this machine — run `renest doctor --storage` for "
        "the setup steps. The key is used locally to sign the upload; it is "
        "never sent to the Renest service",
    )
    parser.add_argument(
        "--origin",
        help="Renest service address (default https://api.renest.ai, or the RENEST_ORIGIN "
        "environment variable)",
    )


def _pick_version(detail: dict, wanted_no: int | None) -> tuple[dict | None, str]:
    """Choose the version to export. Returns (version, error_message)."""
    versions = detail.get("versions") or []
    if wanted_no is not None:
        for v in versions:
            if int(v.get("version_no", -1)) == wanted_no:
                if v.get("status") != "committed":
                    return None, (
                        f"Version {wanted_no} is not fully verified yet "
                        f"(status: {v.get('status')}). Only verified versions can be "
                        "exported — they are the only ones the drive can vouch for."
                    )
                return v, ""
        return None, (
            f"This nest has no version {wanted_no}. Run `renest list "
            f"{detail.get('id', '')}` to see its versions."
        )
    committed = [v for v in versions if v.get("status") == "committed"]
    if not committed:
        return None, (
            "No version of this nest has finished verifying yet, so there is "
            "nothing complete to export. Try again once `renest list "
            f"{detail.get('id', '')}` shows a verified version."
        )
    head = detail.get("head_version_id")
    for v in committed:
        if v.get("id") == head:
            return v, ""
    return max(committed, key=lambda v: int(v.get("version_no", 0))), ""


def _fetch_nest_detail(
    client: httpx.Client, origin: str, token: str, nest_id: str
) -> tuple[dict | None, int]:
    """GET the nest detail. Returns (detail, exit_code); detail None on failure."""
    try:
        resp = client.get(
            f"{origin.rstrip('/')}/api/v1/nests/{nest_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
    except httpx.HTTPError as e:
        print(
            f"✗ Cannot reach your Renest drive at {origin}: {type(e).__name__}",
            file=sys.stderr,
        )
        return None, int(ExitCode.S1_NETWORK_INTERRUPTED)
    if resp.status_code in (401, 403):
        print(
            "✗ That access token was refused — it may have been revoked. Generate a "
            "fresh one in the web console and update RENEST_TOKEN (or [auth] token).",
            file=sys.stderr,
        )
        return None, int(ExitCode.CONFIG_OR_CREDENTIAL)
    if resp.status_code == 404:
        print(
            f"✗ No nest with id {nest_id} on your drive. Run `renest list` "
            "to see what's there — ids are in the second column.",
            file=sys.stderr,
        )
        return None, int(ExitCode.USAGE)
    if resp.status_code != 200:
        print(f"✗ Your Renest drive said no: {_error_message(resp)}", file=sys.stderr)
        return None, int(ExitCode.S1_STORAGE_UNAVAILABLE)
    return resp.json(), int(ExitCode.OK)


def _request_restore_grant(
    client: httpx.Client, origin: str, token: str, version_id: str
) -> tuple[dict | None, int]:
    """POST a restore-grant for the chosen version. Returns (envelope, exit_code)."""
    try:
        resp = client.post(
            f"{origin.rstrip('/')}/api/v1/nest-versions/{version_id}/restore-grant",
            headers={"Authorization": f"Bearer {token}"},
            json={},
        )
    except httpx.HTTPError as e:
        print(
            f"✗ Cannot reach your Renest drive at {origin}: {type(e).__name__}",
            file=sys.stderr,
        )
        return None, int(ExitCode.S1_NETWORK_INTERRUPTED)
    if resp.status_code == 409:
        print(
            "✗ This version has not finished verifying yet. Try again in a moment.",
            file=sys.stderr,
        )
        return None, int(ExitCode.S1_STORAGE_UNAVAILABLE)
    if resp.status_code == 403:
        print(
            "✗ Something in this nest was blocked by safety policy, so the drive "
            "will not sign download links for it.",
            file=sys.stderr,
        )
        return None, int(ExitCode.S1_CREDENTIAL_EXPIRED)
    if resp.status_code in (401,):
        print(
            "✗ That access token was refused — it may have been revoked. Generate a "
            "fresh one in the web console and update RENEST_TOKEN (or [auth] token).",
            file=sys.stderr,
        )
        return None, int(ExitCode.CONFIG_OR_CREDENTIAL)
    if resp.status_code != 201:
        print(f"✗ Your Renest drive said no: {_error_message(resp)}", file=sys.stderr)
        return None, int(ExitCode.S1_STORAGE_UNAVAILABLE)
    return resp.json(), int(ExitCode.OK)


def _write_manifest(out: Path, nest_id: str, manifest: dict, want_sha: str) -> Path:
    """Write the manifest in the canonical byte form and verify it against the
    grant's sha256 — the archive must carry exactly the bytes the drive vouched
    for, not a re-rendering that merely looks the same."""
    body = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    got = hashlib.sha256(body).hexdigest()
    if want_sha and got != want_sha:
        raise NestFailure(
            "S1",
            "UNKNOWN",
            "The manifest re-serialised to different bytes than the drive signed "
            f"({got[:12]}… ≠ {want_sha[:12]}…). Refusing to write a copy that "
            "does not match its own receipt.",
        )
    dest = out / "nests" / nest_id / "manifest.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    tmp.write_bytes(body)
    os.replace(tmp, dest)
    return dest


def _already_here(path: Path, sha: str, size: int) -> bool:
    """A staged file counts only if the bytes actually match — resumability
    must never trade away verification."""
    try:
        if path.stat().st_size != size:
            return False
    except OSError:
        return False
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest() == sha


def run_from_args(args: argparse.Namespace, emitter: EventEmitter) -> int:  # noqa: ARG001
    log = (lambda m: None) if args.json else (lambda m: print(m, file=sys.stderr))

    try:
        token = resolve_token(config_path=getattr(args, "config", None))
    except ConfigError as e:
        print(f"✗ {e.human}", file=sys.stderr)
        return e.exit_code
    if not token:
        # Word-for-word the same message as `pack --dest hosted` and `list`:
        # same gap, same way out.
        print(
            "✗ No access token. Generate one in the web console, then put it in the "
            "RENEST_TOKEN environment variable, or write it into [auth] token in "
            "~/.config/renest/config.toml.",
            file=sys.stderr,
        )
        return int(ExitCode.CONFIG_OR_CREDENTIAL)

    # Credentials before bytes, same as packing: when the goal
    # is your own bucket, fail on a missing bucket key BEFORE downloading
    # gigabytes, not after.
    uploader = None
    if args.dest == "s3":
        try:
            creds = resolve_credentials(config_path=getattr(args, "config", None))
        except ConfigError as e:
            print(f"✗ {e.human}", file=sys.stderr)
            if e.hint:
                print(f"  → {e.hint}", file=sys.stderr)
            return e.exit_code
        if creds.source is not CredentialSource.BUCKET_KEY or creds.bucket_key is None:
            print(
                "✗ No bucket of your own is set up yet. Run `renest doctor --storage` — it "
                "prints the exact steps.",
                file=sys.stderr,
            )
            return int(ExitCode.CONFIG_OR_CREDENTIAL)
        for warning in creds.exposure_warnings:
            print(f"⚠ {warning}", file=sys.stderr)
        if creds.warning:
            print(f"⚠ {creds.warning}", file=sys.stderr)
        try:
            uploader = S3Uploader(creds.bucket_key, log=None if args.json else log)
        except PackError as e:
            print(f"✗ {e.human}", file=sys.stderr)
            return e.exit_code

    origin = args.origin or os.environ.get("RENEST_ORIGIN") or DEFAULT_ORIGIN
    client = getattr(args, "_client", None) or httpx.Client(
        timeout=_TIMEOUT, follow_redirects=True
    )
    own_client = getattr(args, "_client", None) is None
    try:
        detail, code = _fetch_nest_detail(client, origin, token, args.nest)
        if detail is None:
            return code
        version, err = _pick_version(detail, args.version)
        if version is None:
            print(f"✗ {err}", file=sys.stderr)
            return int(ExitCode.USAGE)

        envelope, code = _request_restore_grant(client, origin, token, str(version["id"]))
        if envelope is None:
            return code

        try:
            payload = _exchange_envelope(envelope, client)
            grant = _parse_grant(payload)
            manifest, blobmap = _resolve_grant(grant, client)
        except NestFailure as e:
            print(f"✗ {e.human}", file=sys.stderr)
            return e.exit_code

        wanted = manifest_blobs(manifest)
        # An export is complete or it is nothing: if the drive will not sign
        # links for some files (e.g. licence-restricted bytes someone handed
        # you), say which and stop — never quietly ship a partial archive.
        missing = sorted(sha for sha in wanted if not blobmap.get(sha))
        if missing:
            print(
                f"✗ The drive signed links for {len(wanted) - len(missing)} of "
                f"{len(wanted)} files, so a complete export is not possible. "
                "Files it cannot supply (usually licence-restricted bytes from a "
                "hand-off — fetch those from their original source):",
                file=sys.stderr,
            )
            for sha in missing[:10]:
                print(f"    {sha[:16]}…", file=sys.stderr)
            if len(missing) > 10:
                print(f"    … and {len(missing) - 10} more", file=sys.stderr)
            return int(ExitCode.S1_OBJECT_MISSING)

        out = Path(args.out)
        nest_id = str(manifest.get("id") or args.nest)
        blobs_root = out / "blobs" / "sha256"
        total = len(wanted)
        done = 0
        fetched = 0
        for sha, size in sorted(wanted.items()):
            dest = blobs_root / sha[:2] / sha
            done += 1
            if _already_here(dest, sha, int(size)):
                log(f"  [{done}/{total}] {sha[:12]}… already here, verified")
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            spec = BlobSpec(sha, int(size), sources_from_urls(blobmap[sha]))
            log(f"  [{done}/{total}] {sha[:12]}… ({size} bytes)")
            try:
                resolve(spec, dest, client)
            except SourcesExhausted as e:
                print(f"✗ Could not download {sha[:12]}…: {e}", file=sys.stderr)
                return int(ExitCode.S1_NETWORK_INTERRUPTED)
            fetched += 1

        manifest_path = _write_manifest(out, nest_id, manifest, grant.manifest_sha256 or "")

        if uploader is not None:
            try:
                uploader(blobs_root, manifest)
            except PackError as e:
                print(f"✗ {e.human}", file=sys.stderr)
                return e.exit_code
    except NestFailure as e:
        print(f"✗ {e.human}", file=sys.stderr)
        return e.exit_code
    finally:
        if own_client:
            client.close()

    total_bytes = sum(int(s) for s in wanted.values())
    if args.json:
        doc = {
            "ok": True,
            "nest_id": nest_id,
            "version_no": version.get("version_no"),
            "files": total,
            "downloaded": fetched,
            "total_bytes": total_bytes,
            "out": str(out),
            "manifest_path": str(manifest_path),
            "own_bucket": uploader.result.to_dict() if uploader is not None else None,
        }
        print(json.dumps(doc, ensure_ascii=False, indent=2))
    else:
        print(
            f"✓ Exported nest {nest_id} (version {version.get('version_no')}) to {out} — "
            f"{total} files, {total_bytes} bytes, every one sha256-verified.",
            file=sys.stderr,
        )
        if uploader is not None:
            r = uploader.result
            print(
                f"✓ In your own bucket now: {r.uploaded_blobs} uploaded, "
                f"{r.skipped_blobs} already there, manifest published.",
                file=sys.stderr,
            )
            print(
                "  This copy is yours outright. To restore from it — even with no "
                "Renest service anywhere — sign links on this machine:\n"
                f"    renest presign --nest {nest_id} --out restore-code.json\n"
                "    GRANT=restore-code.json TARGET=/workspace bash restore.sh\n"
                "  (restore.sh is the escape script; every nest carries a copy at "
                ".renest/escape/restore.sh)",
                file=sys.stderr,
            )
    return int(ExitCode.OK)
