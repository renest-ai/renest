"""``renest presign`` -- sign time-limited links on the machine that holds the key.

A long-lived key should never land on a machine you rented. Packing uses the key once,
on your own computer; the rebuilding machine gets only links limited in time, in object
and in action, and can neither see nor derive the key. The output is a v1 restore code,
one file both legs already speak -- ``renest restore --grant <file>`` and
``GRANT=<file> bash restore.sh`` -- so the escape hatch gains no new dependency.

[SECURITY-REVIEW] the key signs inside this process and is never written into the
output: the restore code holds time-limited URLs and nothing else. That code is itself
a pass while it is valid, so it lands on disk 0600 and the output says what it can do
and when it expires. Anything logged goes through :func:`renest.s3sig.redact_url`,
which drops the whole query string. The 7-day ceiling is a SigV4 protocol limit, not
ours -- past it we refuse instead of handing back a link guaranteed to fail.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import sys
from pathlib import Path

import httpx

from .byos import blob_key, manifest_key
from .config import ConfigError, CredentialSource, read_json_source, resolve_credentials
from .errors import ExitCode
from .events import EventEmitter
from .hosted import manifest_blobs
from .s3sig import S3SigError, presign

__all__ = [
    "DEFAULT_EXPIRES_IN",
    "SELF_SIGNED_MAX_EXPIRES_IN",
    "add_arguments",
    "build_restore_code",
    "run_from_args",
]

#: Default validity of 6 hours: long enough to cover downloading a large nest, short
#: enough that a leaked restore code does not stay useful for long.
DEFAULT_EXPIRES_IN = 6 * 3600

#: Codes you sign yourself are capped at 24 hours; the protocol ceiling is 7 days
#: (:data:`renest.s3sig.MAX_EXPIRES_SECONDS`). Exceeding the cap says outright what the
#: cap is, rather than dressing it up as a technical limit.
SELF_SIGNED_MAX_EXPIRES_IN = 24 * 3600


def _iso(seconds_from_now: int) -> str:
    when = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=seconds_from_now)
    return when.replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Signer:
    """Bucket config plus key, wrapped as the ability to sign one key.

    The key never leaves this object.
    """

    def __init__(self, bucket_key, expires_in: int = DEFAULT_EXPIRES_IN) -> None:
        self._k = bucket_key
        self._expires_in = expires_in
        self._region = bucket_key.effective_region()
        self._addressing = bucket_key.effective_addressing()
        if not bucket_key.bucket:
            raise ConfigError(
                "No bucket name. Set it under [storage] in your config file, or in "
                "RENEST_S3_BUCKET."
            )
        if not self._region:
            raise ConfigError(
                "We can't tell which region to sign for. A wrong region fails as "
                "“signature does not match”, which is nearly impossible to work out from "
                "the error, so we ask up front instead of guessing.",
                hint="Set region under [storage] (Cloudflare R2 uses the literal value auto).",
            )

    def sign(self, key: str, method: str = "GET") -> str:
        try:
            return presign(
                method=method,
                key=key,
                endpoint=self._k.endpoint or "",
                bucket=self._k.bucket or "",
                region=self._region or "",
                access_key=self._k.access_key,
                secret_key=self._k.secret_key,
                addressing=self._addressing,
                expires=self._expires_in,
            )
        except S3SigError as e:
            raise ConfigError(str(e)) from e


def build_restore_code(
    signer: Signer,
    manifest: dict,
    *,
    expires_in: int = DEFAULT_EXPIRES_IN,
) -> dict:
    """manifest -> a v1 restore code, understood by both the agent and the escape hatch.

    ``manifest_sha256`` is computed over the bytes the URL in the restore code will
    actually fetch, that is the canonical serialisation of the manifest, byte for byte
    the same as what pack wrote into the bucket. The restoring side checks against it and
    treats any mismatch as the manifest having been swapped.
    """
    nest_id = str(manifest.get("id") or "")
    if not nest_id:
        raise ConfigError("This manifest has no id, so there is nothing to sign links for.")
    body = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    return {
        "grant_version": "1",
        "nest_id": nest_id,
        "expires_at": _iso(expires_in),
        "manifest_url": signer.sign(manifest_key(nest_id)),
        "manifest_sha256": hashlib.sha256(body).hexdigest(),
        "blobmap": {
            sha: [signer.sign(blob_key(sha))] for sha in sorted(manifest_blobs(manifest))
        },
    }


def _write_0600(path: Path, text: str) -> None:
    """A restore code is a pass while it is valid, so it hits the disk as 0600 already.

    Writing it wide and tightening afterwards would leave a window where anyone on the
    machine could read it.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)
    if os.name != "nt":
        os.chmod(path, 0o600)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--manifest",
        help="the nest manifest to sign links for — a local path, or a URL. This is the "
        "usual way: point it at the manifest.json inside your pack output",
    )
    src.add_argument(
        "--nest",
        metavar="NEST_ID",
        help="sign links for a nest already in your bucket (we fetch its manifest first)",
    )
    src.add_argument(
        "--key",
        help="sign a link for one single object key and print it — for poking at things "
        "by hand, not for restores",
    )
    parser.add_argument(
        "--expires-in",
        type=int,
        default=DEFAULT_EXPIRES_IN,
        metavar="SECONDS",
        help=f"how long the links stay valid, in seconds (default {DEFAULT_EXPIRES_IN}, "
        f"max {SELF_SIGNED_MAX_EXPIRES_IN // 3600}h). Sign a fresh one whenever it "
        "runs out",
    )
    parser.add_argument(
        "--method",
        default="GET",
        help="HTTP method for --key (default GET)",
    )
    parser.add_argument(
        "--out",
        help="write the restore code here (permissions 600). Left out, it goes to stdout",
    )


def run_from_args(args: argparse.Namespace, emitter: EventEmitter | None = None) -> int:
    # Usage errors are checked first: they must not depend on whether a bucket is set up.
    # When someone gets --expires-in wrong, answering "you have no bucket configured" is
    # answering a question they did not ask.
    if args.expires_in <= 0:
        print(f"✗ --expires-in must be at least 1 second (got {args.expires_in}s).",
              file=sys.stderr)
        return int(ExitCode.USAGE)
    if args.expires_in > SELF_SIGNED_MAX_EXPIRES_IN:
        hours = SELF_SIGNED_MAX_EXPIRES_IN // 3600
        # An error message states the cap and what to do next. It never sells and never
        # argues for the limit.
        print(
            f"✗ --expires-in is at most {hours}h ({SELF_SIGNED_MAX_EXPIRES_IN}s); "
            f"you asked for {args.expires_in}s.\n"
            f"  When a code runs out, sign a fresh one — it takes a second and your nest "
            f"doesn't change.",
            file=sys.stderr,
        )
        return int(ExitCode.USAGE)

    try:
        creds = resolve_credentials(config_path=getattr(args, "config", None))
    except ConfigError as e:
        print(f"✗ {e.human}", file=sys.stderr)
        if e.hint:
            print(f"  → {e.hint}", file=sys.stderr)
        return e.exit_code
    if creds.source is not CredentialSource.BUCKET_KEY or creds.bucket_key is None:
        print(
            "✗ No bucket of your own is set up yet, so there is no key to sign with. "
            "Run `renest doctor --storage` — it prints the exact steps.",
            file=sys.stderr,
        )
        return int(ExitCode.CONFIG_OR_CREDENTIAL)
    # Signing links on a rented machine turns the point of this command inside out.
    # We say so, but we do not block it.
    if creds.on_pod:
        print(
            "⚠ You are signing links on a machine you rent, which means your long-lived "
            "key is already on it — that is the thing this command exists to avoid. Sign "
            "them on your own computer and bring only the restore code here.",
            file=sys.stderr,
        )

    try:
        signer = Signer(creds.bucket_key, expires_in=args.expires_in)
    except ConfigError as e:
        print(f"✗ {e.human}", file=sys.stderr)
        if e.hint:
            print(f"  → {e.hint}", file=sys.stderr)
        return e.exit_code

    if args.key:
        try:
            print(signer.sign(args.key, method=args.method))
        except ConfigError as e:
            print(f"✗ {e.human}", file=sys.stderr)
            return e.exit_code
        return int(ExitCode.OK)

    client = httpx.Client(follow_redirects=True)
    try:
        if args.nest:
            url = signer.sign(manifest_key(args.nest))
            try:
                manifest = read_json_source(url, client=client)
            except ConfigError as e:
                print(
                    f"✗ Could not read the manifest for nest {args.nest} from your bucket: "
                    f"{e.human}",
                    file=sys.stderr,
                )
                return e.exit_code
        else:
            try:
                manifest = read_json_source(args.manifest, client=client)
            except ConfigError as e:
                print(f"✗ Could not read that manifest: {e.human}", file=sys.stderr)
                return e.exit_code
    finally:
        client.close()

    try:
        code = build_restore_code(signer, manifest, expires_in=args.expires_in)
    except ConfigError as e:
        print(f"✗ {e.human}", file=sys.stderr)
        return e.exit_code

    text = json.dumps(code, ensure_ascii=False, indent=1) + "\n"
    if args.out:
        _write_0600(Path(args.out), text)
        hours = args.expires_in / 3600
        print(
            f"✓ Restore code for nest {code['nest_id']} written to {args.out} "
            f"(permissions 600, {len(code['blobmap'])} files, good for {hours:g}h).\n"
            f"  Take just this file to the other machine — your key stays here:\n"
            f"    renest restore --grant {args.out} --dir /workspace\n"
            f"    GRANT={args.out} TARGET=/workspace bash restore.sh\n"
            f"  Treat it like a password while it lasts: anyone holding it can read this "
            f"nest until it expires.",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(text)
    return int(ExitCode.OK)
