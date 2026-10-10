"""Which container image this machine booted from -- only when the image says so itself.

A container cannot see its own image name: no provider puts it in the environment
(RunPod and vast were both checked), so ``base_image`` was only ever written when a
person typed it into a pack-spec. ``pack --auto`` and ``pack --workflow`` never had a
place to type it, so every nest packed that way carried no image line at all -- and
the restore-side advice "boot from the image this was packed on" had no name to give.

**One case is not a guess: our own template image.** It writes its own version into
``/opt/renest/versions.env`` at build time (``IMAGE_TAG=<date>``, see
``oss/floor-image/Dockerfile``), and every tag of it lives in one repository whose tags
are never overwritten (the tag-digest ledger beside the Dockerfile). So the name is read
from the image's own file, and the fingerprint comes from the published-tag table below
or, for a tag newer than this release, from the registry. **Nothing else is inferred**:
no file, no record -- the block is left out, exactly as before.

What this cannot tell: an image someone built *on top of* the template carries the same
file, and is recorded as the template it was built from.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx

__all__ = [
    "FLOOR_IMAGE_REPO",
    "FLOOR_VERSIONS_FILE",
    "PUBLISHED_FLOOR_TAGS",
    "detect_base_image",
    "floor_image_tag",
]

#: Where every tag of the template image is published (tag-digest ledger, ``repo``).
FLOOR_IMAGE_REPO = "ghcr.io/renest-ai/nest-base"

#: The file the template image writes its own version into at build time.
FLOOR_VERSIONS_FILE = Path("/opt/renest/versions.env")

#: Tags already published, and the manifest digest the registry serves for each --
#: copied from ``oss/floor-image/tag-digest-ledger.json`` (a test keeps the two in step).
#: These are single-architecture image manifests (the registry answers with an image
#: manifest, not an index), so the digest is the platform one. Tags are never
#: overwritten, so a known tag needs no network at all.
PUBLISHED_FLOOR_TAGS: dict[str, str] = {
    "20260913": "sha256:e31d287a7244cd04f527b03693a7b623c514ec828ae8a5a98072b20264f928d8",
    "20261003": "sha256:5c61740842359fb23b649cb1d3bc8f2f16c60f3b6b7cac7a8006c4dce57192f2",
    "20261005": "sha256:1e12c0b380f493e074b05ffa52778035cac88bc7093511db4a686df9b8d421be",
    "20261008": "sha256:4a14617e8272d32afd514a470ee565dec0864d4cc338af10f127c8b8204215ab",
}

_TAG_SHAPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_DIGEST_SHAPE = re.compile(r"^sha256:[a-f0-9]{64}$")
_INDEX_TYPES = ("application/vnd.oci.image.index.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json")
_IMAGE_TYPES = ("application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.v2+json")


def floor_image_tag(path: Path | None = None) -> str | None:
    """The template image's own version, read from its versions file. None if absent.

    ``unknown`` is what a build that forgot ``--build-arg IMAGE_TAG`` writes; it names
    nothing, so it counts as absent.
    """
    p = FLOOR_VERSIONS_FILE if path is None else path
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key.strip() == "IMAGE_TAG":
            tag = value.strip().strip("'\"")
            if tag and tag.lower() != "unknown" and _TAG_SHAPE.match(tag):
                return tag
            return None
    return None


def _registry_digest(tag: str, *, client: httpx.Client | None, timeout: float
                     ) -> tuple[str, str] | None:
    """Ask the registry for this tag's digest: ``(digest, kind)`` or None.

    Anonymous pull token, one HEAD request, no body. ``kind`` comes from what the
    registry says it served -- an index is ``index``, an image manifest ``platform``.
    """
    host, _, repo = FLOOR_IMAGE_REPO.partition("/")
    own = client is None
    c = client or httpx.Client(timeout=timeout, follow_redirects=True)
    try:
        tok = c.get(f"https://{host}/token", params={"scope": f"repository:{repo}:pull"})
        if tok.status_code != 200:
            return None
        r = c.head(
            f"https://{host}/v2/{repo}/manifests/{tag}",
            headers={"Authorization": f"Bearer {tok.json().get('token', '')}",
                     "Accept": ",".join(_INDEX_TYPES + _IMAGE_TYPES)},
        )
        if r.status_code != 200:
            return None
        digest = (r.headers.get("docker-content-digest") or "").strip()
        if not _DIGEST_SHAPE.match(digest):
            return None
        ctype = (r.headers.get("content-type") or "").split(";")[0].strip()
        kind = "index" if ctype in _INDEX_TYPES else "platform" if ctype in _IMAGE_TYPES else ""
        return digest, kind
    except (httpx.HTTPError, ValueError):
        return None
    finally:
        if own:
            c.close()


def detect_base_image(
    *, path: Path | None = None, online: bool = True, client: httpx.Client | None = None,
    timeout: float = 10.0,
) -> tuple[dict | None, str | None]:
    """``(block, note)``: the manifest's ``base_image`` block for this machine, or None.

    ``note`` is set only when the template image was recognised but its fingerprint
    could not be established -- the one case worth telling the person packing.
    """
    tag = floor_image_tag(path)
    if not tag:
        return None, None
    ref = f"{FLOOR_IMAGE_REPO}:{tag}"
    known = PUBLISHED_FLOOR_TAGS.get(tag)
    if known:
        return {"ref": ref, "digest": known, "digest_kind": "platform"}, None
    got = _registry_digest(tag, client=client, timeout=timeout) if online else None
    if not got:
        return None, (
            f"This machine runs our template image {ref}, but this version of renest "
            f"does not know that tag and the registry could not be asked for its "
            f"fingerprint, so the image line is left out of the manifest. Packing again "
            f"with a network connection, or after `uv tool install --upgrade renest`, "
            f"records it."
        )
    digest, kind = got
    block = {"ref": ref, "digest": digest}
    if kind:
        block["digest_kind"] = kind
    return block, None
