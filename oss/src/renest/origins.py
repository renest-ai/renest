"""Download addresses for files that do not travel with a hand-off -- only proven ones.

A restricted model's bytes are never passed to someone you hand the nest to; what they
get instead is ``origin_url`` plus the fingerprint, and they fetch it themselves. With no
address that becomes a hunt. Until 0.1.20 the address was written only when a person typed
it into a pack-spec, so ``pack --auto`` / ``--workflow`` / the panel never wrote one.

**Every address here is either derived from where the file sits or checked against the
file's own fingerprint. None is guessed from a file name.**

1. The Hugging Face model cache: ``models--<org>--<name>/snapshots/<commit>/<file>`` names
   the repository, the revision and the file outright.
2. Our known-files table: each row was checked by hand against the repository's own
   record of that exact sha256 (repository, revision, path).
3. Model addresses a ComfyUI workflow carries for its loaders (``properties.models`` --
   what ComfyUI's missing-model dialog downloads from). A file name is not proof, so a
   candidate is kept only when Hugging Face itself says the file at that address has
   this sha256 (the ``X-Linked-ETag`` it returns for large files), and it is recorded
   pinned to the revision Hugging Face answered with.

Only Hugging Face addresses are produced. The restore side sends the recipient's own
Hugging Face token along when it fetches an address, so an address on any other host is
never written by us -- only by the person packing, who typed it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import quote, unquote, urlsplit

import httpx

__all__ = [
    "HF_HOSTS",
    "editor_model_urls",
    "hf_address_from_cache_path",
    "hf_resolve_parts",
    "known_component_address",
    "verify_hf_address",
]

HF_HOSTS = frozenset({"huggingface.co"})

_HF_SNAPSHOT = re.compile(r"^models--([^/]+?)--([^/]+)/snapshots/([0-9a-f]{40})/(.+)$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _quote_path(path: str) -> str:
    return quote(path, safe="/")


def hf_address_from_cache_path(path: str) -> str:
    """The address of a file in the Hugging Face model cache, from its path alone.

    Only a ``snapshots/<commit>/`` path names a file; a ``refs/`` pointer or a blob does
    not, so those get nothing.
    """
    m = _HF_SNAPSHOT.match(path or "")
    if not m:
        return ""
    org, name, commit, rest = m.groups()
    return f"https://huggingface.co/{org}/{name}/resolve/{commit}/{_quote_path(rest)}"


def known_component_address(sha256: str) -> str:
    """The pinned download address of a file in our known-files table, or empty."""
    from .licensing import known_component_row

    row = known_component_row(sha256)
    if not row:
        return ""
    origin = str(row.get("origin_url") or "").strip()
    path = str(row.get("path") or "").strip().lstrip("/")
    rev = str(row.get("revision") or "").strip()
    parts = urlsplit(origin)
    if parts.scheme != "https" or (parts.hostname or "").lower() not in HF_HOSTS:
        return ""
    repo = parts.path.strip("/")
    if repo.count("/") != 1 or not path or not _COMMIT.match(rev):
        return ""
    return f"https://huggingface.co/{repo}/resolve/{rev}/{_quote_path(path)}"


def hf_resolve_parts(url: str) -> tuple[str, str, str] | None:
    """``(repo, revision, file)`` of a Hugging Face file address, or None.

    ``https://huggingface.co/<org>/<name>/resolve/<rev>/<file>`` (``blob`` instead of
    ``resolve`` is the same file's web page and reads the same). Query strings such as
    ``?download=true`` are dropped. Dataset and Space addresses are not model files.
    """
    parts = urlsplit((url or "").strip())
    if parts.scheme != "https" or (parts.hostname or "").lower() not in HF_HOSTS:
        return None
    segs = [unquote(s) for s in parts.path.split("/") if s]
    if len(segs) < 5 or segs[2] not in ("resolve", "blob") or segs[0] in ("datasets", "spaces"):
        return None
    return f"{segs[0]}/{segs[1]}", segs[3], "/".join(segs[4:])


def editor_model_urls(graphs: Iterable[object]) -> dict[str, list[str]]:
    """File name -> the download addresses ComfyUI workflows (editor format) give for it.

    ComfyUI's own templates, and the editor when a model is picked from its library,
    write ``properties.models: [{"name", "url", "directory"}]`` onto loader nodes; newer
    files also carry a top-level ``models`` list. Subgraph definitions are walked too.
    These are what a workflow *says*; :func:`verify_hf_address` decides what is true.
    """
    out: dict[str, list[str]] = {}

    def take(models: object) -> None:
        if not isinstance(models, list):
            return
        for m in models:
            if not isinstance(m, dict):
                continue
            name = str(m.get("name") or "").strip().rsplit("/", 1)[-1]
            url = str(m.get("url") or "").strip()
            if name and url.startswith("https://"):
                urls = out.setdefault(name, [])
                if url not in urls:
                    urls.append(url)

    def walk(graph: object, depth: int = 0) -> None:
        if not isinstance(graph, dict) or depth > 8:
            return
        take(graph.get("models"))
        for node in graph.get("nodes") or []:
            if isinstance(node, dict):
                take((node.get("properties") or {}).get("models")
                     if isinstance(node.get("properties"), dict) else None)
        defs = graph.get("definitions")
        if isinstance(defs, dict):
            for sub in defs.get("subgraphs") or []:
                walk(sub, depth + 1)

    for g in graphs:
        walk(g)
    return out


def verify_hf_address(url: str, sha256: str, *, client: httpx.Client) -> tuple[str, str]:
    """Ask Hugging Face whether ``url`` serves the file with this sha256.

    Returns ``(verdict, address)``: ``("match", pinned)`` -- the address rewritten to the
    exact revision Hugging Face answered with; ``("mismatch", "")`` -- that address serves
    other bytes; ``("unknown", "")`` -- it could not say (not a Hugging Face file address,
    a small file it does not fingerprint by sha256, no access, no network).

    One HEAD request, no body, no redirect followed, **no credentials sent**.
    """
    parsed = hf_resolve_parts(url)
    sha = (sha256 or "").strip().lower()
    if parsed is None or not _SHA256.match(sha):
        return "unknown", ""
    repo, rev, path = parsed
    ask = f"https://huggingface.co/{repo}/resolve/{quote(rev, safe='')}/{_quote_path(path)}"
    try:
        r = client.head(ask, follow_redirects=False, timeout=15.0)
    except Exception:  # noqa: BLE001 -- a lookup failing must never fail packing
        return "unknown", ""
    if r.status_code not in (200, 301, 302, 303, 307, 308):
        return "unknown", ""
    etag = (r.headers.get("x-linked-etag") or "").strip().strip('"').lower()
    if not _SHA256.match(etag):
        return "unknown", ""
    if etag != sha:
        return "mismatch", ""
    commit = (r.headers.get("x-repo-commit") or "").strip().lower()
    pinned_rev = commit if _COMMIT.match(commit) else rev
    return "match", (f"https://huggingface.co/{repo}/resolve/{quote(pinned_rev, safe='')}/"
                     f"{_quote_path(path)}")
