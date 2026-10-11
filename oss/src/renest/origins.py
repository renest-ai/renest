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

4. A Civitai record found by this file's own sha256 while its licence was looked up:
   the download address that record gives for the file with exactly this sha256.

Since 0.1.23 an address is recorded for every file one can be derived for, restricted or
not: it is where the bytes came from, and what a restore shows and fetches from when the
bytes do not travel. The restore side sends the recipient's Hugging Face token to Hugging
Face addresses only (``gated.token_may_go_to``), so an address on another host never
receives it.

**No address that carries a credential is ever recorded** -- not ours, and not one the
person packing typed (:func:`unsafe_address`): a manifest is handed to other people.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import parse_qsl, quote, unquote, urlsplit

import httpx

__all__ = [
    "HF_HOSTS",
    "civitai_address",
    "editor_model_urls",
    "hf_address_from_cache_path",
    "hf_resolve_parts",
    "known_component_address",
    "unsafe_address",
    "verify_hf_address",
]

HF_HOSTS = frozenset({"huggingface.co"})

_HF_SNAPSHOT = re.compile(r"^models--([^/]+?)--([^/]+)/snapshots/([0-9a-f]{40})/(.+)$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_HOME_HF_PREFIX = ".cache/huggingface/hub/"

#: Query parameters that carry a credential or a signature, lower case: a presigned
#: storage link, a Civitai ``?token=`` API key, an Azure ``sig``.
_SECRET_QUERY_KEYS = frozenset({
    "token", "access_token", "api_key", "apikey", "api-key", "key", "sig", "signature",
    "secret", "password", "passwd", "auth", "authorization", "credential", "expires",
    "policy", "awsaccesskeyid", "key-pair-id",
})
_SECRET_QUERY_PREFIXES = ("x-amz-", "x-goog-")

_CIVITAI_HOSTS = frozenset({"civitai.com"})
_CIVITAI_DOWNLOAD_QUERY = frozenset({"type", "format", "size", "fp"})


def _quote_path(path: str) -> str:
    return quote(path, safe="/")


def unsafe_address(url: str) -> str:
    """Why this address must not be written into a nest, or empty when it is fine.

    A manifest is handed to other people, so an address that carries a login
    (``https://user:pass@host/``) or a signed / keyed query string would hand that
    credential over with it. The answer is a short phrase for a warning.
    """
    parts = urlsplit((url or "").strip())
    if parts.username or parts.password:
        return "it has a user name or password in it"
    for key, _value in parse_qsl(parts.query, keep_blank_values=True):
        k = key.strip().lower()
        if k in _SECRET_QUERY_KEYS or k.startswith(_SECRET_QUERY_PREFIXES):
            return f"its query string carries a key or signature ({key}=…)"
    return ""


def civitai_address(version: dict, sha256: str) -> str:
    """The download address a Civitai model-version record gives for this exact file.

    ``version`` is the answer to ``model-versions/by-hash/<sha256>``. One version can
    hold several files, so the address is taken only from the file whose own sha256
    is this one. When the record lists no such file, the version's page is given
    instead (a person can still find the file there). Empty when neither can be
    built. Never an address with a credential in it.
    """
    sha = (sha256 or "").strip().lower()
    if not isinstance(version, dict) or not _SHA256.match(sha):
        return ""
    for f in version.get("files") or []:
        if not isinstance(f, dict) or not isinstance(f.get("hashes"), dict):
            continue
        if str(f["hashes"].get("SHA256") or "").strip().lower() != sha:
            continue
        url = str(f.get("downloadUrl") or "").strip()
        parts = urlsplit(url)
        if (parts.scheme == "https" and (parts.hostname or "").lower() in _CIVITAI_HOSTS
                and not parts.username and not parts.password and not parts.fragment
                and parts.path.startswith("/api/download/models/")
                and all(k in _CIVITAI_DOWNLOAD_QUERY
                        for k, _v in parse_qsl(parts.query, keep_blank_values=True))):
            return url
    model_id, version_id = version.get("modelId"), version.get("id")
    if (isinstance(model_id, int) and isinstance(version_id, int)
            and not isinstance(model_id, bool) and not isinstance(version_id, bool)):
        return f"https://civitai.com/models/{model_id}?modelVersionId={version_id}"
    return ""


def hf_address_from_cache_path(path: str, root: str = "hf_hub") -> str:
    """The address of a file in the Hugging Face model cache, from its path alone.

    Only a ``snapshots/<commit>/`` path names a file; a ``refs/`` pointer, a
    ``.no_exist`` marker or a blob does not, so those get nothing. ``root == "home"``
    is the same cache under ``.cache/huggingface/hub/``.
    """
    path = path or ""
    if root == "home":
        if not path.startswith(_HOME_HF_PREFIX):
            return ""
        path = path[len(_HOME_HF_PREFIX):]
    elif root != "hf_hub":
        return ""
    m = _HF_SNAPSHOT.match(path)
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
