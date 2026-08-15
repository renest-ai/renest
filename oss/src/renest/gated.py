"""Assets that do not travel inside the nest: say so up front, fetch what we can.

Restricted assets **never cross users** — the recipient fetches them from the
origin with their own credentials. Without this check a rebuild runs to the end
with those files silently absent, and the user learns it from an unrelated-looking
crash after twenty minutes of paid machine time.

Four cases: publicly downloadable (automatic, just slower); needs one click
(automatic if already accepted with a token on this machine, otherwise accept and
re-run); needs author approval (may take days); origin unknown (only a fingerprint).

The pre-flight check and the fetch live together, because they use the same data
and two copies drift. The token is only ever used on the user's own machine and
never uploaded — which is why "can I download this?" is answered there.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

import httpx

__all__ = [
    "Reach",
    "fetch_from_origin",
    "GatedAsset",
    "gated_assets",
    "find_token",
    "TOKEN_HELP",
    "check_reach",
    "summarise",
]

#: Where to get a token and where to put it. Anyone receiving someone else's
#: nest for the first time hits this step, so the instructions have to be right
#: here rather than in documentation they would have to go looking for.
TOKEN_HELP = (
    "Some of these come from Hugging Face and need your own account:\n"
    "  1. open https://huggingface.co/settings/tokens and make a read token\n"
    "  2. put it in this shell:  export HF_TOKEN=hf_...\n"
    "     (or run `huggingface-cli login` once — we read that too)\n"
    "It stays on this machine. We never see it, and we never ask for it."
)


class Reach:
    """Whether this asset can be got right now, **on this machine, with your
    own credentials**."""

    FREE = "free"                # downloadable as is; will be fetched automatically
    NEEDS_CLICK = "needs_click"  # go accept the terms once; takes seconds
    NEEDS_APPROVAL = "needs_approval"  # the author has to approve; may take days
    NO_TOKEN = "no_token"        # credentials required, none on this machine
    NO_SOURCE = "no_source"      # we do not even know where to get it
    ERROR = "error"              # the probe failed (network etc.); not "unreachable"


@dataclass
class GatedAsset:
    """One asset that does not travel inside the nest."""

    path: str
    sha256: str
    size_bytes: int = 0
    origin_url: str = ""
    #: The restriction shape recorded in the manifest (``auto`` / ``manual`` /
    #: ``none``); empty when the manifest does not say.
    gated_form: str = ""
    reach: str = ""
    detail: str = ""


def gated_assets(manifest: dict) -> list[GatedAsset]:
    """The manifest entries that **do not travel inside the nest**.

    There is exactly one test: ``license.shareable`` is false, or the serving
    scope is gated. Both fields are decided once, at pack time; the restore
    side **follows what it is told and never re-judges in the moment**.
    """
    out: list[GatedAsset] = []
    for f in manifest.get("files") or []:
        lic = f.get("license") or {}
        if lic.get("shareable", True) and lic.get("serving_scope") != "gated":
            continue
        blob = f.get("blob") or {}
        out.append(
            GatedAsset(
                path=f.get("path", ""),
                sha256=blob.get("sha256", ""),
                size_bytes=int(blob.get("size_bytes") or 0),
                origin_url=f.get("origin_url") or "",
                gated_form=lic.get("gated_form") or "",
            )
        )
    return out


def find_token(env: dict[str, str] | None = None, home: Path | None = None) -> str:
    """Find the user's own Hugging Face token. Returns an empty string if none.

    Two places count: the environment, and the file the official command-line
    tool writes after a login. **Read only, used only on this machine, never
    uploaded.**
    """
    e = os.environ if env is None else env
    for key in ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_TOKEN"):
        if e.get(key, "").strip():
            return e[key].strip()
    base = Path(home) if home is not None else Path(e.get("HOME") or Path.home())
    for rel in ("token", "hub/token"):
        p = base / ".cache" / "huggingface" / rel
        try:
            if p.is_file():
                tok = p.read_text(encoding="utf-8").strip()
                if tok:
                    return tok
        except OSError:
            pass
    return ""


def check_reach(asset: GatedAsset, *, token: str, client: httpx.Client) -> GatedAsset:
    """Probe whether this asset can be got right now, **on this machine, with
    your own credentials**.

    This step **needs no GPU and runs on a laptop** — spend a minute here
    instead of twenty minutes plus machine rental finding out the hard way. The
    probe sends one request that asks for no body, and downloads no bytes.
    """
    if not asset.origin_url:
        asset.reach = Reach.NO_SOURCE
        asset.detail = "we do not know where this one came from"
        return asset
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = client.head(asset.origin_url, headers=headers, follow_redirects=True, timeout=20.0)
        code = r.status_code
    except Exception as exc:  # a network problem is not a refusal; do not report it as one
        asset.reach = Reach.ERROR
        asset.detail = f"could not check right now ({type(exc).__name__})"
        return asset

    if code < 400:
        asset.reach = Reach.FREE
        return asset
    if code in (401, 403):
        if not token:
            asset.reach = Reach.NO_TOKEN
            asset.detail = "needs your own account, and this machine has no token"
        elif asset.gated_form == "manual":
            asset.reach = Reach.NEEDS_APPROVAL
            asset.detail = "the author has to approve you — that can take days"
        else:
            asset.reach = Reach.NEEDS_CLICK
            asset.detail = "open the page once and accept the terms"
        return asset
    if code == 404:
        asset.reach = Reach.NO_SOURCE
        asset.detail = "the source no longer has it"
        return asset
    asset.reach = Reach.ERROR
    asset.detail = f"the source answered {code}"
    return asset


#: Display order: **what we handle automatically goes first, what needs the
#: user goes last** — the first thing they should see is "these are taken care
#: of", not a screen full of red.
_ORDER = [Reach.FREE, Reach.NEEDS_CLICK, Reach.NO_TOKEN, Reach.NEEDS_APPROVAL,
          Reach.NO_SOURCE, Reach.ERROR]
_MARK = {Reach.FREE: "OK ", Reach.NEEDS_CLICK: "!! ", Reach.NO_TOKEN: "!! ",
         Reach.NEEDS_APPROVAL: "XX ", Reach.NO_SOURCE: "XX ", Reach.ERROR: "?? "}
_HEAD = {
    Reach.FREE: "will be fetched for you — nothing to do",
    Reach.NEEDS_CLICK: "need you to accept the terms once, then run this again",
    Reach.NO_TOKEN: "need a token on this machine",
    Reach.NEEDS_APPROVAL: "need the author to approve you, which can take days",
    Reach.NO_SOURCE: "cannot be fetched — we do not know where to get them",
    Reach.ERROR: "could not be checked right now",
}


def summarise(assets: list[GatedAsset], *, have_token: bool) -> str:
    """Explain all four cases **in one go**.

    **Why all at once**: the worst experience is not "you have to fetch it
    yourself", it is hitting them one at a time — fix one, run again, hit the
    next. Said once, they can deal with the whole set once.
    """
    if not assets:
        return ""
    lines = [
        f"{len(assets)} file(s) do not travel with this nest — they are fetched from "
        f"where they came from, with your own account:"
    ]
    by: dict[str, list[GatedAsset]] = {}
    for a in assets:
        by.setdefault(a.reach or Reach.ERROR, []).append(a)
    for reach in _ORDER:
        group = by.get(reach)
        if not group:
            continue
        lines.append(f"\n  {_MARK[reach]}{len(group)} {_HEAD[reach]}")
        for a in group[:5]:
            where = f"  <{a.origin_url}>" if a.origin_url else ""
            lines.append(f"      {a.path}{where}")
        if len(group) > 5:
            lines.append(f"      …and {len(group) - 5} more")
    if not have_token and any(
        a.reach in (Reach.NO_TOKEN, Reach.NEEDS_CLICK, Reach.NEEDS_APPROVAL) for a in assets
    ):
        lines.append("\n" + TOKEN_HELP)
    return "\n".join(lines)


def fetch_from_origin(
    asset: GatedAsset, dest: Path, *, token: str, client: httpx.Client
) -> str | None:
    """Fetch this asset from its origin. Returns None on success, or a plain
    sentence explaining the failure.

    **Why not reuse the general downloader**: that path was written for our own
    storage, and this one has to carry the user's token. Hand the token to the
    general downloader and it will **attach it to requests to our own storage
    as well** — a third-party credential belongs only to the party that issued
    it, and should have no extra recipients at all. So this is its own path,
    and **the token appears on this one request only**.

    Landing is done exactly as on the main path: download to ``.part``,
    **verify the sha256**, atomically rename to the real filename. The
    verification is free — the fingerprint is already recorded in the nest, so
    even for bytes we did not serve, **getting the wrong version is caught on
    the spot** instead of surfacing as an incomprehensible error when the
    application starts.
    """
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    tmp = dest.with_suffix(dest.suffix + ".part")
    dest.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    got = 0
    try:
        with client.stream("GET", asset.origin_url, headers=headers,
                           follow_redirects=True, timeout=300.0) as r:
            if r.status_code >= 400:
                return f"the source answered {r.status_code}"
            with tmp.open("wb") as w:
                for chunk in r.iter_bytes(1 << 20):
                    w.write(chunk)
                    h.update(chunk)
                    got += len(chunk)
    except Exception as exc:
        tmp.unlink(missing_ok=True)
        return f"could not download it ({type(exc).__name__})"

    if asset.sha256 and h.hexdigest() != asset.sha256:
        tmp.unlink(missing_ok=True)
        # This message has to make clear "it is not your fault, the thing at the
        # other end changed" — the bytes just downloaded are not the ones the
        # nest was built with, and going ahead with them yields an environment
        # that is quietly different.
        return (
            "what the source has now is not the same file this nest was built with "
            f"(expected {asset.sha256[:12]}…, got {h.hexdigest()[:12]}…). "
            "Nothing was kept — get that exact version yourself, or ask whoever packed it."
        )
    tmp.replace(dest)
    return None
