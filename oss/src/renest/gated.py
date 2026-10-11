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
from collections.abc import Callable, Collection
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
    "not_travelling",
    "already_in_place",
    "needs_you",
    "missing_report",
    "human_size",
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
    #: The host wants a sign-in and it is not Hugging Face: we hold no credential
    #: for it and never send the Hugging Face one there.
    SIGN_IN_ELSEWHERE = "sign_in_elsewhere"
    #: Handed-over nest, address on a host we do not recognise, sender not named:
    #: not contacted at all until the receiver names the sender.
    UNVETTED = "unrecognised_source"
    #: Already at its landing path with the right sha256. Nothing left to do.
    PRESENT = "present"


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
    #: The landing root recorded in the manifest (``files[].root``).
    root: str = "env"
    #: The exact place this file has to be on this machine (filled by the restore).
    dest: str = ""


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
                root=f.get("root") or "env",
            )
        )
    return out


def not_travelling(
    manifest: dict,
    *,
    linked: Collection[str],
    dest_of: Callable[[str, str], Path],
) -> list[GatedAsset]:
    """The restricted files **this restore has no link for**, each with the exact
    place it has to land.

    ``linked`` holds the sha256 of every file the restore can download as usual
    (a restore code that carries a link for it, or a storage address given by
    hand). A restricted file with a link is the owner's own copy and travels like
    anything else; one without is what the receiver gets from its original source.
    ``dest_of(root, path)`` is the landing rule, passed in so this module never
    holds a second copy of it.
    """
    out = []
    for a in gated_assets(manifest):
        if not a.sha256 or a.sha256 in linked:
            continue
        a.dest = str(dest_of(a.root, a.path))
        out.append(a)
    return out


def already_in_place(asset: GatedAsset) -> bool:
    """Whether the file is at its landing path with the right bytes.

    Size first (free), then the sha256 — a file somebody put there by hand counts
    exactly when its bytes are the ones the nest was built with.
    """
    p = Path(asset.dest)
    try:
        if not p.is_file():
            return False
        if asset.size_bytes and p.stat().st_size != asset.size_bytes:
            return False
        h = hashlib.sha256()
        with p.open("rb") as r:
            for chunk in iter(lambda: r.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return False
    return h.hexdigest() == asset.sha256


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


#: Content types that mean "this is a page about the file", not the file.
_PAGE_TYPES = frozenset({"text/html", "application/xhtml+xml", "text/plain"})


#: The only hosts the user's Hugging Face token is ever sent to. ``origin_url``
#: comes from the nest, and whoever packed the nest wrote it: a nest naming some
#: other host must not be able to collect the receiver's token. Redirects off
#: these hosts already drop the header (httpx strips it on a cross-host hop); this
#: covers the first request.
_TOKEN_HOSTS = ("huggingface.co", "hf.co")


def token_may_go_to(url: str) -> bool:
    """Is ``url`` an https address on Hugging Face, the issuer of the token?"""
    try:
        u = httpx.URL(url)
    except Exception:
        return False
    host = (u.host or "").lower()
    return u.scheme == "https" and any(
        host == h or host.endswith("." + h) for h in _TOKEN_HOSTS
    )


def _auth_headers(url: str, token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token and token_may_go_to(url) else {}


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
    headers = _auth_headers(asset.origin_url, token)
    try:
        r = client.head(asset.origin_url, headers=headers, follow_redirects=True, timeout=20.0)
        code = r.status_code
    except Exception as exc:  # a network problem is not a refusal; do not report it as one
        asset.reach = Reach.ERROR
        asset.detail = f"could not check right now ({type(exc).__name__})"
        return asset

    if code < 400:
        # **A 200 is not proof the file is there.** Some hosts answer an anonymous
        # request with a login page and status 200; taking that as "you can get this"
        # is the one answer this probe must never give, because its whole promise is
        # "find out in a minute instead of after renting a machine". Two cheap tells,
        # both from headers we already have: the reply says it is a web page, or it is
        # far smaller than the file we are asking about. Unsure is reported as unsure.
        ctype = (r.headers.get("content-type") or "").split(";")[0].strip().lower()
        try:
            clen = int(r.headers.get("content-length") or 0)
        except ValueError:
            clen = 0
        looks_like_a_page = ctype in _PAGE_TYPES
        far_too_small = bool(asset.size_bytes and clen and clen * 100 < asset.size_bytes)
        if looks_like_a_page or far_too_small:
            asset.reach = Reach.ERROR
            asset.detail = (
                f"the source answered {code}, but with "
                + (f"a web page ({ctype})" if looks_like_a_page
                   else f"only {clen} bytes for a {asset.size_bytes}-byte file")
                + " — that is usually a sign-in page, so we cannot tell from here "
                  "whether you can really get this one"
            )
            return asset
        asset.reach = Reach.FREE
        return asset
    if code in (401, 403):
        if not token_may_go_to(asset.origin_url):
            # Not Hugging Face: there is no credential of yours we would send here,
            # token on this machine or not — and asking for a Hugging Face token
            # would point the reader at the wrong account.
            asset.reach = Reach.SIGN_IN_ELSEWHERE
            asset.detail = (
                "this host asks for a sign-in; your Hugging Face token is only ever "
                "sent to huggingface.co, so get this file from that site yourself"
            )
        elif not token:
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


def human_size(n: int) -> str:
    for unit, k in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= k:
            return f"{n / k:.1f} {unit}"
    return f"{n} bytes"


#: The reaches where nothing we can do on our own gets the file: the receiver has
#: to act (provide it, accept terms, add a token, name the sender).
_NEEDS_YOU = frozenset({
    Reach.NEEDS_CLICK, Reach.NO_TOKEN, Reach.NEEDS_APPROVAL, Reach.NO_SOURCE,
    Reach.SIGN_IN_ELSEWHERE, Reach.UNVETTED,
})

#: Said when the reach itself is the whole story and no detail was recorded.
_WHY = {
    Reach.NEEDS_CLICK: "open the page once and accept the terms",
    Reach.NO_TOKEN: "needs your own account, and this machine has no token",
    Reach.NEEDS_APPROVAL: "the author has to approve you — that can take days",
    Reach.NO_SOURCE: "we do not know where this one came from",
    Reach.SIGN_IN_ELSEWHERE: "this host asks for a sign-in — get it there yourself",
    Reach.UNVETTED: "the address is on a host we do not recognise",
    Reach.ERROR: "could not be checked right now",
}


def needs_you(asset: GatedAsset) -> bool:
    """Whether this file can only arrive if the receiver does something."""
    return asset.reach in _NEEDS_YOU


def _entry(a: GatedAsset, *, why: bool) -> list[str]:
    size = f"  ({human_size(a.size_bytes)})" if a.size_bytes else ""
    lines = [f"      {a.path}{size}"]
    lines.append(f"          from <{a.origin_url}>" if a.origin_url
                 else "          no address on record")
    if why:
        lines.append(f"          {a.detail or _WHY.get(a.reach, a.reach)}")
    return lines


def summarise(assets: list[GatedAsset], *, have_token: bool) -> str:
    """Every file that does not travel with the nest, **all of them, in one go**,
    in two groups: the ones we fetch, and the ones the receiver has to provide.

    **Why all at once**: the worst experience is not "you have to fetch it
    yourself", it is hitting them one at a time — fix one, run again, hit the
    next. Said once, with size and address, they can deal with the whole set once.
    Never shortened to "and N more": a file left out of this list is a file the
    reader finds out about after paying for the machine.
    """
    if not assets:
        return ""
    lines = [
        f"{len(assets)} file(s) do not travel with this nest — their licence does not "
        f"let the sender pass them on. All of them, before anything is downloaded:"
    ]
    ours = [a for a in assets if a.reach in (Reach.FREE, Reach.ERROR, "")]
    yours = [a for a in assets if needs_you(a)]
    here = [a for a in assets if a.reach == Reach.PRESENT]
    if ours:
        lines.append(
            f"\n  We will fetch these for you from their original source "
            f"({len(ours)}), and check each one against this nest:"
        )
        for a in ours:
            lines += _entry(a, why=a.reach != Reach.FREE)
    if yours:
        lines.append(f"\n  You need to provide these ({len(yours)}):")
        for a in yours:
            lines += _entry(a, why=True)
    if here:
        lines.append(f"\n  Already on this machine and checked ({len(here)}):")
        for a in here:
            lines += _entry(a, why=False)
    if not have_token and any(
        a.reach in (Reach.NO_TOKEN, Reach.NEEDS_CLICK, Reach.NEEDS_APPROVAL) for a in assets
    ):
        lines.append("\n" + TOKEN_HELP)
    return "\n".join(lines)


def missing_report(
    assets: list[GatedAsset], *, have_token: bool, sender: str = "", tried: bool = False
) -> str:
    """The one message printed when the restore stops because files that do not
    travel are not here: **every** such file, with its size, sha256, address, the
    exact place to put it, and how to carry on.

    ``tried`` = we did go to the original source and it did not work out (as
    opposed to knowing beforehand that only the receiver can supply the file).
    """
    lines = [
        (
            f"{len(assets)} file(s) that do not travel with this nest could not be "
            f"fetched from their original source. They are licence-restricted, so "
            f"your drive holds no copy to download. None of this nest's files or code "
            f"has been downloaded yet."
            if tried else
            f"{len(assets)} file(s) this nest needs are licence-restricted, so they "
            f"never travel with a hand-off, and they are not on this machine. Not a "
            f"transfer failure — nothing has been downloaded yet, and running this "
            f"again as it is will stop here again."
        )
        + " Each one, and the exact place to put it:"
    ]
    for i, a in enumerate(assets, 1):
        size = f" ({human_size(a.size_bytes)})" if a.size_bytes else ""
        lines.append(f"\n  {i}. {a.path}{size}")
        lines.append(f"       sha256: {a.sha256}")
        lines.append(
            f"       came from: <{a.origin_url}>" if a.origin_url else
            "       came from: no address on record — find a file with exactly this sha256"
        )
        lines.append(f"       why we could not get it: {a.detail or _WHY.get(a.reach, a.reach)}")
        lines.append(f"       put it at: {a.dest}")
    lines.append(
        "\nThen run the same command again. A file that is in place and matches its "
        "sha256 is kept as it is; a file with different bytes is never accepted."
    )
    if sender and any(a.reach == Reach.UNVETTED for a in assets):
        lines.append(
            f"To let this restore fetch from the addresses {sender} recorded on hosts "
            f'we do not recognise, add: --trust-sender "{sender}"'
        )
    if any(a.reach in (Reach.NO_TOKEN, Reach.NEEDS_CLICK, Reach.NEEDS_APPROVAL) for a in assets):
        lines.append(
            "Files that need your own Hugging Face account are fetched for you once "
            + ("the terms are accepted on their page." if have_token
               else "your token is on this machine:\n" + TOKEN_HELP)
        )
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
    headers = _auth_headers(asset.origin_url, token)
    tmp = dest.with_suffix(dest.suffix + ".part")
    dest.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    got = 0
    try:
        with client.stream("GET", asset.origin_url, headers=headers,
                           follow_redirects=True, timeout=300.0) as r:
            if r.status_code >= 400:
                return f"the source answered {r.status_code}"
            ctype = (r.headers.get("content-type") or "").split(";")[0].strip().lower()
            if ctype in ("text/html", "application/xhtml+xml"):
                # A page about the file (or a sign-in page), not the file. Said as
                # what it is: reading it to the end only to report "different bytes"
                # would blame the source for changing a file it never served.
                return (
                    "the address on record answers with a web page, not the file "
                    "itself — open it and download the file there"
                )
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
