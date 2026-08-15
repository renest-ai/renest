"""Licence judgement: may we pass these bytes on to someone else on the author's behalf?

The one and only implementation -- scattered across capture and pack, "why was this model
judged restricted?" stops being answerable. In: clues; out: one of three tiers plus the
reasoning behind it.

**Allow-list, deny by default.** Not because upstream fields lie: the ``license`` field
offers only about 80 fixed choices and files every custom licence under ``other``, and
there is an unbounded number of those, some permissive and some strict.

The asymmetry is the whole design -- withholding something passable only means the
recipient fetches it from the original site (annoying, visible, recoverable), while passing
on what we had no right to pass on is invisible and turns us into a distributor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # Imported for type annotations only. httpx is never imported at runtime here:
    # looking up licences is an optional path and the caller passes its own client in.
    # A real top-level import would make every "no licence lookup" run pay the startup
    # cost of that dependency.
    import httpx

__all__ = [
    "PERMISSIVE_LICENSES",
    "permissive_licenses",
    "PERMISSIVE_BASE_MODELS",
    "SHARED_COMPONENT_KINDS",
    "GatedForm",
    "LicenseClues",
    "LicenseVerdict",
    "hf_repo_from_path",
    "parse_allow_commercial_use",
    "judge_hf",
    "judge_civitai",
    "unknown_verdict",
    "lookup",
    "github_repo_from_url",
    "judge_code_licence",
    "lookup_code_dep",
    "licence_text_path",
]

# --------------------------------------------------------------------------
# The allow-list: three waves. Waves two and three each wait on the same piece of
# engineering work -- "the licence text travels with the nest".
# --------------------------------------------------------------------------
#: **Wave one, live today.** Permissive, decades of judicial testing behind them, and
#: essentially no commercial friction (``apache-2.0`` also grants a patent licence).
PERMISSIVE_LICENSES: frozenset[str] = frozenset({"apache-2.0", "mit"})

#: Waves two and three: releasable only once we hold the full licence text, because what
#: these licences require is precisely that their terms travel with the distribution.
#: The gate is **in code, not merely in a comment** -- :func:`permissive_licenses` releases
#: only the ones whose text is actually on disk. Note that OpenRAIL is not one name but
#: four distinct strings; listed here are only the ones whose text we can obtain.
_CONDITIONAL_LICENSES: frozenset[str] = frozenset(
    {"cc-by-4.0", "openrail++", "creativeml-openrail-m"}
)

#: **Wave two, not releasable yet**: ``cc-by-4.0`` allows commercial redistribution on
#: **one condition only: attribution**, so author and origin must show through on the page
#: first. Opening this tier without attribution is **not a missing feature, it is a breach
#: of the licence**.
_STAGE_2_PENDING: frozenset[str] = frozenset({"cc-by-4.0"})

#: **Wave three, not releasable yet**: the OpenRAIL family. Permissive in itself and
#: explicitly allowing distribution in software-as-a-service form ("carries restrictions"
#: is widely misread as ruling out commercial hosting). Its real requirement is that
#: **whoever distributes passes the use restrictions down to the next party**, so the
#: licence text must travel with the nest and that clause must be in the terms of service
#: before this opens. Again: four distinct strings, not one name.
_STAGE_3_PENDING: frozenset[str] = frozenset(
    {"openrail", "openrail++", "creativeml-openrail-m", "bigscience-openrail-m"}
)

#: **Deliberately excluded**: ``cdla-permissive-2.0``. Reading model weights as "Results",
#: which the agreement leaves unrestricted, is a clever but untested derivation -- exactly
#: the class of argument the cost asymmetry above exists to guard against. Almost nobody in
#: the model ecosystem uses it, so **the upside is close to zero and the risk is not zero**.
_DELIBERATELY_EXCLUDED: frozenset[str] = frozenset({"cdla-permissive-2.0"})

#: Base models confirmed permissive. **This list is only ever used to release, never to
#: tighten.** The base is judged separately because an add-on is a derivative: its author
#: has a say over their own work and **none over the base**, so "commercial use allowed"
#: declared on top of a restricted base is a statement they had no standing to make.
#: Upstream obligations cannot be widened or waived downstream; a downstream author may
#: only add stricter terms. A name goes in only when the licence chain is clear all the way
#: from base to finished model **and** we hold the full licence text -- without the text
#: the terms cannot be delivered alongside the bytes.

#: The field holds a community nickname (``SD 1.5`` / ``Pony`` / ``Illustrious`` /
#: ``NoobAI``), **not an address that can be looked up**, so this mapping is maintained by
#: hand and an empty list releases nothing (deny by default, not a bug).
#: The community bases stay out because each trips a different wire: ``Illustrious`` has
#: two different licences under one name (early versions strongly copyleft, requiring
#: weights, datasets and merge recipes to be published), ``NoobAI`` additionally bans
#: commercial use of what the model **produces**, and ``Pony`` forbids use in unauthorised
#: online image generation services -- which is exactly the shape of a hosted drive.
PERMISSIVE_BASE_MODELS: frozenset[str] = frozenset({
    "sdxl 1.0", "sdxl1.0", "sdxl", "stable diffusion xl", "sdxl 1.0 refiner",
    # Released only once that licence text was obtained: what blocked the SD 1.5 family
    # was never the licence refusing, it was not holding the text to pass on.
    "sd 1.5", "sd1.5", "sd 1.4", "stable diffusion 1.5",
})

#: Kinds that are a **shared part**, not a model of their own: one text encoder or VAE sits
#: inside dozens of unrelated models. A content-hash hit on such a file identifies **some
#: bundle that contains it**, so that bundle's base model says nothing about this file --
#: whoever uploaded it first simply claimed the hash. Live case (2026-08-09): the Qwen3-4B
#: encoder shipping with FLUX.2-klein matched a stranger's "Z Image Turbo" upload, and an
#: encoder is a derivative of no base at all. Permission flags on such a record still count
#: in full; only the base-model question is meaningless, so only that one is skipped.
SHARED_COMPONENT_KINDS: frozenset[str] = frozenset({"clip", "vae", "tokenizer"})

#: Pull the repository name out of an ``hf_hub`` cache path: ``models--<org>--<name>/...``
_HF_CACHE_PATH = re.compile(r"^models--([^/]+)/")


class GatedForm:
    """The three states of the upstream ``gated`` field. **Do not collapse them into a
    single "needs permission"**: for the recipient, "click through an agreement" and
    "apply to the author and possibly wait days" set completely different expectations."""

    NONE = "none"      # just download it
    AUTO = "auto"      # click through an agreement, seconds
    MANUAL = "manual"  # the author has to approve, possibly days


@dataclass(frozen=True)
class LicenseClues:
    """Input to the judgement: **clues, not conclusions**."""

    root: str = "env"
    path: str = ""
    sha256: str = ""


@dataclass
class LicenseVerdict:
    """Output of the judgement.

    ``serving_scope`` / ``shareable`` / ``spdx`` / ``tag`` go straight into the licence
    block of the manifest (all four fields **already exist today**, which is why the
    judgement half of this work needs no format change).

    ``gated_form`` / ``declared_license_name`` / ``reason`` are **the reasoning, written
    for humans**; for now they only reach logs and prompts. Putting them in the manifest
    has to wait for the new fields in the format work.
    """

    serving_scope: str = "gated"
    shareable: bool = False
    spdx: str = ""
    tag: str = "unknown"
    origin_url: str = ""
    gated_form: str = GatedForm.NONE
    #: The name the author typed by hand when ``license == "other"``.
    #: **Displayed only, never a basis for releasing anything.**
    declared_license_name: str = ""
    #: One plain sentence: why it was judged this way. Disputes, bug hunts and
    #: explanations to users all rely on this.
    reason: str = ""
    #: Things worth telling the person packing (never blocking).
    warnings: list[str] = field(default_factory=list)

    def as_license_block(self) -> dict[str, Any]:
        """Fold into the manifest's licence block. Emits **only fields the format
        already has today**."""
        block: dict[str, Any] = {
            "shareable": self.shareable,
            "serving_scope": self.serving_scope,
        }
        if self.spdx:
            block["spdx"] = self.spdx
        if self.tag:
            block["tag"] = self.tag
        if self.reason:
            block["note"] = self.reason[:500]
        return block


def unknown_verdict(reason: str) -> LicenseVerdict:
    """Not found, lookup failed, origin unrecognised -- restricted in every case
    (deny by default).

    **Packing never fails because of this**: being unable to judge is the normal case,
    not an error.
    """
    return LicenseVerdict(
        serving_scope="gated", shareable=False, tag="unknown", reason=reason
    )


def permissive_licenses() -> frozenset[str]:
    """Which licences are **actually** released right now.

    The two unconditional ones, plus those whose condition is already met -- and the
    condition is **that we hold their full text**, because what those licences require is
    exactly that the terms be delivered along with the distribution.

    **This is a gate in code, not a convention in a comment**: the day someone deletes a
    licence text, or adds a name to ``_CONDITIONAL_LICENSES`` whose text we do not have,
    **it stops releasing that licence on the spot** instead of quietly distributing on
    someone's behalf without the terms attached.
    """
    ok = set(PERMISSIVE_LICENSES)
    for spdx in _CONDITIONAL_LICENSES:
        if licence_text_path(spdx) is not None:
            ok.add(spdx)
    return frozenset(ok)


def hf_repo_from_path(path: str) -> str:
    """Pull the repository name out of a model cache path. Empty string if it is absent.

    This is the **main route** on the Hugging Face side: repository name and revision are
    both written straight into the path, ready to use.
    (**No reverse lookup by content hash.** Upstream has no public hash-to-repository
    endpoint; its hashes can only confirm an already-known repository, never discover
    which repository a file came from. This was corrected against the real API.)
    """
    m = _HF_CACHE_PATH.match(path or "")
    if not m:
        return ""
    return m.group(1).replace("--", "/", 1)


def parse_allow_commercial_use(raw: object) -> frozenset[str]:
    """Parse a value like ``{Image,RentCivit,Rent}`` into a set of options.

    **This is the easiest place in this module to get wrong.** It looks like a string but
    it is really a set of checkboxes, and **the order of the same set of checkboxes
    varies**: both ``{Image,RentCivit,Rent}`` and ``{RentCivit,Image,Rent}`` occur in the
    wild and mean the same thing.

    Comparing them as strings would judge the second one "different from the first" and so
    **silently** mark a shareable model as not shareable -- and a mistake in that
    direction **is invisible from the outside** (the result merely looks "stricter"), so
    it can survive undetected for a long time. Hence: parse into a set.

    The four options observed: ``Image`` / ``Rent`` / ``RentCivit`` / ``Sell``;
    ``{}`` means no commercial use at all, and empty is common.
    """
    if isinstance(raw, (list, tuple, set, frozenset)):
        return frozenset(str(x).strip() for x in raw if str(x).strip())
    if not isinstance(raw, str):
        return frozenset()
    return frozenset(x.strip() for x in raw.strip("{} ").split(",") if x.strip())


def judge_hf(repo_id: str, payload: dict) -> LicenseVerdict:
    """Judge once from Hugging Face's answer. ``payload`` = the body of
    ``GET /api/models/{repo_id}``."""
    origin = f"https://huggingface.co/{repo_id}" if repo_id else ""
    card = payload.get("cardData") or {}
    lic = (card.get("license") or "").strip().lower()
    lic_name = (card.get("license_name") or "").strip()

    # 1. Anything that requires permission before download never travels with the nest:
    #    the recipient has to fetch it from the source under their own credentials.
    #    What is blocked here is "passing it to someone else", **not packing**: packing
    #    it for your own use is entirely fine.
    gated_raw = payload.get("gated")
    if gated_raw:
        form = GatedForm.MANUAL if str(gated_raw).lower() == "manual" else GatedForm.AUTO
        wait = (
            "the author has to approve you, which can take days"
            if form == GatedForm.MANUAL
            else "you have to click through an agreement once"
        )
        return LicenseVerdict(
            serving_scope="gated",
            shareable=False,
            spdx=lic,
            tag="restricted",
            origin_url=origin,
            gated_form=form,
            declared_license_name=lic_name,
            reason=f"{repo_id} is behind an agreement — {wait}. Fetch it yourself from the source.",
        )

    # 2. Allow-list hit -> redistributable. **Only this controlled enumeration counts.**
    if lic in permissive_licenses():
        return LicenseVerdict(
            serving_scope="open",
            shareable=True,
            spdx=lic,
            tag="permissive",
            origin_url=origin,
            reason=f"{repo_id} is {lic}, which allows redistribution.",
        )

    # 3. `other` -> read the typed name, **display only, never a basis for releasing**.
    #    Observed in the wild: someone wrote Apache as `apache-license-2.0`. How an
    #    author happens to spell the name should not decide whether we distribute on
    #    their behalf -- and plenty of `other` entries name no licence at all.
    if lic == "other":
        named = f' The author calls it "{lic_name}".' if lic_name else ""
        return LicenseVerdict(
            serving_scope="gated",
            shareable=False,
            spdx="",
            tag="unknown",
            origin_url=origin,
            declared_license_name=lic_name,
            reason=(
                f"{repo_id} uses a licence that is not one of the standard ones.{named} "
                f"We only pass on licences we recognise for certain, so this one stays with you."
            ),
        )

    # 4. Any other value, including the two waves not yet released -> restricted, but
    #    say clearly why.
    pending = lic in _STAGE_2_PENDING or lic in _STAGE_3_PENDING
    why = (
        f"{repo_id} is {lic}. That licence does allow passing it on, but only if its own "
        f"terms travel with the files, and we do not do that yet — so for now it stays with you."
        if pending
        else f"{repo_id} is {lic}, which is not one of the licences we pass on."
    )
    return LicenseVerdict(
        serving_scope="gated",
        shareable=False,
        spdx=lic,
        tag="capped" if pending else "restricted",
        origin_url=origin,
        reason=why,
    )


def judge_civitai(version: dict, model: dict, *, kind: str = "") -> LicenseVerdict | None:
    """Judge once from Civitai's answer. ``None`` = this record cannot speak for this file.

    **These two payloads take two calls to obtain**: ``by-hash`` returns only the model
    id and name; the four permission fields require a second call to ``models/{id}``.

    ``kind`` is the ``files[].kind`` of the file being judged. It only ever matters for
    :data:`SHARED_COMPONENT_KINDS`, and only for the base-model question -- see there.
    """
    model_id = version.get("modelId") or model.get("id") or ""
    origin = f"https://civitai.com/models/{model_id}" if model_id else ""
    base = str(version.get("baseModel") or "").strip()

    allow_commercial = parse_allow_commercial_use(model.get("allowCommercialUse"))
    flags_ok = all(
        bool(model.get(k))
        for k in ("allowNoCredit", "allowDerivatives", "allowDifferentLicense")
    )

    # 1. If any of the four permission flags says no -> restricted.
    if not allow_commercial or not flags_ok:
        return LicenseVerdict(
            serving_scope="gated",
            shareable=False,
            tag="restricted",
            origin_url=origin,
            reason=(
                "The author of this model did not allow it to be passed on freely. "
                "Download it yourself from the source."
            ),
        )

    # 2. Base model check. **This is the easiest check to leave out**, and leaving it out
    #    amounts to letting the add-on's author speak for the base model. The base field
    #    holds a community nickname, not an address that can be looked up, so the only
    #    option is a hand-maintained list: **free-typed text may tighten, never release**,
    #    so release only what we recognise and have confirmed permissive.
    #    A live example from the wild: an add-on model whose base is Flux (strictly
    #    non-commercial) declaring commercial use allowed for itself.
    if base.lower() not in {b.lower() for b in PERMISSIVE_BASE_MODELS}:
        if kind in SHARED_COMPONENT_KINDS:
            # No conclusion rather than a restriction: the caller then keeps what the user
            # wrote and marks it as their own unverified claim -- exactly what already
            # happens for the same file when nobody happened to upload it here.
            return None
        return LicenseVerdict(
            serving_scope="gated",
            shareable=False,
            tag="unknown",
            origin_url=origin,
            reason=(
                f"This was trained on top of {base or 'a base model we cannot identify'}, "
                f"and we cannot confirm what that base allows. What the author of an add-on "
                f"says cannot speak for the model it was built on, so this one stays with you."
            ),
        )

    return LicenseVerdict(
        serving_scope="open",
        shareable=True,
        tag="permissive",
        origin_url=origin,
        reason=f"The author allows this to be passed on, and its base ({base}) is one we recognise.",
    )


# --------------------------------------------------------------------------
# The seam with the packing side's existing behaviour
# --------------------------------------------------------------------------
#: Strictness of the three tiers; higher number means stricter.
_STRICTNESS = {"open": 0, "private": 1, "gated": 2}


def stricter_of(spec_license: dict | None, verdict: LicenseVerdict | None) -> dict:
    """Merge **what the user wrote in the spec** with **what we looked up**, taking
    whichever is stricter.

    **Why stricter-wins rather than lookup-wins**:

    - user declares permissive, lookup says restricted -> restricted. The lookup wins,
      and that is the entire point of this judgement;
    - user declares restricted, lookup says permissive -> **still restricted**. They may
      know things we do not (a private licensing arrangement, an internal company rule),
      and **honouring the stricter side can never make us distribute one extra byte**;
    - nothing found -> use what they wrote, but **mark it as their own unverified
      statement**.

    Wiring the judgement in this way **can only make a nest stricter, never looser**, and
    that guarantee needs no new fields at all -- while "adding a feature loosened things"
    is the single worst kind of regression to have here.
    """
    spec_block = dict(spec_license) if isinstance(spec_license, dict) else {}
    if verdict is None:
        # Nothing found: keep what they wrote, but record that **they** said it rather
        # than that we looked it up.
        if spec_block:
            # **Deny-by-default must not be routed around here**: when the user writes a
            # licence block but omits the serving tier, it has to be filled in as
            # restricted. Without these two lines, "looked it up and found nothing"
            # would become a looser path than "never looked it up at all", which is the
            # worst kind of regression.
            spec_block.setdefault("serving_scope", "gated")
            if spec_block["serving_scope"] == "gated":
                spec_block["shareable"] = False
            spec_block.setdefault("shareable", False)
            spec_block.setdefault("declared_by", "user")
        return spec_block

    detected = verdict.as_license_block()
    detected["declared_by"] = "detected"
    if verdict.gated_form != GatedForm.NONE:
        detected["gated_form"] = verdict.gated_form
    if not spec_block:
        return detected

    spec_scope = spec_block.get("serving_scope", "gated")
    det_scope = detected.get("serving_scope", "gated")
    if _STRICTNESS.get(spec_scope, 2) > _STRICTNESS.get(det_scope, 2):
        # The user is stricter than we are: take their tier, but carry over the facts we
        # found (licence name, origin, gating form) and label the tier honestly as
        # something they declared.
        merged = dict(detected)
        merged["serving_scope"] = spec_scope
        merged["shareable"] = bool(spec_block.get("shareable", False)) and spec_scope != "gated"
        merged["declared_by"] = "user"
        return merged
    return detected


# --------------------------------------------------------------------------
# Licence texts travel with the nest
# --------------------------------------------------------------------------
#: The licence texts shipped with the tool live here. **We never write licence text
#: ourselves**: these are originals fetched from the official SPDX list, with their
#: sha256 recorded at fetch time, and `test_licence_texts_are_authentic` watches that
#: they have not been altered since.
_LICENSE_TEXT_DIR = Path(__file__).parent / "data" / "licenses"


def licence_text_path(spdx: str) -> Path | None:
    """Where the canonical text of this licence lives. None if we do not ship it.

    **Why ship canonical texts instead of picking them up from the source repository**: a
    repository may ship a ``LICENSE`` that downloading the model **does not bring along**
    (SDXL, Qwen2-7B), or may carry no licence file at all
    (``openai/clip-vit-large-patch14``). The allow-list is a handful of licences with
    exactly one canonical text each, so shipping them settles every case at once and keeps
    packing off the network -- the network only ever decides **which** licence applies.

    Where a repository does carry its own copy (possibly with additions the author wrote
    themselves), **that copy travels too**; this function covers the canonical half only.
    """
    if not spdx:
        return None
    p = _LICENSE_TEXT_DIR / f"{spdx.strip().lower()}.txt"
    return p if p.is_file() else None


def lookup(fspec: dict, *, client: "httpx.Client | None" = None) -> LicenseVerdict | None:
    """Turn the clues in one ``files[]`` entry into a verdict. ``None`` if nothing found.

    **This is the wire that connects this module to the packing side.**

    Two independent routes, as established by probing the real APIs -- not one chain:

    - the placement root is the model cache and the path looks like
      ``models--<org>--<name>/...`` -> **take the repository name straight from the path**
      and look it up; name and revision are both already there;
    - everything else (mostly weights the user downloaded by hand) -> look up by content
      hash on the community site, which **takes two requests** (the first returns only an
      id; the permission fields need a second one).

    **Nothing found, lookup failed, or timed out: always return None** -- the layer above
    then keeps what the user wrote and labels it as their own statement.
    **Packing never fails because a lookup failed**: being unable to judge is the normal
    case, not an error.
    """
    import httpx as _httpx

    own = client is None
    c = client or _httpx.Client(timeout=15.0, follow_redirects=True)
    try:
        if fspec.get("root") == "hf_hub":
            repo = hf_repo_from_path(fspec.get("path", ""))
            if not repo:
                return None
            r = c.get(f"https://huggingface.co/api/models/{repo}")
            if r.status_code != 200:
                return None
            return judge_hf(repo, r.json())

        sha = ((fspec.get("blob") or {}).get("sha256")) or fspec.get("sha256") or ""
        if len(sha) != 64:
            return None
        r = c.get(f"https://civitai.com/api/v1/model-versions/by-hash/{sha}")
        if r.status_code != 200:
            return None
        version = r.json()
        model_id = version.get("modelId")
        if not model_id:
            return None
        # Second request: the permission fields exist only here
        r2 = c.get(f"https://civitai.com/api/v1/models/{model_id}")
        if r2.status_code != 200:
            return None
        return judge_civitai(version, r2.json(), kind=str(fspec.get("kind") or ""))
    except Exception:
        return None      # a site being down is not our fault, and must not fail packing
    finally:
        if own:
            c.close()


# --------------------------------------------------------------------------
# Licences on the code side (extensions / host application)
# --------------------------------------------------------------------------
#: Copyleft licences: use one, and what you build has to be released on the same terms.
#: We **do not judge whether the user is in violation** (that is between them and the
#: author, and it is not something code can decide); we only state the fact -- a
#: commercial team receiving an extension under such a licence should at least know it
#: is in there.
_COPYLEFT = frozenset({"GPL-3.0", "GPL-2.0", "AGPL-3.0", "LGPL-3.0", "GPL-3.0-only",
                       "GPL-3.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later"})

_GH_URL = re.compile(r"github\.com[:/]+([^/]+)/([^/#?\s]+?)(?:\.git)?/?$")


def github_repo_from_url(url: str) -> str:
    """Pull ``owner/repo`` out of a repository URL. Empty string if it is absent.

    Provenance on the code side is far easier than for models: ``code_deps[].repo_url``
    already records the address -- nothing to guess and nothing to reverse-look-up.
    """
    m = _GH_URL.search((url or "").strip())
    return f"{m.group(1)}/{m.group(2)}" if m else ""


def judge_code_licence(repo: str, payload: dict) -> LicenseVerdict:
    """Judge once from the code host's answer. ``payload`` = the body of
    ``GET /repos/{owner}/{repo}``.

    **One important difference from the model side: the code side does not judge
    "may this be passed on".**

    The three model tiers govern "may these bytes be served across users". Code, by
    contrast, **always travels with the nest** (the source archive is captured in full so
    that rebuilding does not depend on upstream still being alive), so it was always going
    to ship with it. What is judged here is therefore not "pass on or not" but
    **stating truthfully which licence it is under**, copyleft above all: a commercial
    team receiving such an extension should at least know it is in there.

    **We do not judge whether the user is in violation** -- that is between them and the
    author, and it is not something code can decide (which is exactly what the
    no-curation rule exists to prevent).
    """
    origin = payload.get("html_url") or (f"https://github.com/{repo}" if repo else "")
    lic = payload.get("license") or {}
    spdx = (lic.get("spdx_id") or "").strip()

    if not spdx or spdx == "NOASSERTION":
        # About a quarter of popular extensions **state no licence at all**. Saying
        # nothing does not mean "use it freely": the default is that the author keeps all
        # rights, so this case has to be spelled out rather than waved through.
        return LicenseVerdict(
            serving_scope="gated", shareable=False, tag="unknown", origin_url=origin,
            reason=(
                f"{repo} does not say what licence it is under. That does not mean it is free "
                f"to use — by default the author keeps all rights. Ask them, or leave it out."
            ),
        )
    if spdx in _COPYLEFT:
        return LicenseVerdict(
            serving_scope="private", shareable=True, spdx=spdx.lower(), tag="rail",
            origin_url=origin,
            reason=(
                f"{repo} is {spdx}. It travels with the nest, but that licence asks anything "
                f"built on it to be shared on the same terms — worth knowing before you build "
                f"a product around it."
            ),
        )
    return LicenseVerdict(
        serving_scope="private", shareable=True, spdx=spdx.lower(),
        tag="permissive" if spdx.lower() in PERMISSIVE_LICENSES else "capped",
        origin_url=origin,
        reason=f"{repo} is {spdx}.",
    )


def lookup_code_dep(dep: dict, *, client: "httpx.Client | None" = None) -> LicenseVerdict | None:
    """Look up the licence of one code dependency. ``None`` if nothing found.

    Simpler than the model side: the address is already there (``repo_url``) and one
    request is enough -- no inferring it from a cache path, no reverse lookup by hash.
    """
    import httpx as _httpx

    repo = github_repo_from_url(dep.get("repo_url") or "")
    if not repo:
        return None      # a user's own scripts live in no repository; normal, not an error
    own = client is None
    c = client or _httpx.Client(timeout=15.0, follow_redirects=True)
    try:
        r = c.get(f"https://api.github.com/repos/{repo}",
                  headers={"Accept": "application/vnd.github+json"})
        if r.status_code != 200:
            return None
        return judge_code_licence(repo, r.json())
    except Exception:
        return None
    finally:
        if own:
            c.close()
