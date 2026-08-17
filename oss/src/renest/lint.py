"""Nest format lint (`renest lint`).

Three layers: schema validation (hard fail); internal consistency (blob
conflicts, gated-asset invariants, fingerprint presence); and the blob landing
check when ``blobs_dir`` is given — ``size`` (default) / ``sample`` / ``full``,
plus the bad-bytes structure probe (:mod:`renest.integrity`), because a matching
sha256 proves the bytes did not change, never that they were ever a complete set
of weights. That probe warns unless ``--strict``: capture-side discipline is to
report, never to block.

Exit codes: clean → 0; any error → 23 (S2_HASH_MISMATCH); ``--strict`` promotes
warnings to errors; a missing schema library → 2 (USAGE). The ``--json`` shape is
frozen: ``{manifest, ok, unique_blobs, verify, checked, findings}``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import httpx

from .envlock import canonical_name
from .errors import ExitCode
from .integrity import probe_model_bytes
from .roots import MAX_MANIFEST_FILES, bad_entrypoint_env
from .syslibs import lock_requirements

#: URLs inside the lock text. Same shape as ``wheels._ANY_URL``; lint does not
#: import wheels, to keep its dependency surface thin.
_ANY_URL_IN_LOCK = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s'\"#]+")

#: The shapes a fill-this-in blank actually takes, exactly as the pack skeletons
#: emit them. **Only these count, not "it contains an angle bracket"**: this check
#: is an error, and one false positive condemns a perfectly good nest.
#: The last alternative is a Chinese placeholder word, kept because a user may
#: type it into their own spec -- recognising it is a feature, not a leftover
#: note. It is written as an escape so this file stays plain ASCII; the publish
#: gate lists this file explicitly for that reason rather than being fooled by
#: the escaping.
_PLACEHOLDER_RE = re.compile(
    "<\\s*(fill in|give it a name|your |TODO|\u5f85\u586b)", re.IGNORECASE
)

#: **Holding placeholder prose is the whole job of these keys, so never report
#: them as "left unfilled".** ``entrypoint.redactions[].placeholder`` is a
#: sentence addressed to whoever rebuilds (for example, "pick your own output
#: folder after the rebuild"), so it naturally looks like placeholder text.
_PLACEHOLDER_IS_THE_POINT = frozenset({"placeholder"})

__all__ = [
    "BLOCK",
    "Finding",
    "LintResult",
    "lint",
    "find_schema",
    "kind_advice",
    "run_from_args",
]

BLOCK = 1 << 20  # sample block size, 1 MiB


def find_schema() -> Path:
    """Locate ``manifest.schema.json``. ``RENEST_MANIFEST_SCHEMA`` overrides;
    otherwise prefer the copy force-included into the installed package
    (``renest/specs/``, see ``pyproject.toml``), falling back to the repo-relative
    ``oss/specs`` layout when running from a source checkout without a build."""
    override = os.environ.get("RENEST_MANIFEST_SCHEMA")
    if override:
        return Path(override)
    packaged = Path(__file__).resolve().parent / "specs" / "manifest.schema.json"
    if packaged.is_file():
        return packaged
    # oss/src/renest/lint.py -> parents[2] == oss/
    return Path(__file__).resolve().parents[2] / "specs" / "manifest.schema.json"


def find_pack_spec_schema() -> Path:
    """Locate ``pack-spec.schema.json``, searching in the same order as
    :func:`find_schema`."""
    override = os.environ.get("RENEST_PACK_SPEC_SCHEMA")
    if override:
        return Path(override)
    packaged = Path(__file__).resolve().parent / "specs" / "pack-spec.schema.json"
    if packaged.is_file():
        return packaged
    return Path(__file__).resolve().parents[2] / "specs" / "pack-spec.schema.json"


def kind_advice(files: object) -> list[str]:
    """Non-blocking notes about ``files[].kind`` values (empty = nothing to say).

    Since format 2.7 this field is an open string, so a wrong value can no longer be
    refused -- an open ecosystem cannot be chased with a list. One mistake still costs
    real money, though: a text encoder written as ``text_encoder`` (its ComfyUI
    *category* name) instead of ``clip`` silently loses the shared-part rule, and that
    rule is what stops one bundle's licence speaking for a base model. So the exact
    swaps we ourselves make in the capture table get a warning, and nothing else does.
    """
    from .capture import CATEGORIES
    from .licensing import SHARED_COMPONENT_KINDS

    # Category names whose asset really is a shared part: writing the category name
    # where the kind belongs is the one confusion that changes a licence outcome.
    confusable = {
        cat: kind for cat, (_dirs, kind) in CATEGORIES.items()
        if kind in SHARED_COMPONENT_KINDS and cat not in SHARED_COMPONENT_KINDS
    }
    notes = []
    for f in files if isinstance(files, list) else []:
        want = confusable.get(f.get("kind")) if isinstance(f, dict) else None
        if want:
            notes.append(
                f"{f.get('path')}: kind={f['kind']!r} is the name of a search folder, not an "
                f"asset kind. It is accepted as written, but only {want!r} carries the rule "
                f"that keeps this file's licence from speaking for the model it sits inside.")
    return notes


def validate_pack_spec(spec: dict) -> list[str]:
    """Validate a pack spec against its schema; returns a list of problems in
    plain language (empty = it passes).

    Why this exists: a misspelled enum value in a hand-written pack spec would
    otherwise blow up on a rented machine minutes later. Checking here fails on
    the local machine, before anything starts, with every legal value listed.
    """
    import jsonschema

    schema = json.loads(find_pack_spec_schema().read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    problems = []
    for e in sorted(validator.iter_errors(spec), key=lambda e: list(e.absolute_path)):
        where = ".".join(str(x) for x in e.absolute_path) or "(top level)"
        problems.append(f"{where}: {e.message}")
    return problems


@dataclass
class Finding:
    level: str  # error | warn
    code: str
    message: str

    def to_dict(self) -> dict:
        return {"level": self.level, "code": self.code, "message": self.message}


@dataclass
class LintResult:
    manifest: str
    findings: list[Finding] = field(default_factory=list)
    unique_blobs: int = 0
    verify: str = "none"
    checked: dict = field(default_factory=lambda: {"exist": 0, "size": 0, "full_hash": 0, "sampled": 0})
    strict: bool = False

    @property
    def has_error(self) -> bool:
        levels = {f.level for f in self.findings}
        return "error" in levels or (self.strict and "warn" in levels)

    @property
    def exit_code(self) -> int:
        return int(ExitCode.S2_HASH_MISMATCH) if self.has_error else int(ExitCode.OK)

    def to_dict(self) -> dict:
        return {
            "manifest": self.manifest,
            "ok": not self.has_error,
            "unique_blobs": self.unique_blobs,
            "verify": self.verify,
            "checked": self.checked,
            "findings": [f.to_dict() for f in self.findings],
        }


def _sha256_full(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_at(f, offset: int, n: int) -> bytes:
    f.seek(offset)
    return f.read(n)


def _sample_probe(path: Path, sha256: str, size: int) -> list[str]:
    """Cheap big-file probe: read head/tail/random block, report suspected
    degradation. Returns a problem list (empty = passed).

    Honest boundary: sample blocks have nothing to compare against (the manifest
    holds only the full sha256), so this catches truncation, zero-fill and
    whole-file swaps — not arbitrary tampering. Use ``full`` for that."""
    problems: list[str] = []
    with path.open("rb") as f:
        head = _read_at(f, 0, min(BLOCK, size))
        tail = _read_at(f, max(0, size - BLOCK), min(BLOCK, size))
        mid = b""
        if size > 3 * BLOCK:
            span = size - 2 * BLOCK - BLOCK
            off = BLOCK + (int(sha256[:8], 16) % max(1, span))
            mid = _read_at(f, off, BLOCK)
    for name, blk in (("head", head), ("tail", tail), ("middle", mid)):
        if blk and len(set(blk)) == 1:
            problems.append(
                f"the {name} block is dead (every byte is 0x{blk[0]:02x} — "
                f"looks zero-filled or half-downloaded)"
            )
    return problems


def lint(
    manifest_path: str | os.PathLike[str],
    *,
    blobs_dir: str | os.PathLike[str] | None = None,
    verify: str = "size",
    sample_threshold: int = 256 << 20,
    strict: bool = False,
) -> LintResult:
    """Lint a nest manifest. See module docstring for the layers and exit codes."""
    manifest_path = Path(manifest_path)
    result = LintResult(manifest=str(manifest_path), strict=strict)

    def err(code: str, msg: str) -> None:
        result.findings.append(Finding("error", code, msg))

    def warn(code: str, msg: str) -> None:
        result.findings.append(Finding("warn", code, msg))

    m = json.loads(manifest_path.read_text())

    # ---- 1. schema validation (hard fail) ----
    import jsonschema  # hard dependency; ImportError surfaces as a tool error

    schema = json.loads(find_schema().read_text())
    validator = jsonschema.Draft202012Validator(schema)
    for e in validator.iter_errors(m):
        err("schema", f"{e.json_path}: {e.message}")

    # ---- 1b. entry-count ceiling (the number and the reasoning behind it live
    #          on roots.MAX_MANIFEST_FILES) ----
    _n = len(m.get("files") or [])
    if _n > MAX_MANIFEST_FILES:
        err("too-many-files",
            f"this nest lists {_n} files; we stop at {MAX_MANIFEST_FILES}. "
            f"Split it into more than one nest.")

    # ---- 2. internal consistency ----
    seen: dict[str, int] = {}  # hash -> size

    def walk(o) -> None:
        if isinstance(o, dict):
            if set(o) >= {"sha256", "size_bytes"}:
                h, s = o["sha256"], o["size_bytes"]
                if h in seen and seen[h] != s:
                    err(
                        "blob-conflict",
                        f"blob {h[:12]}… is declared with two different sizes: {seen[h]} vs {s}",
                    )
                seen[h] = s
            for x in o.values():
                walk(x)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(m)

    # ---- 2a. Warn when information is missing, reject placeholder text ----
    #
    # Which container image this ran on and the dependency lockfile are optional,
    # because the packing side cannot always find them out: the schema tolerates
    # absence and lint names what is missing, with no completeness flag invented
    # for it. Placeholder text, by contrast, is an error -- an absent field is
    # honest, placeholder text pretends the field was filled in.
    if not m.get("base_image"):
        warn("base-image-missing",
             "this nest doesn't say which container image it was built on. That is allowed "
             "(a container often cannot see its own image name) and rebuilding never needed "
             "it — but whoever rebuilds loses the one clue about the system layer underneath.")
    if not (m.get("python_lock") or {}).get("lockfile"):
        warn("lockfile-missing",
             "this nest carries no dependency lockfile, so the Python environment cannot be "
             "rebuilt from it. Pack again from that machine with --env-python pointing at the "
             "interpreter the app starts with, and the package list gets read off it directly.")

    # Format 2.6. A recipe with no record of where it lived is restorable but not
    # usable: the restore side is forbidden to invent a path, so it parks the file in
    # a staging folder and the app never sees it.
    _cui = (m.get("adapters") or {}).get("comfyui") or {}
    if _cui.get("workflow") and not _cui.get("workflow_path"):
        warn("workflow-path-missing",
             "this nest carries a recipe but does not record where it used to live, so "
             "restoring it leaves the file in a staging folder instead of where the app "
             "looks. Nests packed before format 2.6 are all like this; a fresh pack fixes it.")
    # Format 2.7: kind is an open string, so nothing here refuses an unfamiliar
    # value. The one confusion that changes a licence outcome still gets said out loud.
    for note in kind_advice(m.get("files")):
        warn("kind-is-a-folder-name", note)
    _nl = (m.get("runtime") or {}).get("native_libs") or {}
    if _nl and not _nl.get("names"):
        warn("native-libs-empty",
             "this nest says how it collected the operating-system libraries its run "
             "needed, and then lists none. Collecting nothing means writing nothing: an "
             "empty list reads as 'this run needed no libraries from the machine', which "
             "is a claim, not an absence.")
    # Format 2.8: contested modules. The schema holds the shape (the fingerprint
    # must be 64 lower-case hex characters, the method one of two words); this is
    # the one relation the schema cannot say. The winner is what a restore
    # reinstalls, so a winner outside the candidate list would reinstall a
    # package that never wrote that folder -- and change nothing.
    _cm = [e for e in ((m.get("runtime") or {}).get("contested_modules") or [])
           if isinstance(e, dict)]
    for _i, _e in enumerate(_cm):
        _cands = [c for c in (_e.get("candidates") or []) if isinstance(c, str)]
        if _e.get("winner") not in _cands:
            err("contested-winner-not-a-candidate",
                f"runtime.contested_modules[{_i}] ({_e.get('module')}): the winner "
                f"{_e.get('winner')!r} is not one of the candidates {_cands}. A restore "
                f"reinstalls the winner to make it write last; a package that never wrote "
                f"this folder cannot be that.")

    # Cross-field checks the schema cannot express (format 2.4). The writing side
    # already gets these right; this catches nests built by anything else.
    gpu = m.get("gpu") or {}
    cards = gpu.get("device_count")
    if "peer_access" in gpu and not (isinstance(cards, int) and cards > 1):
        err("peer-access-without-cards",
            "this nest says whether its GPUs could reach each other, but does not say there "
            "was more than one GPU. On a single card that answer means nothing, and a reader "
            "may take it as proof the cards were linked. Record the card count too, or drop "
            "the answer.")
    use = gpu.get("observed_use") or {}
    if use and int(use.get("samples") or 0) <= 2:
        warn("observed-use-from-too-few-readings",
             f"the video-memory figure here rests on {use.get('samples')} reading(s), which is "
             f"too few to mean much: a run that crashed before touching the card reads as "
             f"almost no memory at all. Keep the figure, but treat it as a hint, not a floor.")
    base = (m.get("derived_from") or {})
    if base and not base.get("nest_id"):
        err("derived-from-without-parent",
            "this nest says it came from another one but does not name which. A parent "
            "without an identifier cannot be resolved to bytes.")

    def _placeholders(node, where: str) -> list[str]:
        """Find every place that still holds a fill-this-in blank.

        Only the shapes the pack skeletons actually emit count, not "the string
        contains an angle bracket": the looser test fires on shell redirections
        and on mathematical symbols in licence notes, and since this check is an
        error, **one false positive condemns a perfectly good nest**.
        """
        if isinstance(node, str):
            return [f"{where} = {node.strip()[:60]}"] if _PLACEHOLDER_RE.search(node) else []
        if isinstance(node, dict):
            return [
                x
                for k, v in node.items()
                if k not in _PLACEHOLDER_IS_THE_POINT
                for x in _placeholders(v, f"{where}.{k}")
            ]
        if isinstance(node, list):
            return [x for i, v in enumerate(node) for x in _placeholders(v, f"{where}[{i}]")]
        return []

    for _hit in _placeholders(m, "manifest"):
        err("placeholder-left-in",
            "a fill-in-yourself placeholder was left in the manifest — a nest packed like "
            f"that looks finished and is not: {_hit}. Leave the field out instead: from "
            "format 2.3 on, 'we could not find this out' is written by omitting the field, "
            "never by writing a placeholder into it.")

    # ---- 2b. Semantic checks on the fields format 2.2 added. The schema only
    #          governs shape; this section governs whether the values make
    #          sense together. ----
    _lic_text_hashes = {
        f["blob"]["sha256"]
        for f in m.get("files", [])
        if f.get("kind") == "license_text" and isinstance(f.get("blob"), dict)
    }
    for f in m.get("files", []):
        lic2 = f.get("license", {}) or {}
        # (1) Claiming "this was detected" means being able to say what was
        #     detected; otherwise the marker says nothing at all.
        if lic2.get("declared_by") == "detected" and not (lic2.get("spdx") or f.get("origin_url")):
            warn("declared-by-empty",
                 f"license says it was detected but names neither a licence nor a source: {f['path']}")
        # (2) The two restriction shapes only mean anything on a file that is
        #     actually restricted.
        if lic2.get("gated_form") in ("auto", "manual") and lic2.get("serving_scope") != "gated":
            err("gated-form-mismatch",
                f"gated_form={lic2['gated_form']} but serving_scope is "
                f"{lic2.get('serving_scope')!r} — those two disagree: {f['path']}")
        # (3) The licence text has to really be inside the nest; pointing at a
        #     file that is not there is the same as not carrying it.
        tx = lic2.get("text")
        if isinstance(tx, dict) and tx.get("sha256") and tx["sha256"] not in _lic_text_hashes:
            err("licence-text-missing",
                "license.text points at bytes that are not in this nest as a "
                f"kind=license_text file: {f['path']}")

    for c in m.get("code_deps", []):
        um = c.get("upstream_match") or {}
        # (4) Saying "this was modified" means saying how many places changed;
        #     any other state should not carry that count at all.
        if um.get("state") == "modified" and not um.get("changed_files"):
            warn("upstream-modified-count",
                 f"{c.get('name')} is marked as changed from upstream but says nothing about "
                 f"how much — the recipient cannot tell a typo from a rewrite")
        if um.get("state") in ("clean", "no_upstream") and um.get("changed_files"):
            err("upstream-count-mismatch",
                f"{c.get('name')} says {um['state']} yet reports "
                f"{um['changed_files']} change(s) — those two disagree")
        # (5) Naming an upstream identity while claiming to live in no
        #     repository at all contradicts itself.
        if um.get("state") == "no_upstream" and (c.get("repo_url") or c.get("commit")):
            err("upstream-contradiction",
                f"{c.get('name')} says it has no upstream, but names a repo or commit")

    for f in m.get("files", []):
        lic = f.get("license", {})
        if not lic.get("shareable", True) and not (f.get("origin_url") or lic.get("note")):
            err(
                "share-hint",
                "this file cannot be handed off and gives no way to get it "
                f"(needs origin_url or license.note): {f['path']}",
            )
        # Gated bytes never cross users -> must be shareable=false, must carry an origin
        if lic.get("serving_scope") == "gated":
            if lic.get("shareable"):
                err(
                    "serving-scope",
                    "a gated file must not be shareable=true — gated bytes are never "
                    f"served to anyone but you: {f['path']}",
                )
            if not f.get("origin_url"):
                # **A warning, not an error** (2026-08-11, decided after a real run).
                # Measured: a nest where eight files landed here restored perfectly and
                # drew a byte-identical image -- because the owner's own drive serves the
                # owner's own bytes. So this is not "cannot be rebuilt"; it is "cannot be
                # passed on". Calling it a failure sent the owner hunting for a problem
                # they did not have. The message has to carry the whole chain: licence
                # unconfirmed -> we may not pass the bytes on -> the other person has to
                # find the file themselves.
                warn(
                    "gated-origin",
                    "we could not confirm this file's licence, so it is treated as "
                    "restricted and we will not pass its bytes on for you. **Restoring it "
                    "yourself is unaffected** — those bytes come from your own drive. But "
                    "if you hand this nest to someone else, they will have to find this "
                    f"file themselves: {f['path']}. Recording origin_url turns that hunt "
                    "into a link.",
                )

    # ---- A snapshots/ entry obliges a refs/ pointer for the same repository ----
    #
    # refs/<branch> is a 40-byte file holding the commit hash. Without it, naming
    # a model by repository name with no revision pinned cannot be resolved
    # offline -- and it surfaces as "We couldn't connect to huggingface.co", so
    # the user blames their connection and never reaches the real cause. A failure
    # that misdirects that badly has to be stopped at pack time.
    _snap_repos: dict[str, str] = {}  # models--X dir -> first path seen (for the message)
    _ref_repos: set[str] = set()
    for f in m.get("files", []):
        if not isinstance(f, dict) or f.get("root") != "hf_hub":
            continue
        p = f.get("path")
        if not isinstance(p, str):
            continue
        head, _, rest = p.partition("/")
        if not head.startswith("models--"):
            continue
        if rest.startswith("snapshots/"):
            _snap_repos.setdefault(head, p)
        elif rest.startswith("refs/"):
            _ref_repos.add(head)
    for repo_dir in sorted(_snap_repos):
        if repo_dir in _ref_repos:
            continue
        repo_id = repo_dir[len("models--"):].replace("--", "/")
        err(
            "hf-missing-ref",
            f"This nest has model files for {repo_id} but not the small refs/<branch> "
            "pointer that names which version they are. Without it, anything that loads "
            "the model by name will fail on a machine with no internet — and it reports "
            "itself as a network error, which is very hard to work out. Re-pack after a "
            "run that worked.",
        )

    # Path-shaped keys in entrypoint.env must stay inside the rebuild folder.
    # This is pinned down before anything consumes the field, deliberately:
    # adding the constraint after a consumer exists would be a breaking change,
    # and an LD_LIBRARY_PATH that can point at a .so carried inside the nest is
    # a library-hijack entry point.
    for why in bad_entrypoint_env((m.get("entrypoint") or {}).get("env")):
        err("entrypoint-env", f"this nest's start-up settings put something where it does not belong: {why}")

    # Landing-path safety, raised earlier than the restore side's own rejection.
    # An absolute path overrides the rebuild root and ".." climbs out of it --
    # both are attack surface once a nest is handed to someone else.
    # **Every root, without exception**: the tail of the hf_hub pattern,
    # `snapshots/<40hex>/.+`, accommodates ".." quite happily on its own.
    for p in [f.get("path") for f in m.get("files", []) if isinstance(f, dict)] + [
        d.get("install_path") for d in m.get("code_deps", []) if isinstance(d, dict)
    ]:
        if isinstance(p, str) and p:
            pp = PurePosixPath(p.replace("\\", "/"))
            if pp.is_absolute() or ".." in pp.parts or p.startswith("~"):
                err(
                    "path-escape",
                    f"this file lands outside the rebuild folder (absolute path or ..): {p}",
                )

    # Pairs of paths that would overwrite each other on a case-insensitive
    # volume (an SMB/CIFS mount, the default macOS volume). Both files report a
    # successful restore, the final verification then fails with a message
    # nobody can make sense of, so name the pair up front.
    lowered: dict[str, str] = {}
    for f in m.get("files", []):
        p = f.get("path") if isinstance(f, dict) else None
        if isinstance(p, str):
            key = p.lower()
            if key in lowered and lowered[key] != p:
                warn(
                    "case-collision",
                    "two paths differ only in upper/lower case and will overwrite each "
                    f"other on drives that ignore case: {lowered[key]} vs {p}",
                )
            else:
                lowered.setdefault(key, p)

    # Format 1.3: gpu.node_native_archs[].code_dep must name a code_deps[].name
    # that actually exists. The entry records which node a retained vendored
    # .so belongs to, so a dangling reference means the packing side's ledger
    # is wrong.
    dep_names = {d.get("name") for d in m.get("code_deps", [])}
    for na in m.get("gpu", {}).get("node_native_archs", []):
        if na.get("code_dep") not in dep_names:
            warn(
                "node-arch-orphan",
                "gpu.node_native_archs points at a code_deps entry that does not exist: "
                f"{na.get('code_dep')!r}",
            )

    # The fingerprint is a pre-restore success predictor: absent is not a
    # violation, but it does leave the recipient guessing.
    if "fingerprint" not in m:
        warn(
            "no-fingerprint",
            "no record of the machine this was packed on, so there is no way to tell "
            "in advance whether another machine can rebuild it. Pack again to record one.",
        )

    # Blobs are content-addressed: the filename is the hash and there is no
    # extension. The bad-bytes health check needs the **logical path** both to
    # pick the right structure to look for and to say something a human can
    # read, so build a hash -> manifest path map first.
    blob_names: dict[str, str] = {}
    for f in m.get("files", []):
        blob = f.get("blob")
        if isinstance(blob, dict) and isinstance(blob.get("sha256"), str) and f.get("path"):
            blob_names.setdefault(blob["sha256"], f["path"])

    # ---- 3. blob landing check ----
    result.unique_blobs = len(seen)
    result.verify = verify if blobs_dir else "none"
    if blobs_dir:
        base = Path(blobs_dir)
        for h, s in seen.items():
            p = base / h[:2] / h
            if not p.exists():
                err("blob-missing", f"blob {h[:12]}… is not in storage")
                continue
            result.checked["exist"] += 1
            actual = p.stat().st_size
            if actual != s:
                err(
                    "blob-size",
                    f"blob {h[:12]}… is the wrong size: declared {s} bytes, stored {actual}",
                )
                continue
            result.checked["size"] += 1
            # Bad-bytes structure check: a blob can match its sha256 and size and
            # still have been bad bytes when stored (a half-downloaded weights
            # file, or an LFS pointer posing as a model). Warns rather than blocks
            # unless --strict; the tool does not decide for the user.
            bad = probe_model_bytes(p, s, logical_name=blob_names.get(h))
            if bad:
                warn("model-integrity", f"{bad} (blob {h[:12]}…)")
            if verify == "full" or (verify == "sample" and s <= sample_threshold):
                got = _sha256_full(p)
                if got != h:
                    err(
                        "blob-hash",
                        f"blob {h[:12]}… holds the wrong bytes: expected sha256 {h}, got {got}",
                    )
                else:
                    result.checked["full_hash"] += 1
            elif verify == "sample":
                for prob in _sample_probe(p, h, s):
                    err("blob-sample", f"blob {h[:12]}… spot check: {prob}")
                result.checked["sampled"] += 1

        # ---- 4. Spot-check that pinned wheel URLs are still reachable ----
        #
        # This lock only rebuilds while its wheel host stays alive, so HEAD the
        # first few pinned URLs: 404/410 means the host dropped them, and knowing
        # now still leaves time to re-pack. Warn level, never blocking, and a
        # connection failure skips the section by design -- only the host saying
        # "gone" counts, so a network-less environment still passes.
        lock_blob = (m.get("python_lock") or {}).get("lockfile") or {}
        lock_path = base / str(lock_blob.get("sha256", ""))[:2] / str(lock_blob.get("sha256", ""))
        if lock_blob.get("sha256") and lock_path.exists():
            # Format 2.8: every candidate of a contested module must be a package
            # this lock installs -- the field describes a contest between packages
            # in the lock, and a name outside it describes nothing.
            _in_lock = {n for n, _ in lock_requirements(lock_path.read_text(errors="replace"))}
            for _i, _e in enumerate(_cm):
                for _c in (_e.get("candidates") or []):
                    if isinstance(_c, str) and canonical_name(_c) not in _in_lock:
                        err("contested-candidate-not-in-lock",
                            f"runtime.contested_modules[{_i}] ({_e.get('module')}): candidate "
                            f"{_c!r} is not in this nest's dependency lock, so it cannot be "
                            f"one of the packages competing for that folder.")
            wheel_urls = [
                u for u in _ANY_URL_IN_LOCK.findall(lock_path.read_text(errors="replace"))
                if u.endswith(".whl")
            ]
            # A spot check, not an audit: confirming the host is still alive
            # does not need every URL tried.
            for u in wheel_urls[:3]:
                try:
                    code = httpx.head(u, follow_redirects=True, timeout=4.0).status_code
                except httpx.HTTPError:
                    break  # offline or unreachable: skip the section, do not guess
                if code in (404, 410):
                    warn(
                        "wheel-url-dead",
                        f"a pinned wheel URL answers HTTP {code} — the host this lock "
                        f"depends on has dropped it ({u[:90]}…). Re-pack while the "
                        f"environment still exists; a restore will die at the "
                        f"dependency step.",
                    )

    return result


def print_human(result: LintResult, stream) -> None:
    for x in result.findings:
        prefix = "✗ " if x.level == "error" else "⚠ "
        print(prefix + f"[{x.code}] {x.message}", file=stream)
    tail = f"({result.unique_blobs} unique blobs"
    if result.verify != "none":
        c = result.checked
        tail += (
            f"; checked {result.verify}: {c['full_hash']} byte-checked, "
            f"{c['sampled']} spot-checked, {c['size']} size-checked"
        )
    tail += ")"
    verdict = "✗ Failed" if result.has_error else "✓ Passed"
    print(f"{verdict}: {result.manifest} {tail}", file=stream)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("manifest", help="path to manifest.json")
    parser.add_argument(
        "--blobs",
        help="local blobs folder (each file sits at <first 2 chars of its sha256>/<sha256>)",
    )
    parser.add_argument(
        "--depth",
        choices=["size", "sample", "full"],
        default="size",
        help="how closely to check the stored files",
    )
    parser.add_argument("--sample-threshold", type=int, default=256 << 20)
    parser.add_argument("--strict", action="store_true", help="treat warnings as failures")


def run_from_args(args: argparse.Namespace, emitter) -> int:
    import sys

    try:
        result = lint(
            args.manifest,
            blobs_dir=args.blobs,
            verify=args.depth,
            sample_threshold=args.sample_threshold,
            strict=args.strict,
        )
    except ImportError:
        print("✗ jsonschema is not installed, so the format cannot be checked.", file=sys.stderr)
        return int(ExitCode.USAGE)
    except (OSError, json.JSONDecodeError) as e:
        print(f"✗ Cannot read the manifest: {e}", file=sys.stderr)
        return int(ExitCode.USAGE)
    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print_human(result, sys.stderr)
    return result.exit_code
