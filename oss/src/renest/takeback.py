"""Take a saved workflow back into the ComfyUI it came from (the panel's "Take back").

Ruled 2026-10-19: a workflow saved from the panel is an ordinary nest. This module is
the **other way of using one**: not a rebuild on another machine (``renest restore``),
but putting the workflow and its files back into a ComfyUI that is already running,
and saying, as plain facts, what changed since it was saved.

Three rules, each with a test:

* **Facts only.** The report says ``unchanged`` / ``changed`` (then → now) /
  ``missing`` (what it was, where it came from). It never says compatible, never
  recommends a version or a replacement, never installs a custom node.
* **Never overwrite the person's files.** A file already at the landing path with
  different bytes stays; ours lands beside it under ``.renest/kept/`` and the report
  names it. Same bytes → skipped. Absent → fetched, checked byte for byte, moved in.
* **Never write outside the ComfyUI tree** (``.renest/incoming``, ``.renest/kept`` and
  the landing paths, all under the environment root). ``root: home`` entries land under
  ``<root>/.renest/home/`` like a restore's, and the home folder is not touched.
* **The same landing gate as a restore.** Every ``files[]`` entry passes
  :func:`renest.roots.bad_root_entry` first: a path into ``site-packages``, ``venv``,
  ``bin``, ``custom_nodes/.../*.py`` or any other place where a file gets *run* is refused,
  not placed. A nest can come from a hand-off, and a take-back that laid down a ``.pth``
  would run someone else's code at the next interpreter start (independent security review,
  2026-10-19).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable

import httpx

from .download import BlobSpec, SourcesExhausted, resolve, sources_from_urls
from .envlock import freeze_environment
from .integrity import git_identity, registry_identity
from .restore import place_sidebar_workflow, sidebar_workflow_name
from .roots import bad_root_entry, unsafe_relpath

__all__ = [
    "FORBIDDEN_WORDS",
    "TakebackReport",
    "compare",
    "fetch",
    "live_environment",
]

#: Words a report may never contain. A test scans the JSON and the panel's strings.
FORBIDDEN_WORDS = ("compatible", "incompatible", "should work", "will work", "recommend")

#: Everything of ours lands under the ComfyUI folder itself, never beside it: a ComfyUI
#: kept at ~/ComfyUI has the home folder as its environment root, and a take-back that
#: wrote ``.renest/`` or ``RECIPES/`` there wrote into the person's home (real-stack
#: acceptance, 2026-10-19).
INCOMING_REL = Path(".renest") / "incoming"
KEPT_REL = Path(".renest") / "kept"
STAGED_REL = Path(".renest") / "takeback"
HOME_REL = Path(".renest") / "home"

#: Packages whose version difference is always shown on its own line.
_ALWAYS_SHOWN = ("torch", "torchvision", "torchaudio", "xformers", "triton", "numpy")


@dataclass
class TakebackReport:
    comfyui: dict = field(default_factory=dict)
    python: dict = field(default_factory=dict)
    packages: dict = field(default_factory=dict)
    node_packs: list[dict] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)
    gpu: dict = field(default_factory=dict)
    counts: dict = field(default_factory=dict)
    #: Entries the landing gate refused (a path that would be run as code, a climb out
    #: of the tree). Listed so the panel can say so; never placed.
    refused: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "comfyui": self.comfyui, "python": self.python, "packages": self.packages,
            "node_packs": self.node_packs, "files": self.files, "gpu": self.gpu,
            "counts": self.counts, "refused": self.refused,
        }


# ----------------------------------------------------------------------------
# what this machine looks like right now
# ----------------------------------------------------------------------------
def live_environment(comfyui_dir: Path, env_python: str | None,
                     node_owners: dict | None = None) -> dict:
    """The facts a comparison needs, read off this machine. Anything unreadable is
    left out, and the report then says "not recorded" rather than guessing."""
    out: dict[str, Any] = {}
    ident = git_identity(comfyui_dir)
    if ident:
        out["comfyui"] = {"commit": ident.get("commit"), "repo_url": ident.get("repo_url")}
    if env_python:
        try:
            import subprocess

            r = subprocess.run([str(env_python), "-c", "import sys;print(sys.version.split()[0])"],
                               capture_output=True, text=True, timeout=20)
            if r.returncode == 0 and r.stdout.strip():
                out["python_version"] = r.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
        frozen = freeze_environment(env_python)
        if frozen:
            out["packages"] = _parse_freeze(frozen)
    out["node_dirs"] = _node_dirs(comfyui_dir)
    try:
        from .doctor import collect_gpu_name

        name = collect_gpu_name()
        if name:
            out["gpu_name"] = name
    except Exception:
        pass
    if isinstance(node_owners, dict):
        out["node_owners"] = {k: v for k, v in node_owners.items()
                              if isinstance(k, str) and isinstance(v, dict)}
    return out


def _node_dirs(comfyui_dir: Path) -> dict[str, dict]:
    """Every custom node folder here and how it identifies itself (git, then registry)."""
    out: dict[str, dict] = {}
    base = comfyui_dir / "custom_nodes"
    if not base.is_dir():
        return out
    for d in sorted(base.iterdir()):
        if not d.is_dir() or d.name.startswith((".", "__")):
            continue
        ident = git_identity(d) or registry_identity(d) or {}
        out[d.name] = {k: ident.get(k) for k in ("repo_url", "commit", "version") if ident.get(k)}
    return out


_WHEEL_VERSION = re.compile(r"^[A-Za-z0-9_.]+-([0-9][^-]*)-")


def _parse_freeze(text: str) -> dict[str, str]:
    """``name -> version`` from a lock or a freeze. Only the version is kept: the
    ``--hash=…`` tail, an environment marker after ``;`` and a line continuation are not
    part of the version, and reading them as such reported every pinned package as
    "changed" against itself (real-stack acceptance, 2026-10-19). A ``name @ <url>`` line
    gets its version from the wheel's file name when it has one, else the address."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip().rstrip("\\").strip()
        if not line or line.startswith(("#", "-")):
            continue
        line = line.split(" --hash", 1)[0].split(" ;", 1)[0].split(";", 1)[0].strip()
        if "==" in line:
            name, _, ver = line.partition("==")
            out[name.strip().lower().replace("_", "-")] = ver.strip()
        elif " @ " in line:
            name, _, url = line.partition(" @ ")
            fname = urllib.parse.unquote(url.strip().split("#", 1)[0].rsplit("/", 1)[-1])
            m = _WHEEL_VERSION.match(fname)
            out[name.strip().lower().replace("_", "-")] = m.group(1) if m else url.strip()
    return out


# ----------------------------------------------------------------------------
# compare: the nest as saved vs this machine now
# ----------------------------------------------------------------------------
def compare(manifest: dict, comfyui_dir: Path, live: dict, *,
            hash_cache: Any = None, lock_text: str | None = None,
            blobmap: dict[str, list[str]] | None = None) -> TakebackReport:
    """Facts only. ``lock_text`` is the nest's own lock, when the caller fetched it;
    ``blobmap`` is what the drive hands out -- a missing file with no link is reported
    as ``withheld`` right here, so the panel never promises to fetch it."""
    rep = TakebackReport()
    root = comfyui_dir.parent

    # -- ComfyUI itself -------------------------------------------------------
    host = next((d for d in manifest.get("code_deps") or [] if d.get("role") == "host"), None)
    then_commit = (host or {}).get("commit")
    now_commit = (live.get("comfyui") or {}).get("commit")
    rep.comfyui = _fact(then_commit, now_commit, extra={"repo_url": (host or {}).get("repo_url")})

    # -- Python -------------------------------------------------------------
    rep.python = _fact((manifest.get("runtime") or {}).get("python_version"),
                       live.get("python_version"))

    # -- packages ---------------------------------------------------------------
    then_pkgs = _parse_freeze(lock_text) if lock_text else None
    now_pkgs = live.get("packages")
    if then_pkgs is None or now_pkgs is None:
        rep.packages = {"state": "not_recorded",
                        "why": "no dependency list to compare" if then_pkgs is None
                        else "this machine's packages could not be read"}
    else:
        changed, added, removed = [], [], []
        for name, then_v in sorted(then_pkgs.items()):
            now_v = now_pkgs.get(name)
            if now_v is None:
                removed.append({"name": name, "then": then_v})
            elif now_v != then_v:
                changed.append({"name": name, "then": then_v, "now": now_v})
        for name, now_v in sorted(now_pkgs.items()):
            if name not in then_pkgs:
                added.append({"name": name, "now": now_v})
        shown = [c for c in changed if c["name"] in _ALWAYS_SHOWN]
        rep.packages = {
            "state": "unchanged" if not (changed or added or removed) else "changed",
            "shown": shown,
            "other_changed": len(changed) - len(shown),
            "added": len(added), "removed": len(removed),
            "all_changed": changed, "all_added": added, "all_removed": removed,
        }

    # -- node packs -------------------------------------------------------------
    now_dirs: dict[str, dict] = live.get("node_dirs") or {}
    for dep in manifest.get("code_deps") or []:
        if dep.get("role") != "extension":
            continue
        name = PurePosixPath(str(dep.get("install_path") or dep.get("name") or "")).name
        then = {k: dep.get(k) for k in ("repo_url", "commit") if dep.get(k)}
        now = now_dirs.get(name)
        entry: dict[str, Any] = {"dir": name, "then": then}
        if now is None:
            entry["state"] = "missing"
        else:
            entry["now"] = now
            same = bool(then.get("commit")) and then.get("commit") == now.get("commit")
            entry["state"] = "unchanged" if same else (
                "changed" if (then.get("commit") or now.get("commit")) else "present")
        rep.node_packs.append(entry)
    # node types the workflow uses, as the running app reports their owners now
    owners = live.get("node_owners")
    if isinstance(owners, dict):
        for entry in rep.node_packs:
            provided = sorted(cls for cls, info in owners.items()
                              if isinstance(info, dict) and info.get("dir") == entry["dir"])
            entry["node_types_provided_now"] = len(provided)

    # -- files ----------------------------------------------------------------------
    counts = {"unchanged": 0, "missing": 0, "different_here": 0, "withheld": 0}
    # outside_app / not_placeable entries are listed but not counted: they are not files
    # the person had, so they are neither "missing" here nor anything to bring back.
    for f in manifest.get("files") or []:
        if not isinstance(f, dict) or f.get("kind") == "input_asset":
            continue
        rel = str(f.get("path") or "")
        blob = f.get("blob") or {}
        sha, size = str(blob.get("sha256") or ""), int(blob.get("size_bytes") or 0)
        entry: dict[str, Any] = {"path": rel, "root": f.get("root") or "env", "sha256": sha,
                                 "size_bytes": size, "kind": f.get("kind") or "other"}
        why = refusal_for(f)
        if why is not None:
            entry["state"] = "refused"
            entry["why"] = why
            rep.files.append(entry)
            rep.refused.append(entry)
            continue
        dest = _landing(root, f, comfyui_dir)
        if dest is None and f.get("kind") == "workflow" and _landing(root, f) is not None:
            # The editor-form workflow travels beside the app; it is wanted for the
            # sidebar, so it is fetched into the app's own staging rather than skipped.
            entry["state"] = "sidebar_workflow"
            entry["staged"] = True
        elif dest is None:
            entry["state"] = "outside_app" if _landing(root, f) is not None else "not_placeable"
            rep.files.append(entry)
            continue
        elif dest is not None and dest.is_file():
            have = _sha256_of(dest, hash_cache)
            if have == sha:
                entry["state"] = "unchanged"
            else:
                entry["state"] = "different_here"
                entry["sha256_here"] = have
                if blobmap is not None and not blobmap.get(sha):
                    # Ours is not handed out, so "ours lands beside it" would be a
                    # promise fetch cannot keep (real-stack acceptance, 2026-10-19).
                    entry["state"] = "withheld"
                    if f.get("origin_url"):
                        entry["origin_url"] = f["origin_url"]
        else:
            entry["state"] = "missing"
            if blobmap is not None and not blobmap.get(sha):
                entry["state"] = "withheld"
            if f.get("origin_url"):
                entry["origin_url"] = f["origin_url"]
        if not entry.get("staged"):
            counts[entry["state"]] = counts.get(entry["state"], 0) + 1
        rep.files.append(entry)
    rep.counts = counts

    # -- gpu ------------------------------------------------------------------------
    then_gpu = ((manifest.get("gpu") or {}).get("cards") or [{}])[0].get("name") \
        if isinstance((manifest.get("gpu") or {}).get("cards"), list) else \
        (manifest.get("runtime") or {}).get("gpu_model")
    rep.gpu = _fact(then_gpu, live.get("gpu_name"))
    return rep


def _fact(then: Any, now: Any, extra: dict | None = None) -> dict:
    out: dict[str, Any] = {"then": then, "now": now}
    if then is None or now is None:
        out["state"] = "not_recorded"
    else:
        out["state"] = "unchanged" if then == now else "changed"
    for k, v in (extra or {}).items():
        if v:
            out[k] = v
    return out


def refusal_for(entry: dict) -> str | None:
    """Why this ``files[]`` entry may not be placed by a take-back: the restore's own
    landing gate (root known, path relative and inside its root, allowlisted shape for the
    cache roots, and **never a position that gets executed as code**)."""
    return bad_root_entry(entry)


def _landing(root: Path, entry: dict, comfyui_dir: Path | None = None) -> Path | None:
    """Where this files[] entry sits on this machine.

    Always inside ``root``; and when ``comfyui_dir`` is given, always inside **that**:
    an entry that would land beside the app (the nest's own escape hatch, licence texts,
    ``RECIPES/``) answers ``None`` -- those are not the person's files and a take-back
    has no business writing next to their ComfyUI. The ``home`` and cache roots land under
    the app's own ``.renest/home``. ``..`` is judged after backslashes are read as
    separators, so a Windows-spelled climb does not slip through."""
    rel = str(entry.get("path") or "")
    if not rel or unsafe_relpath(rel):
        return None
    rel = rel.replace("\\", "/")
    where = str(entry.get("root") or "env")
    inside = comfyui_dir if comfyui_dir is not None else root
    if where == "env":
        base = root
    elif where == "home":
        base = inside / HOME_REL
    else:
        base = inside / HOME_REL / where
    dest = (base / PurePosixPath(rel)).resolve()
    try:
        dest.relative_to(inside.resolve())
    except ValueError:
        return None
    return dest


def _inside_app(comfyui_dir: Path, rel: str) -> PurePosixPath:
    """A manifest path relative to the environment root, with the app folder's own name
    taken off the front: ``.renest/kept/models/x`` rather than ``.renest/kept/ComfyUI/models/x``."""
    parts = PurePosixPath(rel).parts
    if parts and parts[0] == comfyui_dir.name:
        parts = parts[1:]
    return PurePosixPath(*parts) if parts else PurePosixPath(rel)


def _under(comfyui_dir: Path, candidate: Path) -> Path | None:
    """``candidate`` resolved, or ``None`` when it is not inside the app folder. The same
    containment check ``_landing`` makes, applied again to the kept and staging paths
    (defence in depth, independent security review 2026-10-19)."""
    dest = candidate.resolve()
    try:
        dest.relative_to(comfyui_dir.resolve())
    except ValueError:
        return None
    return dest


def _sha256_of(path: Path, cache: Any = None) -> str:
    st = path.stat()
    if cache is not None:
        hit = cache.lookup(path, st)
        if hit:
            return hit
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    digest = h.hexdigest()
    if cache is not None:
        cache.remember(path, st, digest)
    return digest


# ----------------------------------------------------------------------------
# fetch: bring the missing files back, never overwrite
# ----------------------------------------------------------------------------
def fetch(manifest: dict, blobmap: dict[str, list[str]], comfyui_dir: Path,
          report: TakebackReport, *, client: httpx.Client | None = None,
          say: Callable[[str], None] | None = None, emitter: Any = None) -> dict:
    """Fetch every ``missing`` file in ``report`` and put it where it belongs; for a
    ``different_here`` file fetch ours into ``.renest/kept/<path>`` and leave theirs.
    Returns the outcome counts plus the list of what landed where."""
    root = comfyui_dir.parent
    incoming = comfyui_dir / INCOMING_REL
    incoming.mkdir(parents=True, exist_ok=True)
    staged_workflow: Path | None = None
    # A fetch that was killed mid-way leaves its half file here, and nothing else ever
    # looks (real-stack acceptance, 2026-10-19: 1.26 GB sat under the ComfyUI folder of
    # a person who wanted that disk back). Every fetch starts by clearing what an
    # earlier one left; there is no resume, so a part file is worth nothing.
    stale = 0
    for leftover in incoming.glob("*.part"):
        try:
            leftover.unlink()
            stale += 1
        except OSError:
            pass
    if stale:
        say(f"Cleared {stale} half-fetched file(s) an earlier take-back left behind")
    workflow_here: Path | None = None
    say = say or (lambda _m: None)
    out = {"fetched": 0, "already_here": 0, "kept_yours": 0, "withheld": 0, "failed": 0,
           "landed": [], "withheld_files": [], "failed_files": []}
    by_path = {f.get("path"): f for f in manifest.get("files") or [] if isinstance(f, dict)}
    own_client = client is None
    client = client or httpx.Client(follow_redirects=True)
    try:
        for entry in report.files:
            state = entry.get("state")
            if state == "unchanged":
                out["already_here"] += 1
                continue
            if state == "sidebar_workflow":
                state = "missing"
            if state == "refused" or refusal_for(by_path.get(entry["path"]) or {}) is not None:
                # Belt and braces: a report row the gate refused (or one handed in from
                # elsewhere) never reaches the disk.
                continue
            if state == "withheld":
                f = by_path.get(entry["path"]) or {}
                out["withheld"] += 1
                out["withheld_files"].append({"path": entry["path"],
                                              "origin_url": f.get("origin_url")})
                continue
            if state not in ("missing", "different_here"):
                continue
            f = by_path.get(entry["path"]) or {}
            sha = entry["sha256"]
            urls = blobmap.get(sha) or []
            if not urls:
                out["withheld"] += 1
                out["withheld_files"].append({"path": entry["path"],
                                              "origin_url": f.get("origin_url")})
                say(f"{entry['path']}: not handed out by the drive; get it yourself from "
                    f"{f.get('origin_url') or 'its source'}")
                continue
            if entry.get("staged"):
                dest = _under(comfyui_dir, comfyui_dir / STAGED_REL / _inside_app(comfyui_dir, entry["path"]))
            else:
                dest = _landing(root, f, comfyui_dir)
            if dest is None:
                out["failed"] += 1
                out["failed_files"].append({"path": entry["path"], "why": "path outside the app folder"})
                continue
            if state == "different_here":
                dest = _under(comfyui_dir, comfyui_dir / KEPT_REL / _inside_app(comfyui_dir, entry["path"]))
                if dest is None:
                    out["failed"] += 1
                    out["failed_files"].append({"path": entry["path"], "why": "path outside the app folder"})
                    continue
            tmp = incoming / f"{sha}.part"
            try:
                resolve(BlobSpec(sha, int(entry["size_bytes"]), sources_from_urls(urls)),
                        tmp, client, emitter=emitter, stage="P1")
            except SourcesExhausted as e:
                out["failed"] += 1
                out["failed_files"].append({"path": entry["path"], "why": "every source failed",
                                            "detail": str(e)[:300]})
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists() and state == "missing" and not entry.get("staged"):
                # Appeared while we were fetching: the rule still holds, theirs stays.
                kept = _under(comfyui_dir, comfyui_dir / KEPT_REL / _inside_app(comfyui_dir, entry["path"]))
                if kept is None:
                    tmp.unlink(missing_ok=True)
                    out["failed"] += 1
                    out["failed_files"].append({"path": entry["path"], "why": "path outside the app folder"})
                    continue
                kept.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(tmp), str(kept))
                out["kept_yours"] += 1
                out["landed"].append({"path": entry["path"], "at": str(kept), "kept_yours": True})
                continue
            os.replace(tmp, dest)
            if entry.get("staged"):
                staged_workflow = dest
                continue
            if entry.get("kind") == "workflow" and state == "missing":
                workflow_here = dest
            if state == "different_here":
                out["kept_yours"] += 1
                out["landed"].append({"path": entry["path"], "at": str(dest), "kept_yours": True})
                say(f"{entry['path']}: yours kept; the saved version, checked byte for byte, "
                    f"is beside it at {dest}")
            else:
                out["fetched"] += 1
                out["landed"].append({"path": entry["path"], "at": str(dest)})
                say(f"{entry['path']}: back, checked byte for byte")
        # The workflow into the sidebar: the editor form the fetch above put down, either
        # in the app's staging or at its own place inside the app. Nothing else is read for
        # it -- a path from the manifest that was not placed by this fetch is not trusted.
        editor = staged_workflow or workflow_here
        if editor is not None and editor.is_file():
            placed = place_sidebar_workflow(comfyui_dir, editor, sidebar_workflow_name(manifest))
            if placed is not None:
                out["sidebar_workflow"] = str(placed)
    finally:
        if own_client:
            client.close()
    return out


def write_report(comfyui_dir: Path, report: TakebackReport, outcome: dict | None) -> Path:
    """The report lands under the app folder, never beside it."""
    path = comfyui_dir / ".renest" / "takeback-report.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {"report": report.to_dict(), "outcome": outcome}
    tmp = path.with_suffix(".json.part")
    tmp.write_text(json.dumps(body, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, path)
    return path
