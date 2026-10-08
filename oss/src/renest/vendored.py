"""Wheels the nest carries itself (format 2.13): packages installed from a git
repository or from a direct URL off the public index.

Why: a line like ``sam-2 @ git+https://github.com/facebookresearch/sam2@<commit>``
needs git, a compiler and that host to be up on the machine that restores it. Measured
in a real batch (2026-10-07): the template image had no git, uv stopped with "Git
executable not found", and the nest -- every byte verified -- could not rebuild its
environment. So packing puts **the built wheel that is installed in the environment**
into the nest as an ordinary content-addressed blob, and keeps the original source
(URL plus commit, or URL plus its sha256) next to it. Restoring installs the stored
wheel when it fits the machine and falls back to the original source when it does not,
saying why.

Scope, decided by the founder 2026-10-07:

* **In**: ``name @ git+<url>@<commit>`` (any host) and ``name @ https://<host>/...``
  where the host is neither the public index nor the official PyTorch download site.
* **Out**: anything from PyPI or download.pytorch.org (those hosts keep their files;
  storing them would only duplicate gigabytes), and ``file://`` installs (the
  framework's own checkout travels as code, not as a wheel).

Where the wheel comes from, in order -- **never re-resolved**:

1. the installer caches on this machine (uv keeps the wheel it built from a git
   commit; pip keeps wheels it built from a commit-pinned VCS URL);
2. for a git source, a build of the locked commit with this environment's own
   interpreter and **no build isolation** (an isolated build would resolve its build
   dependencies afresh -- for sam-2 that means a different torch);
3. for a direct wheel URL, that exact URL, checked against the sha256 the lock or the
   installer recorded.

Whatever the route, the wheel is compared against the installed package's own RECORD
before it is accepted: same file set, same bytes for every pure file. A wheel that does
not match what is installed is not the wheel that ran, and is not stored.
"""

from __future__ import annotations

import base64
import csv
import email.parser
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import unquote, urlparse

from .envlock import canonical_name, installed_dist_infos
from .uvbin import uv_executable
from .wheels import (
    WheelPinError,
    _wheel_matches,
    python_tag_of,
    wheel_os_family,
    wheel_platform_tags,
)

__all__ = [
    "PUBLIC_HOSTS",
    "VendorCandidate",
    "ObtainedWheel",
    "vendor_candidates",
    "obtain_wheels",
    "wheel_fit",
    "wheel_tags_of",
    "substitute_vendored",
    "vendored_requirement",
]

#: Hosts whose files stay where they are. The public index and the official PyTorch
#: download site keep every release; storing their wheels would only duplicate them.
PUBLIC_HOSTS = frozenset({
    "pypi.org",
    "files.pythonhosted.org",
    "download.pytorch.org",
    "download-r2.pytorch.org",
})

#: How long one git fetch, and one wheel build, may take. A CUDA extension build
#: (sam-2's ``_C``) runs for minutes; a pack must still end.
GIT_TIMEOUT_S = 600
BUILD_TIMEOUT_S = 1800

_REQ_AT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*@\s*(\S+)(.*)$")
_HASH_OPT = re.compile(r"--hash[= ]sha256:([0-9a-fA-F]{64})")
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_BINARY_SUFFIXES = (".so", ".pyd", ".dylib", ".dll")


@dataclass
class VendorCandidate:
    """One lock line that qualifies for a stored wheel."""

    name: str
    kind: str  # "git" | "url"
    url: str  # git: the repository URL (no git+, no @ref, no #fragment); url: the address
    ref: str | None = None  # git: what the lock names after @ (a commit, or a branch)
    subdirectory: str | None = None
    sha256: str | None = None  # url: the fingerprint the lock itself carries


@dataclass
class ObtainedWheel:
    candidate: VendorCandidate
    path: Path
    filename: str
    version: str
    obtained: str  # "installer_cache" | "built_from_commit" | "downloaded"
    commit: str | None = None
    source_sha256: str | None = None
    license: str | None = None
    notes: list[str] = field(default_factory=list)


def _logical_lines(lock_text: str) -> list[str]:
    """The lock's requirement lines with ``\\`` continuations joined."""
    out: list[str] = []
    buf = ""
    for raw in lock_text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        out.append(buf + line)
        buf = ""
    if buf:
        out.append(buf)
    return out


def _split_git(url: str) -> tuple[str, str | None, str | None]:
    """``https://host/repo.git@ref#subdirectory=x`` -> (repo URL, ref, subdirectory)."""
    frag = ""
    if "#" in url:
        url, frag = url.split("#", 1)
    sub = None
    for part in frag.split("&"):
        if part.startswith("subdirectory="):
            sub = part.split("=", 1)[1] or None
    ref = None
    scheme, sep, rest = url.partition("://")
    # The ref is the last @ in the path part -- never the one in `git@github.com`.
    slash = rest.find("/")
    if slash >= 0 and "@" in rest[slash:]:
        path, ref = rest[slash:].rsplit("@", 1)
        rest = rest[:slash] + path
    return f"{scheme}{sep}{rest}", ref or None, sub


def vendor_candidates(lock_text: str) -> list[VendorCandidate]:
    """Every lock line whose package should travel as a stored wheel (see module doc)."""
    found: list[VendorCandidate] = []
    seen: set[str] = set()
    for line in _logical_lines(lock_text):
        body = line.split(" #", 1)[0] if not line.lstrip().startswith("#") else ""
        m = _REQ_AT.match(body)
        if not m:
            continue
        name, url, rest = m.group(1), m.group(3), m.group(4)
        key = canonical_name(name)
        if key in seen:
            continue
        if url.startswith("git+"):
            repo, ref, sub = _split_git(url[len("git+"):])
            if not repo.startswith(("https://", "http://", "ssh://", "git://")):
                continue
            found.append(VendorCandidate(name, "git", repo, ref=ref, subdirectory=sub))
            seen.add(key)
            continue
        if not url.startswith(("https://", "http://")):
            continue  # file://, hg+, svn+ ... out of scope
        host = (urlparse(url).hostname or "").lower()
        if host in PUBLIC_HOSTS:
            continue
        addr, _, frag = url.partition("#")
        sha = None
        fm = re.search(r"sha256=([0-9a-fA-F]{64})", frag)
        if fm:
            sha = fm.group(1).lower()
        hm = _HASH_OPT.search(rest)
        if hm and sha is None:
            sha = hm.group(1).lower()
        found.append(VendorCandidate(name, "url", addr, sha256=sha))
        seen.add(key)
    return found


# ---------------------------------------------------------------- fit ----
def wheel_tags_of(filename: str) -> tuple[str, str, str] | None:
    """(python, abi, platform) tags of a wheel file name, or None if it is not one."""
    if not filename.endswith(".whl"):
        return None
    fields = filename[: -len(".whl")].split("-")
    if len(fields) < 5:
        return None
    return fields[-3], fields[-2], fields[-1]


def wheel_fit(
    filename: str, python_version: str, machine: str | None = None, system: str | None = None
) -> str | None:
    """None when this wheel installs on this machine with this Python; otherwise one
    plain sentence fragment saying what it was built for and what is needed here.

    The same test the pinning step uses to choose a wheel (``wheels._wheel_matches``) --
    one definition of "fits", and the escape hatch's ``wheel_fits`` mirrors it, compared
    case by case in ``test_both_legs_agree_on_vendored_wheels.py``.
    """
    tags = wheel_tags_of(filename)
    try:
        want = python_tag_of(python_version)
    except WheelPinError:
        return f"this nest does not say which Python it needs, so {filename} cannot be matched"
    plat = wheel_platform_tags(machine)
    osf = wheel_os_family(system)
    if tags and _wheel_matches(filename, want, plat, osf):
        return None
    built = f"{tags[0]} / {tags[2]}" if tags else filename
    return f"it is built for {built}, and this machine needs {want} / {osf} {plat[0]}"


# ---------------------------------------------------------------- lock rewrite ----
def vendored_requirement(name: str, wheel_path: Path, sha256: str) -> str:
    """The lock line that installs the stored wheel instead of the original source.

    Only ``%`` and the space are escaped -- exactly what the escape hatch can do with a
    shell substitution, so both legs hand uv the same line (uv accepts the rest as is).
    """
    path = str(wheel_path.resolve()).replace("%", "%25").replace(" ", "%20")
    return f"{name} @ file://{path} --hash=sha256:{sha256}"


def substitute_vendored(lock_text: str, replacements: dict[str, str]) -> tuple[str, list[str]]:
    """Swap the line of each named package (canonical name -> new requirement line).

    A line continued with ``\\`` (``uv pip compile`` writes its hashes that way) is
    replaced together with its continuation lines. Returns the new text and the
    canonical names actually replaced.
    """
    out: list[str] = []
    done: list[str] = []
    skipping = False
    for raw in lock_text.splitlines():
        if skipping:
            skipping = raw.rstrip().endswith("\\")
            continue
        m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:==|@)", raw)
        key = canonical_name(m.group(1)) if m else None
        if key and key in replacements and key not in done:
            out.append(replacements[key])
            done.append(key)
            skipping = raw.rstrip().endswith("\\")
            continue
        out.append(raw)
    return "\n".join(out) + "\n", done


# ---------------------------------------------------------------- pack side ----
def _b64_sha256(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _file_b64(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return base64.urlsafe_b64encode(h.digest()).rstrip(b"=").decode()


def _is_payload(rel: str) -> bool:
    if rel.endswith(".pyc") or "/__pycache__/" in f"/{rel}":
        return False
    first = rel.split("/", 1)[0]
    return not first.endswith(".dist-info") and not rel.startswith("..")


def _installed_payload(dist_info: Path, site_packages: Path) -> dict[str, str] | None:
    """relpath -> urlsafe-b64 sha256, for what the installer put into site-packages."""
    try:
        text = (dist_info / "RECORD").read_text(encoding="utf-8")
    except OSError:
        return None
    out: dict[str, str] = {}
    for row in csv.reader(io.StringIO(text)):
        if not row or not _is_payload(row[0]):
            continue
        rel = row[0]
        h = row[1] if len(row) > 1 else ""
        if h.startswith("sha256="):
            out[rel] = h[len("sha256="):]
        else:
            p = site_packages / rel
            out[rel] = _file_b64(p) if p.is_file() else ""
    return out


def _wheel_payload(wheel: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    with zipfile.ZipFile(wheel) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            rel = info.filename
            first, _, tail = rel.partition("/")
            if first.endswith(".data"):
                sub, _, rest = tail.partition("/")
                if sub not in ("purelib", "platlib"):
                    continue  # scripts / headers / data land outside site-packages
                rel = rest
            if not _is_payload(rel):
                continue
            out[rel] = _b64_sha256(z.read(info))
    return out


def matches_installed(
    wheel: Path, dist_info: Path, site_packages: Path, *, binaries_may_differ: bool
) -> str | None:
    """None when ``wheel`` is the wheel this package was installed from; else why not.

    Same file set, same bytes for every file -- except, for a wheel we rebuilt here,
    compiled extensions: a compiler does not promise the same bytes twice. They must
    still be present, so a build that silently skipped the CUDA extension the installed
    copy has is refused.
    """
    installed = _installed_payload(dist_info, site_packages)
    if installed is None:
        return "the installed package has no RECORD to compare against"
    try:
        built = _wheel_payload(wheel)
    except (OSError, zipfile.BadZipFile) as e:
        return f"the wheel cannot be read ({type(e).__name__})"
    if set(built) != set(installed):
        extra = sorted(set(built) - set(installed))[:2]
        missing = sorted(set(installed) - set(built))[:2]
        return ("its files differ from the installed copy ("
                + ", ".join([f"+{x}" for x in extra] + [f"-{x}" for x in missing]) + ")")
    for rel, h in built.items():
        if installed[rel] and installed[rel] != h:
            if binaries_may_differ and (rel.endswith(_BINARY_SUFFIXES) or ".so." in rel):
                continue
            return f"{rel} differs from the installed copy"
    return None


def wheel_license(wheel: Path) -> str | None:
    """The licence the wheel's own METADATA states, or None when it states none."""
    try:
        with zipfile.ZipFile(wheel) as z:
            meta_name = next((n for n in z.namelist()
                              if n.count("/") == 1 and n.endswith(".dist-info/METADATA")), None)
            if meta_name is None:
                return None
            raw = z.read(meta_name).decode("utf-8", errors="replace")
    except (OSError, zipfile.BadZipFile):
        return None
    msg = email.parser.Parser().parsestr(raw, headersonly=True)
    expr = (msg.get("License-Expression") or "").strip()
    if expr:
        return expr[:200]
    lic = (msg.get("License") or "").strip()
    if lic and lic.upper() != "UNKNOWN" and "\n" not in lic and len(lic) <= 200:
        return lic
    classifiers = [c.split("::")[-1].strip() for c in msg.get_all("Classifier") or []
                   if c.startswith("License ::") and c.count("::") >= 2]
    if classifiers:
        return "; ".join(classifiers)[:200]
    return None


def _installer_cache_dirs() -> list[Path]:
    """Where uv and pip keep wheels they built: only the parts that hold built wheels."""
    dirs: list[Path] = []
    uv_dir = os.environ.get("UV_CACHE_DIR")
    if not uv_dir:
        try:
            r = subprocess.run([uv_executable(), "cache", "dir"], capture_output=True,
                               text=True, timeout=20)
            uv_dir = r.stdout.strip() if r.returncode == 0 else ""
        except (OSError, subprocess.TimeoutExpired):
            uv_dir = ""
    home = Path.home()
    uv_root = Path(uv_dir) if uv_dir else home / ".cache" / "uv"
    for sd in sorted(uv_root.glob("sdists-v*")):
        for sub in ("git", "url"):
            if (sd / sub).is_dir():
                dirs.append(sd / sub)
    pip_dirs = [Path(os.environ["PIP_CACHE_DIR"])] if os.environ.get("PIP_CACHE_DIR") else []
    pip_dirs += [home / ".cache" / "pip", home / "Library" / "Caches" / "pip"]
    for p in pip_dirs:
        if (p / "wheels").is_dir():
            dirs.append(p / "wheels")
    return dirs


def _cached_wheels(name: str, version: str, dirs: list[Path]) -> list[Path]:
    want = canonical_name(name)
    hits: list[Path] = []
    for d in dirs:
        for dirpath, _dirnames, filenames in os.walk(d):
            for fn in filenames:
                if not fn.endswith(".whl"):
                    continue
                parts = fn[:-4].split("-")
                if len(parts) >= 5 and canonical_name(parts[0]) == want and parts[1] == version:
                    hits.append(Path(dirpath) / fn)
    return hits


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                          timeout=GIT_TIMEOUT_S, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})


def _build_from_commit(
    cand: VendorCandidate, commit: str, env_python: str, work: Path
) -> tuple[Path | None, str]:
    """Check out the locked commit and build its wheel with this environment's own
    interpreter, without build isolation. (wheel, "") or (None, why not)."""
    if shutil.which("git") is None:
        return None, "git is not installed on this machine"
    src = work / "src"
    out = work / "out"
    shutil.rmtree(work, ignore_errors=True)
    src.mkdir(parents=True)
    out.mkdir()
    try:
        for args in (["init", "-q"], ["remote", "add", "origin", cand.url],
                     ["fetch", "-q", "--depth", "1", "origin", commit],
                     ["checkout", "-q", "FETCH_HEAD"],
                     ["submodule", "update", "-q", "--init", "--recursive", "--depth", "1"]):
            r = _git(args, src)
            if r.returncode != 0:
                return None, f"git {args[0]} failed: {(r.stderr or '').strip()[-200:]}"
        build_dir = src / cand.subdirectory if cand.subdirectory else src
        r = subprocess.run(
            [uv_executable(), "build", "--wheel", "--no-build-isolation",
             "--python", env_python, "--out-dir", str(out), str(build_dir)],
            capture_output=True, text=True, timeout=BUILD_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return None, "the build did not finish in time"
    except OSError as e:
        return None, f"the build could not start ({e})"
    if r.returncode != 0:
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or [""]
        return None, f"building it failed ({tail[0][:200]})"
    wheels = sorted(out.glob("*.whl"))
    if len(wheels) != 1:
        return None, f"the build produced {len(wheels)} wheel files"
    return wheels[0], ""


def _download(url: str, dest: Path, client) -> str | None:
    """Stream ``url`` into ``dest``; returns the hex sha256, or None on failure."""
    h = hashlib.sha256()
    try:
        with client.stream("GET", url, follow_redirects=True, timeout=120) as r:
            if r.status_code != 200:
                return None
            with dest.open("wb") as f:
                for chunk in r.iter_bytes(1 << 20):
                    f.write(chunk)
                    h.update(chunk)
    except Exception:  # noqa: BLE001 - any network failure means "not obtained"
        return None
    return h.hexdigest()


def _direct_url_info(dist_info: Path) -> dict:
    try:
        info = json.loads((dist_info / "direct_url.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return info if isinstance(info, dict) else {}


def _recorded_archive_sha(info: dict) -> str | None:
    ai = info.get("archive_info") or {}
    hashes = ai.get("hashes") or {}
    if isinstance(hashes, dict) and hashes.get("sha256"):
        return str(hashes["sha256"]).lower()
    h = ai.get("hash") or ""
    if isinstance(h, str) and h.startswith("sha256="):
        return h.split("=", 1)[1].lower()
    return None


def obtain_wheels(
    lock_text: str,
    site_packages: Path | None,
    env_python: str | None,
    work: Path,
    *,
    online: bool,
    client=None,
    say: Callable[[str], None] | None = None,
) -> tuple[list[ObtainedWheel], list[str]]:
    """Find the installed wheel of every qualifying lock line.

    Returns (wheels obtained, one plain English line per package that could not be
    obtained). Never raises for a package: a nest without the stored wheel is today's
    nest, and packing goes on.
    """
    cands = vendor_candidates(lock_text)
    if not cands:
        return [], []
    misses: list[str] = []
    got: list[ObtainedWheel] = []
    dists = installed_dist_infos(site_packages) if site_packages is not None else {}
    cache_dirs: list[Path] | None = None
    for i, cand in enumerate(cands):
        src_said = (f"git+{cand.url}" + (f"@{cand.ref}" if cand.ref else "")
                    if cand.kind == "git" else cand.url)

        def miss(why: str, _c: VendorCandidate = cand, _s: str = src_said) -> None:
            misses.append(
                f"{_c.name}: its built wheel is not stored in the nest ({why}), so a restore "
                f"installs it from its original source, {_s}"
                + (" -- which needs git on that machine." if _c.kind == "git" else ".")
            )

        dist_info = dists.get(canonical_name(cand.name))
        if dist_info is None:
            miss("it is not installed in the environment being packed")
            continue
        version = dist_info.name[: -len(".dist-info")].split("-", 1)[-1]
        info = _direct_url_info(dist_info)
        commit = None
        if cand.kind == "git":
            commit = ((info.get("vcs_info") or {}).get("commit_id") or "").lower() or None
            if commit is None and cand.ref and _FULL_SHA.match(cand.ref.lower()):
                commit = cand.ref.lower()
            if commit is None:
                miss("no commit is recorded for it, so the exact build cannot be identified")
                continue
            if cand.ref and _FULL_SHA.match(cand.ref.lower()) and cand.ref.lower() != commit:
                miss(f"the installed copy came from commit {commit[:12]}, not the locked "
                     f"{cand.ref[:12]}")
                continue
        expected_sha = cand.sha256 or _recorded_archive_sha(info)

        chosen: ObtainedWheel | None = None
        # 1. installer caches -- only wheels whose every byte matches what is installed
        if cache_dirs is None:
            cache_dirs = _installer_cache_dirs()
        for w in _cached_wheels(cand.name, version, cache_dirs):
            if cand.kind == "url" and expected_sha:
                h = hashlib.sha256(w.read_bytes()).hexdigest()
                if h != expected_sha:
                    continue
            if matches_installed(w, dist_info, site_packages, binaries_may_differ=False) is None:
                chosen = ObtainedWheel(cand, w, w.name, version, "installer_cache", commit=commit)
                break
        why = "no copy in this machine's installer caches"
        # 2. git: build the locked commit, no isolation, this environment's interpreter
        if chosen is None and cand.kind == "git":
            if not online:
                why += ", and building it needs the network, which this pack does not use"
            elif not env_python:
                why += ", and the environment's Python was not found to build it with"
            else:
                if say:
                    say(f"Building {cand.name} from commit {commit[:12]} to store its wheel "
                        f"in the nest (this can take a few minutes)")
                built, bwhy = _build_from_commit(cand, commit, env_python, work / f"build-{i}")
                if built is None:
                    why += f"; building commit {commit[:12]} here: {bwhy}"
                else:
                    diff = matches_installed(built, dist_info, site_packages,
                                             binaries_may_differ=True)
                    if diff is None:
                        chosen = ObtainedWheel(cand, built, built.name, version,
                                               "built_from_commit", commit=commit)
                    else:
                        why += f"; a build of commit {commit[:12]} is not the installed copy: {diff}"
        # 3. url: the exact address, checked against the recorded fingerprint
        if chosen is None and cand.kind == "url":
            fname = unquote(urlparse(cand.url).path.rsplit("/", 1)[-1])
            if wheel_tags_of(fname) is None:
                why += " and the address is not a wheel file"
            elif not online:
                why += ", and downloading it needs the network, which this pack does not use"
            elif client is None:
                why += ", and no network client was available"
            else:
                dest_dir = work / f"dl-{i}"
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest = dest_dir / fname
                h = _download(cand.url, dest, client)
                if h is None:
                    why += "; downloading it failed"
                elif expected_sha and h != expected_sha:
                    why += (f"; the download's sha256 {h[:12]} is not the recorded "
                            f"{expected_sha[:12]}")
                else:
                    diff = matches_installed(dest, dist_info, site_packages,
                                             binaries_may_differ=False)
                    if diff is None:
                        chosen = ObtainedWheel(cand, dest, fname, version, "downloaded",
                                               source_sha256=h)
                    else:
                        why += f"; the downloaded file is not the installed copy: {diff}"
        if chosen is None:
            miss(why)
            continue
        if cand.kind == "url" and chosen.source_sha256 is None:
            chosen.source_sha256 = hashlib.sha256(chosen.path.read_bytes()).hexdigest()
        chosen.license = wheel_license(chosen.path)
        got.append(chosen)
    return got, misses
