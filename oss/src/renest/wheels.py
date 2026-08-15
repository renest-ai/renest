"""Pin wheels to direct URLs when packing, and fall back when those URLs die on restore.

The problem: `uv pip freeze` records `torch==2.4.1+cu124`; that `+cu124` local version
exists only on PyTorch's own index, so a rebuild against PyPI always fails.
`--extra-index-url` is not the answer -- uv refuses same-name packages across indexes
(dependency-confusion defence), and **that default must not be loosened**.

Pack side rewrites such requirements into direct wheel URLs carrying `#sha256=`, so the
escape hatch ``restore.sh`` needs no change; going online is opt-in (`--pin-wheels`).

Restore side: a pinned URL that 404/410s falls back to plain `name==base_version`,
**warned loudly, never silently** -- not the original bytes, and the CUDA variant may
differ (pack with ``wheels_archived`` to resist that rot). An unresolvable pin fails
hard: a dead lock still passes a full sha256 check -- how a useless nest looks fine.
"""

from __future__ import annotations

import os
import platform
import re
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse

import httpx

__all__ = [
    "lock_hosts",
    "WheelPinError",
    "PYTORCH_INDEX",
    "PinnedWheel",
    "find_wheel_url",
    "pin_lock_text",
    "wheel_platform_tags",
    "python_tag_of",
    "parse_pinned_lines",
    "dead_wheel_fallback",
    "TRUSTED_LOCK_HOSTS",
    "TRUSTED_HOSTS_ENV",
    "trusted_lock_hosts",
    "audit_lock_urls",
    "PYPI_INDEX",
    "pypi_index",
    "pytorch_index",
    "artifact_hash",
    "add_hashes",
]

#: Built-in fallback allow-list. **The normal path never reads it** -- the real list lives
#: in ``data/trusted-hosts.json`` (signed, refreshable). This is the rescue path, so it
#: holds the minimum set; the mainland-China mirrors are in it because our own installer
#: points the package index there, and without them such a user could restore nothing.
_FALLBACK_TRUSTED_HOSTS = frozenset(
    {
        "pypi.org",
        "files.pythonhosted.org",
        "download.pytorch.org",
        "github.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "pypi.tuna.tsinghua.edu.cn",
        "mirrors.aliyun.com",
    }
)

#: Where a user or a studio adds their own private sources (Nexus/Artifactory/MinIO, an
#: in-house mirror), comma-separated, so restoring does not need ``--trust-unsafe-urls``
#: every time. An environment variable is the main path because a pod is short-lived;
#: ``~/.renest/rules/trusted-hosts.json`` is the other one.
TRUSTED_HOSTS_ENV = "RENEST_TRUSTED_HOSTS"


def trusted_lock_hosts() -> frozenset[str]:
    """The allow-list in force = the rules file (refreshable) plus the environment extension.

    A host outside it is a hard refusal, with ``--trust-unsafe-urls`` as the only way past
    and **no interactive confirmation** -- headless provisioning is the main path and a
    ``[Y/n]`` prompt would hang that terminal forever.

    Honest boundary: this is not a strong security boundary -- anyone can host a wheel on
    github.com. What it stops is targeted poisoning pointing at an unfamiliar host,
    pulling the attack surface back into ecosystems that have identities and takedowns.
    """
    try:
        from .rules import TRUSTED_HOSTS, load_rules

        hosts = {str(h).strip().lower() for h in load_rules(TRUSTED_HOSTS)["hosts"] if str(h).strip()}
    except Exception:  # noqa: BLE001 - unreadable rules must not stall a restore; fall back
        hosts = set(_FALLBACK_TRUSTED_HOSTS)
    extra = os.environ.get(TRUSTED_HOSTS_ENV, "")
    hosts |= {h.strip().lower() for h in extra.replace(";", ",").split(",") if h.strip()}
    return frozenset(hosts)


#: Kept for older callers (tests and outside references); the normal path calls
#: :func:`trusted_lock_hosts`.
TRUSTED_LOCK_HOSTS = _FALLBACK_TRUSTED_HOSTS

#: Every shape of URL a lockfile can hold: a direct requirement (``name @ https://...``),
#: ``--index-url``, ``--extra-index-url``, ``-f/--find-links``, a remote ``-r`` include --
#: all of them have to clear the allow-list.
_ANY_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s'\"#]+")


def lock_hosts(lock_text: str) -> list[str]:
    """The **host names** a dependency lock will reach out to (deduplicated, sorted).

    Backs the disclosure line that says where your machine will connect when it rebuilds
    (``python_lock.hosts``, format 2.2). **Host names only, never full addresses** -- that
    answers "who will my machine talk to" without blowing past a readable size.

    This and :func:`audit_lock_urls` are **a pair, not alternatives**: that one blocks,
    this one gives advance notice. Disclosure without blocking is a disclaimer; blocking
    without disclosure is a failure nobody had reason to expect.

    ``file://`` does not count -- that is not reaching out, it is something this nest
    brought with it and just landed on the local disk.
    """
    hosts: set[str] = set()
    for line in lock_text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        for url in _ANY_URL.findall(line):
            parsed = urlparse(url)
            if parsed.scheme == "file":
                continue
            host = (parsed.hostname or "").lower()
            if host:
                hosts.add(host)
    return sorted(hosts)


def audit_lock_urls(
    lock_text: str,
    *,
    trusted: frozenset[str] | None = None,
    env_root: "Path | None" = None,
) -> list[str]:
    """Pick out the URLs in a lock that point at **untrusted hosts** (deduplicated, ordered).

    Plain http always counts as untrusted, even when the host is on the allow-list: the
    restore side installs executable bytes from that address, so anyone in the middle who
    rewrites the package owns that pod outright. An empty list means this lock installs
    only from trusted sources.

    ``env_root``: a ``file://`` path **inside the rebuild directory** is not untrusted --
    it is code this nest brought with it (editable installs of fine-tuning frameworks
    leave such entries). **Only paths under the rebuild root are let through**; a nest may
    install only what it brought itself. With no ``env_root``, every file:// is untrusted.
    """
    allow = trusted_lock_hosts() if trusted is None else trusted
    root = str(Path(env_root).resolve()).rstrip("/") + "/" if env_root else None
    bad: list[str] = []
    seen: set[str] = set()
    for line in lock_text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        for url in _ANY_URL.findall(line):
            if url in seen:
                continue
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            # Strip a version-control prefix off the scheme first: urlparse reads
            # `git+https://...` as scheme `git+https`, so **an allow-listed host can never
            # match** and not even `--trust-host` unblocks it -- a false positive that
            # leaves only the "allow everything" switch. Hit for real by a
            # `git+https://github.com/...` requirement. Only `xxx+https` is stripped,
            # never plain `xxx+http`.
            scheme = parsed.scheme.rsplit("+", 1)[-1] if "+" in parsed.scheme else parsed.scheme
            if scheme == "https" and host in allow:
                continue
            if (
                parsed.scheme == "file"
                and not host                       # file://host/... is another machine
                and root is not None
                and _inside(parsed.path, root)
            ):
                continue                            # code this nest brought, landed here
            seen.add(url)
            bad.append(url)
    return bad

def _inside(path: str, root_with_slash: str) -> bool:
    """Whether ``path`` lands inside the rebuild root.

    Resolved first, so ``../`` cannot climb out of it.
    """
    try:
        resolved = str(Path(unquote(path)).resolve())
    except (OSError, ValueError):
        return False
    return (resolved + "/").startswith(root_with_slash)


#: Packages carrying a local version live only on a vendor's private index. Today only the
#: PyTorch family is recognised (the one real runs actually ran into).
#: **This address is a fact about the outside world, not a design decision of ours** -- it
#: changes when upstream changes, so the source of truth is the rules file
#: (`package_indexes.vendor.pytorch` in `data/world-rules.json`), **changeable with one
#: cloud refresh**. What is kept here is the built-in fallback for when that cannot be
#: read, not the only source.
_PYTORCH_INDEX_FALLBACK = "https://download.pytorch.org/whl/{label}/{name}/"


def _world(*path: str, fallback):
    """Read one value out of the "state of the world" rules.

    Falls back to the built-in default when it cannot be read -- **broken rules must never
    crash a pack**.
    """
    try:
        from .rules import WORLD_RULES, load_rules

        node = load_rules(WORLD_RULES)
        for key in path:
            node = node[key]
        return node if node else fallback
    except Exception:  # noqa: BLE001 - rules are a side path, never blocking the real work
        return fallback


def pytorch_index() -> str:
    """URL template of the vendor's private index; the rules file is the source of truth."""
    return _world("package_indexes", "vendor", "pytorch", fallback=_PYTORCH_INDEX_FALLBACK)


#: Kept for older callers (tests and outside references); the normal path calls
#: :func:`pytorch_index`.
PYTORCH_INDEX = _PYTORCH_INDEX_FALLBACK

#: Network guardrail: timeout in seconds for index reads and HEAD probes. Pinning is an
#: explicit online step, but it still must never hang forever.
FETCH_TIMEOUT = 30.0

#: Package names and local version labels may hold only these characters -- they get pasted
#: into an index URL, so no path fragments and no schemes.
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
#: Legal shape of a version (local version included). The dead-link fallback writes it back
#: into the lockfile, so loosening this would let bytes from inside a nest push arguments
#: into the dependency install command.
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]*$")

# name==version(+local); may carry a trailing comment or environment marker
_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([^\s;#]+)\s*$")
# name @ https://…/pkg-1.2.3+cu124-cp311-…whl#sha256=…
_PINNED = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*@\s*(https?://\S+\.whl(?:#\S+)?)\s*$")
_HREF = re.compile(r'href="([^"]+)"', re.I)


class WheelPinError(RuntimeError):
    """Pinning failed. The caller decides what it means (pack fails hard, restore warns)."""


class PinnedWheel:
    """One already-pinned wheel line out of a lockfile."""

    __slots__ = ("name", "url", "version", "line")

    def __init__(self, name: str, url: str, version: str, line: str) -> None:
        self.name = name
        self.url = url
        self.version = version  # version read back off the wheel file name (local included)
        self.line = line

    @property
    def base_version(self) -> str:
        """Drop the local version: ``2.4.1+cu124`` -> ``2.4.1`` (the one PyPI has)."""
        return self.version.split("+", 1)[0]

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"PinnedWheel({self.name}=={self.version})"


def python_tag_of(version: str) -> str:
    """``3.11.9`` → ``cp311``"""
    parts = version.split(".")
    if len(parts) < 2:
        raise WheelPinError(f"Unrecognized Python version: {version!r}")
    return f"cp{parts[0]}{parts[1]}"


def _normalize(name: str) -> str:
    """The normalised name used in a PEP 503 index path."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _get_text(url: str, client: httpx.Client) -> str:
    r = client.get(url, timeout=FETCH_TIMEOUT)
    r.raise_for_status()
    return r.text


# Index host -> the download hosts that index itself may use. **An allow-list, not "any
# cross-host link goes"; never delete it and never open it to arbitrary hosts.** It exists
# because PyTorch serves wheels from `download-r2.pytorch.org` while its index stayed on
# `download.pytorch.org`, and exact equality made `pack --pin-wheels` fail hard -- the only
# rebuild guarantee packages with a local version have. Bar for adding an entry: confirm
# the host belongs to the same operator as the index.
_INDEX_DOWNLOAD_HOSTS: dict[str, frozenset[str]] = {
    # PyTorch's own index plus its R2 distribution domain (index pages link straight to it)
    "download.pytorch.org": frozenset({"download.pytorch.org", "download-r2.pytorch.org"}),
    # PyPI is cross-host by design (simple index on pypi.org, files on files.pythonhosted)
    "pypi.org": frozenset({"pypi.org", "files.pythonhosted.org"}),
}


def _same_operator(index_host: str, wheel_host: str) -> bool:
    """Whether the download host is one of this index's **own** distribution domains.

    The default stays **exact equality**; only explicitly listed indexes may use their own
    extra domains. It stops a rewritten index page sending the rebuild side to a third
    party to fetch torch, which a nest that arrived by hand-off needs most.
    """
    index_host, wheel_host = index_host.lower(), wheel_host.lower()
    if index_host == wheel_host:
        return True
    return wheel_host in _INDEX_DOWNLOAD_HOSTS.get(index_host, frozenset())


def find_wheel_url(
    name: str,
    version: str,
    local_label: str,
    python_tag: str,
    platform_tags: tuple[str, ...],
    *,
    client: httpx.Client,
) -> str:
    """Find the one matching wheel on the vendor index and return an absolute URL.

    The ``#sha256`` fragment is kept whenever the index supplies one.
    """
    # The name and local label get pasted into an index URL: check their shape first, so a
    # strange string inside the lockfile cannot steer the request somewhere else
    if not _SAFE_TOKEN.match(name) or not _SAFE_TOKEN.match(local_label):
        raise WheelPinError(
            "This lockfile line has a malformed package name or build label, so it will "
            f"not be used to build an index address: {name}=={version}+{local_label}"
        )
    index_url = pytorch_index().format(label=local_label, name=_normalize(name))
    try:
        page = _get_text(index_url, client)
    except Exception as e:
        raise WheelPinError(
            f"{name}=={version}+{local_label}: cannot reach the index {index_url} "
            f"({type(e).__name__})."
            f"\n  This build is not on PyPI and the vendor's index is out of reach —"
            f" a rebuild would fail."
            f"\n  Way out: pack the wheel file itself instead"
            f" (python_lock.wheels_archived)."
        ) from e

    dist = name.replace("-", "_")
    want_prefix = f"{dist}-{version}+{local_label}-"

    for href in _HREF.findall(page):
        filename = unquote(href.split("#", 1)[0].rsplit("/", 1)[-1])
        if not filename.startswith(want_prefix) or not filename.endswith(".whl"):
            continue
        if f"-{python_tag}-" not in filename:
            continue
        if not any(p in filename for p in platform_tags):
            continue
        wheel_url = urljoin(index_url, href)
        # A link the index page hands out must still belong to the index's own operator:
        # a rewritten index page must not send the restore side to a third-party host to
        # fetch "torch" (the restore side installs a pinned URL exactly as given).
        if not _same_operator(urlparse(index_url).netloc, urlparse(wheel_url).netloc):
            raise WheelPinError(
                f"{name}: the index page points this wheel at a different host "
                f"({wheel_url}). Not pinning it, and not touching the lockfile."
            )
        return wheel_url

    raise WheelPinError(
        f"{name}=={version}+{local_label}: the index has no wheel matching "
        f"{python_tag} / {'|'.join(platform_tags)} ({index_url})."
        f"\n  Way out: pack the wheel file itself instead"
        f" (python_lock.wheels_archived)."
    )


def has_local_version(lock_text: str) -> bool:
    """Whether the lock holds any package with a local version.

    Only then is it worth going online to pin anything.
    """
    return any(
        m and "+" in m.group(2) for m in (_REQ.match(ln) for ln in lock_text.splitlines())
    )


#: The names ``platform.machine()`` reports -> the segment used in package file names.
#:
#: It exists because the pack call site once passed nothing and the default was a
#: hard-coded ``x86_64``: packing on an ARM machine pinned the Intel build, and the nest
#: verified green -- right size, right fingerprints -- yet **would not install anywhere**.
_WHEEL_PLATFORM_TAG: dict[str, str] = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
}


def wheel_platform_tags(machine: str | None = None) -> tuple[str, ...]:
    """Which build of a package this machine should take; asks the local machine when
    ``machine`` is not given.

    Falling back to x86_64 for an unrecognised chip is not a good answer but beats picking
    nothing: a wrong pick fails to install where you can see it, while picking nothing
    quietly matches whichever architecture happens to come first in the index.
    """
    key = (machine or platform.machine()).strip().lower()
    return (_WHEEL_PLATFORM_TAG.get(key, "x86_64"),)


def pin_lock_text(
    lock_text: str,
    python_tag: str,
    # **Hard-coded x86_64 rather than asking the local machine**: this is a pure function
    # and its answer must not shift with the developer's laptop. The real architecture is
    # read at the boundary by pack, via wheel_platform_tags(), and passed in.
    platform_tags: tuple[str, ...] = ("x86_64",),
    *,
    client: httpx.Client | None = None,
) -> tuple[str, list[tuple[str, str]]]:
    """Rewrite the lock text. Returns (new text, [(package name, wheel URL), ...]).

    Only lines carrying a local version (``+xxx``) are touched; the rest are kept as they
    are -- they exist on PyPI and uv can find them itself.
    """
    own = client is None
    c = client if client is not None else httpx.Client(follow_redirects=True, timeout=FETCH_TIMEOUT)
    out: list[str] = []
    pinned: list[tuple[str, str]] = []
    try:
        for line in lock_text.splitlines():
            m = _REQ.match(line)
            if not m:
                out.append(line)
                continue
            name, version = m.group(1), m.group(2)
            if "+" not in version:
                out.append(line)
                continue
            base, local_label = version.split("+", 1)
            url = find_wheel_url(name, base, local_label, python_tag, platform_tags, client=c)
            out.append(f"{name} @ {url}")
            pinned.append((name, url))
    finally:
        if own:
            c.close()
    return "\n".join(out) + "\n", pinned


# --------------------------------------------------------------------------
# Restore side: dead-link fallback
# --------------------------------------------------------------------------
def parse_pinned_lines(lock_text: str) -> list[PinnedWheel]:
    """Pick out the lines in a lock that were pinned to a direct wheel URL."""
    found: list[PinnedWheel] = []
    for line in lock_text.splitlines():
        m = _PINNED.match(line)
        if not m:
            continue
        name, url = m.group(1), m.group(2)
        filename = unquote(url.split("#", 1)[0].rsplit("/", 1)[-1])
        stem = filename[: -len(".whl")]
        parts = stem.split("-")
        version = parts[1] if len(parts) > 1 else ""
        found.append(PinnedWheel(name=name, url=url, version=version, line=line))
    return found


def dead_wheel_fallback(
    lock_text: str,
    *,
    client: httpx.Client,
) -> tuple[str, list[str]]:
    """Probe whether the pinned wheels are still there; anything taken down falls back to
    the plain ``name==base_version``.

    Returns (new lock text, list of plain-language warnings). With no dead links the text
    comes back unchanged and the warning list is empty -- a failed probe (timeout, no
    connection) is treated as "still there": a restore must not downgrade itself over one
    flaky probe.
    """
    pins = parse_pinned_lines(lock_text)
    if not pins:
        return lock_text, []
    replacements: dict[str, str] = {}
    warnings: list[str] = []
    for pin in pins:
        url = pin.url.split("#", 1)[0]
        try:
            r = client.head(url, timeout=FETCH_TIMEOUT, follow_redirects=True)
            if r.status_code in (405, 501):  # some hosts reject HEAD; use GET for status
                r = client.get(url, timeout=FETCH_TIMEOUT, follow_redirects=True)
        except httpx.HTTPError:
            continue  # a flaky probe is not a dead link
        if r.status_code not in (404, 410):
            continue
        if not _SAFE_VERSION.match(pin.version or "") or not _SAFE_TOKEN.match(pin.name):
            warnings.append(
                f"{pin.name or 'One package'}: the pinned wheel is gone "
                f"(HTTP {r.status_code}), and the version read back from its file name is "
                f"malformed, so the lockfile will not be rewritten from it — pack this nest "
                f"again"
            )
            continue
        if not pin.base_version:
            warnings.append(
                f"{pin.name}: the pinned wheel is gone (HTTP {r.status_code}), and no "
                f"version can be read back from its file name, so there is nothing to fall "
                f"back to"
            )
            continue
        replacements[pin.line] = f"{pin.name}=={pin.base_version}"
        warnings.append(
            f"{pin.name}: the wheel pinned at pack time is gone (HTTP {r.status_code}). "
            f"Falling back to the plain {pin.name}=={pin.base_version} to keep going — "
            f"these are not the same bytes as the machine you packed from (the CUDA build "
            f"may differ). If it does not run, pack the nest again with wheels_archived "
            f"turned on"
        )
    if not replacements:
        return lock_text, warnings
    new_lines = [replacements.get(ln, ln) for ln in lock_text.splitlines()]
    return "\n".join(new_lines) + "\n", warnings


# --------------------------------------------------------------------------
# Dependency fingerprints: looked up online at pack time so the rebuild side can verify
# --------------------------------------------------------------------------
#: The public index (PEP 503 simple); its links carry ``#sha256=`` just like a vendor
#: index. A fact about the outside world, so the rules file
#: (`package_indexes.public.pypi`) is the source of truth and this is only the fallback.
_PYPI_INDEX_FALLBACK = "https://pypi.org/simple/{name}/"
PYPI_INDEX = _PYPI_INDEX_FALLBACK


def pypi_index() -> str:
    return _world("package_indexes", "public", "pypi", fallback=_PYPI_INDEX_FALLBACK)

#: A pure-Python package carries no platform words; its file name holds ``-none-any``.
_ANY_PLATFORM = "none-any"


def _wheel_matches(filename: str, python_tag: str, platform_tags: tuple[str, ...]) -> bool:
    """Whether this package file is one this machine can actually install.

    Two kinds count: **pure Python** (``none-any`` in the file name, identical on every
    machine) and **built for this machine and this Python version**.
    """
    if _ANY_PLATFORM in filename:
        return True
    if f"-{python_tag}-" not in filename:
        return False
    return any(p in filename for p in platform_tags)


def artifact_hash(
    name: str,
    version: str,
    python_tag: str,
    platform_tags: tuple[str, ...],
    *,
    client: httpx.Client,
    index: str | None = None,
) -> str | None:
    """Look up the **content fingerprint** of this package version on the index.

    Returns ``None`` when it cannot be found (**never invented**).

    It must be looked up online rather than read from the environment: once a package is
    installed **the ``.whl`` itself is gone**, so its fingerprint cannot be answered
    locally -- only the index knows.

    When no wheel matches, fall back to the source archive (``.tar.gz``) -- some packages
    ship source only.
    """
    if not _SAFE_TOKEN.match(name) or not _SAFE_VERSION.match(version):
        return None
    try:
        page = _get_text((index or pypi_index()).format(name=_normalize(name)), client)
    except Exception:  # noqa: BLE001 - not found is not found; never crash the whole pack
        return None

    dist = name.replace("-", "_")
    want = (f"{dist}-{version}-", f"{name}-{version}.tar.gz", f"{dist}-{version}.tar.gz")
    sdist: str | None = None
    for href in _HREF.findall(page):
        filename = unquote(href.split("#", 1)[0].rsplit("/", 1)[-1])
        frag = href.split("#", 1)[1] if "#" in href else ""
        if not frag.startswith("sha256="):
            continue
        digest = frag[len("sha256="):]
        if filename.endswith(".whl") and filename.startswith(want[0]):
            if _wheel_matches(filename, python_tag, platform_tags):
                return digest
        elif filename in want[1:]:
            sdist = digest
    return sdist


def add_hashes(
    lock_text: str,
    python_tag: str,
    platform_tags: tuple[str, ...],
    *,
    client: httpx.Client,
) -> tuple[str, int, list[str]]:
    """Add a content fingerprint to every line of the lock text.

    Returns ``(new text, how many were added, names of the ones that could not be found)``.

    **All or nothing -- that is pip/uv's rule, not a preference.** As soon as any one line
    carries a fingerprint the installer checks every line, so the lines without one fail
    the install outright: a half-filled lock installs nothing at all. If even one cannot
    be found, write none of them and report which ones, so whoever packed it knows this
    layer is missing instead of being quietly downgraded.

    **Lines already pinned to a download address are left alone** -- those addresses carry
    a fingerprint on the end already.
    """
    lines = lock_text.splitlines()
    out: list[str] = []
    missing: list[str] = []
    added = 0
    for line in lines:
        m = _REQ.match(line)
        if not m:
            out.append(line)
            continue
        name, version = m.group(1), m.group(2)
        if "+" in version:
            # packages with a local version live only on the vendor index; they take the
            # pinned-URL route, and that address carries its own fingerprint
            out.append(line)
            continue
        digest = artifact_hash(name, version, python_tag, platform_tags, client=client)
        if digest is None:
            missing.append(f"{name}=={version}")
            out.append(line)
            continue
        out.append(f"{line} --hash=sha256:{digest}")
        added += 1
    if missing:
        # all or nothing: hand back the original, not one character changed
        return lock_text, 0, missing
    return "\n".join(out) + "\n", added, []
