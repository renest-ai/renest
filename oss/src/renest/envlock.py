"""Read a dependency list live from **the Python environment that is running**,
for environments that ship no lock file at all.

The ComfyUI desktop build is one: no requirements.lock, no uv.lock, not even a
requirements.txt, so skipping what we cannot find leaves a nest whose owner has
to retype hundreds of versions by hand. Reading the interpreter is legitimate
because a nest only captures a run that worked: what is installed *is* that run.

It asks the interpreter to report on itself (stdlib ``importlib.metadata``;
installs nothing, touches no network) and emits exact ``name==version`` pins, so
the trusted-index, mixed-CUDA and wheel-pinning checks all keep applying. The
**honest limit**, stated in the generated file and as a pack-time warning: no
hashes and no original index, so private indexes and vendor builds (torch's
``+cu124``) will not come back this way.
"""

from __future__ import annotations


import json
import re
import subprocess
from pathlib import Path
from .roots import ENV_ROOT_TOKEN
from .uvbin import uv_executable

__all__ = [
    "LOCK_FROM_INSTALLED_HEADER",
    "LOCK_FROM_ENV_HEADER",
    "COMPILE_REQUIRED_PACKAGES",
    "COMPILE_REQUIRED_VERDICT",
    "canonical_name",
    "compile_required_evidence",
    "conda_owned_evidence",
    "distro_owned_packages",
    "env_dir_of",
    "env_python_matches_run_record",
    "image_build_evidence",
    "is_conda_build_url",
    "local_label_family",
    "local_path_evidence",
    "local_version_sources",
    "vendor_only_locals",
    "find_env_python",
    "find_launchers",
    "find_site_packages",
    "drop_ourselves",
    "freeze_environment",
    "freeze_from_installed",
    "installed_dist_infos",
    "interpreter_kernel",
    "launcher_interpreter_dir",
    "interpreter_python_series",
    "venv_python_candidates",
    "is_system_interpreter",
]

#: Packages the operating system installs into its own Python and that no package index
#: carries. A lock naming any of them can never be installed on another machine — pinning
#: to a wheel URL does not help, because no wheel was ever published.
DISTRO_ONLY_PACKAGES = frozenset({
    "python-apt", "pygobject", "dbus-python", "launchpadlib", "lazr-restfulclient",
    "lazr-uri", "python-debian", "distro-info", "command-not-found", "ufw",
    "ubuntu-drivers-common", "systemd-python", "apt-clone", "unattended-upgrades",
    "sos", "cloud-init", "netifaces", "pycurl", "python-apt-dbg", "gpg", "louis",
    "ubuntu-pro-client", "screen-resolution-extra", "xkit",
})

#: Local-version suffixes a distribution stamps on its own rebuilds (PEP 440 local part).
#: ``+cu124`` is a vendor build and is a different problem with a different fix, so it is
#: deliberately not in here.
DISTRO_LOCAL_MARKERS = ("+ubuntu", "+deb", "+dfsg", "+ds", "+really", "+esm")


def canonical_name(name: str) -> str:
    """One spelling for a distribution name (PEP 503): ``Opencv_Python`` and
    ``opencv-python`` are the same package and must compare equal."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()

#: Header lines of the generated file, so whoever receives the nest can see at a
#: glance where this list came from.
LOCK_FROM_ENV_HEADER = (
    "# Read from the Python environment that ran this workflow — there was no lock\n"
    "# file to pack. Versions are pinned exactly as they were installed, with one\n"
    "# line left out: the tool that made this nest. A nest describes the environment\n"
    "# that ran the workflow, not that environment plus us; packages it pulled in are\n"
    "# kept, because the app may need them too. Other than that, package\n"
    "# hashes and original index URLs were not recorded, so a restore installs these\n"
    "# versions from the public index.\n"
)

#: The probe handed to that interpreter to execute. Stdlib only: installs
#: nothing, touches no network.
#: Last-resort freeze, stdlib only. **Reads ``direct_url.json`` as well as the
#: version**: a package installed from git carries no useful version (`SAM-2==1.0`
#: is not on any index -- installing from that line fails), and the address plus
#: commit that would reinstall it is sitting right there in the metadata. pip and uv
#: both emit the address; this route used to drop it and say nothing.
_FREEZE_SNIPPET = """
import importlib.metadata as m, json
lines = {}
for d in m.distributions():
    name = (d.metadata['Name'] or '').strip()
    if not name or not d.version:
        continue
    pin = name + '==' + d.version
    try:
        info = json.loads(d.read_text('direct_url.json') or '')
        vcs = info.get('vcs_info') or {}
        if vcs.get('vcs') and vcs.get('commit_id') and info.get('url'):
            pin = name + ' @ ' + vcs['vcs'] + '+' + info['url'] + '@' + vcs['commit_id']
    except Exception:
        pass
    lines[name] = pin
print(chr(10).join(v for _, v in sorted(lines.items(), key=lambda kv: kv[0].lower())))
"""


def distro_owned_packages(lock_text: str) -> list[str]:
    """Lines in a lock that only the operating system's own Python could have.

    Two tells, either is enough: a distro local version (``2.4.0+ubuntu4``), or a name
    on the list above. Kept separate from vendor builds like ``torch==2.4.1+cu124``,
    which a wheel URL does fix — these cannot be fixed at all, only avoided by building
    the environment in a venv before packing.

    **What it does not do**, stated because the wording here used to claim it did:
    it never asks an index whether a name exists. A package installed straight from a
    repository is not on the list and has no distro version, so it is **not** reported
    here even though nothing could install it from a bare ``name==version`` line —
    that case is handled where the lock is written, by keeping the address and the
    commit (see ``_FREEZE_SNIPPET``), not by trying to spot it afterwards.
    Asking an index would mean a network call from a step that must work offline.
    """
    hits: list[str] = []
    for raw in lock_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-") or "==" not in line:
            continue
        name, _, version = line.partition("==")
        name = canonical_name(name.split("[", 1)[0].strip())
        local = version.split("+", 1)[1].lower() if "+" in version else ""
        if name in DISTRO_ONLY_PACKAGES or any(
            ("+" + local).startswith(m) for m in DISTRO_LOCAL_MARKERS if local
        ):
            hits.append(line)
    return hits


#: Packages that only a conda channel ships: conda's own machinery, and Intel's MKL
#: shims. None install from PyPI, so a lock naming any of them cannot be rebuilt with
#: uv/pip on another machine — the same dead end as DISTRO_ONLY_PACKAGES, from a
#: different source. Stored canonicalised so ``mkl_fft`` and ``mkl-fft`` compare equal.
CONDA_ONLY_PACKAGES = frozenset(
    canonical_name(n)
    for n in (
        "conda", "conda-build", "conda-libmamba-solver", "conda-content-trust",
        "conda-package-handling", "conda-package-streaming", "libmambapy", "menuinst",
        "mkl-service", "mkl_fft", "mkl_random", "anaconda-anon-usage",
    )
)

#: A dependency URL pointing into conda's own build tree — what pip/uv record for a
#: package that conda built and installed (``croot`` is Anaconda's build root; a local
#: ``conda-bld`` is conda-build's). No machine but the build farm has these paths, and
#: they name no host a user could ever ``--trust-host`` into.
_CONDA_BUILD_URL = re.compile(r"file://\S*/(?:croot|conda-bld)/", re.IGNORECASE)


#: The distribution name at the head of a ``Requires-Dist:`` line, before any
#: extras, version specifier or environment marker.
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def requires_of(dist_info: Path) -> set[str]:
    """Canonical names a distribution declares in ``Requires-Dist`` (its METADATA
    header block), read off disk. Markers and extras are deliberately not evaluated:
    an over-wide answer only ever shrinks what the callers below act on."""
    names: set[str] = set()
    try:
        with (dist_info / "METADATA").open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    break               # headers end at the first blank line
                if line.lower().startswith("requires-dist:"):
                    m = _REQ_NAME.match(line.split(":", 1)[1])
                    if m:
                        names.add(canonical_name(m.group(1)))
    except OSError:
        pass
    return names


#: The package manager whose own machinery must never be mistaken for the app's
#: dependencies. Only conda for now: it is the one that installs itself *into* the
#: environment it manages, so a freeze of that environment lists the manager as if
#: it were part of the work.
_PACKAGE_MANAGER = "conda"


def package_manager_closure(site_packages: Path) -> set[str]:
    """Canonical names of the package manager's **own** installation — the manager
    plus everything it, transitively, declares it needs — as installed here.
    Empty when the manager is not installed in this environment.

    **Why this is a reading and not a judgement.** It answers one question off
    disk — *which distributions make up conda itself?* — by walking conda's own
    ``Requires-Dist`` headers. It never asks the second question, the one we are
    not allowed to guess: *does the app need this?* A package the app installed
    stays, even when conda installed it, because nothing here looks at the app.

    Measured on a real fine-tune run (``pytorch/pytorch:2.4.0-cuda12.1``): the
    packed environment *was* conda's base environment, so its 121-line lock carried
    ``libmambapy``, ``menuinst``, ``boltons``, ``pycosat`` and ``ruamel.yaml`` --
    conda's own parts, on no package index. A restore stopped on the first of them
    after 2.1 GB had been downloaded and paid for.
    """
    installed = installed_dist_infos(site_packages)
    if _PACKAGE_MANAGER not in installed:
        return set()
    closure = {_PACKAGE_MANAGER}
    frontier = [_PACKAGE_MANAGER]
    while frontier:
        for req in requires_of(installed[frontier.pop()]):
            if req in installed and req not in closure:
                closure.add(req)
                frontier.append(req)
    return closure


def unreinstallable_manager_parts(site_packages: Path) -> set[str]:
    """The package manager's own parts **that no index can give back** — the only
    names it is safe to take out of a lock. Two independent readings, intersected:

    * :func:`package_manager_closure` — a structural fact off conda's own METADATA:
      is this distribution part of conda itself?
    * :data:`CONDA_ONLY_PACKAGES` — a maintained list of names whose **conda builds**
      are not published to PyPI at the same version.

    **That second one is weaker than it used to say here, and the wording mattered.**
    It read "names no package index carries", which is false for most of the list:
    checked against PyPI on 2026-09-09, 9 of the 12 names exist there (``conda``,
    ``menuinst``, ``mkl-service``, ``mkl_fft``, ``mkl_random`` and more). What is
    absent is the *version* conda installed -- ``conda==24.1.2``, ``menuinst==2.1.1``
    and ``libmambapy==1.5.8`` are each a 404 at that version. So the list is a proxy,
    not a fact, and it earns its place only by being intersected with the closure
    below: a name has to be conda's own machinery *as installed here* before the
    proxy is allowed to decide anything.

    **Each covers the other's weakness, which is the whole point.** The list alone
    could name something an app legitimately depends on (drop it and the rebuild
    fails silently, missing a package); the closure alone sweeps in ordinary PyPI
    packages conda happens to require (``requests`` is in conda's closure, and every
    index has it — taking it out would be the same silent breakage). Intersected,
    a name has to be *both* conda's own machinery *and* absent from every index
    before it is touched, so over-dropping needs two independent readings to be
    wrong at once.

    The failure that remains is the harmless direction: a conda-only package the
    list has never heard of stays in the lock, and the rebuild fails on it exactly
    as it does today, with the same pack-time warning saying so. Under-dropping
    costs a warning; over-dropping costs a silent missing package.
    """
    return package_manager_closure(site_packages) & CONDA_ONLY_PACKAGES


def dists_built_from_a_directory(site_packages: Path) -> dict[str, str]:
    """Installed distributions that came from a **folder on the packing machine**,
    mapped to that folder. Read off each one's ``direct_url.json`` (PEP 610), which
    the installer wrote at install time.

    Why it matters: ``pip install -e .`` — the last line of kohya_ss's own
    requirements.txt, and the standard way its README says to install it — records
    the repository as an ordinary distribution. In a freeze it comes out as a bare
    ``library==0.0.0``, indistinguishable from a package anyone could download,
    and no index has ever carried that name at that version. Measured on a real
    fine-tune archive: line 44 of its 121-line lock, and not one of the five
    lock-text checks in this module sees it — they read the text, and the text
    looks ordinary. The install record is where the fact actually lives.

    **Only ``dir_info`` counts** (a directory install, editable or not). A local
    ``.whl`` file records ``archive_info`` instead, and that same wheel may well be
    on an index at that version, so calling it un-installable would be a guess.
    A directory install never is one.
    """
    out: dict[str, str] = {}
    for name, di in installed_dist_infos(site_packages).items():
        try:
            info = json.loads((di / "direct_url.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(info, dict) and isinstance(info.get("dir_info"), dict):
            out[name] = str(info.get("url") or "")
    return out


def lock_lines_for(lock_text: str, names: set[str]) -> list[str]:
    """The lock's own lines for ``names`` — so a warning can quote the text the
    reader will actually see, instead of a name they then have to go find."""
    hits: list[str] = []
    for raw in lock_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-r ", "-c ", "--")):
            continue
        stem = re.sub(r"^-e\s+", "", line)
        stem = re.split(r"\s+@\s+|===|==|>=|<=|~=|!=|<|>|@", stem, maxsplit=1)[0]
        if canonical_name(stem.split("[", 1)[0]) in names:
            hits.append(line)
    return hits


def split_out_package_manager(lock_text: str, owned: set[str]) -> tuple[str, list[str]]:
    """Take the package manager's own parts out of a lock. Returns
    ``(lock without them, the lines removed)``; ``owned`` empty means nothing moves.

    The removed lines are handed back rather than swallowed so the caller can say in
    the pack output exactly what was left out and why -- a lock that silently grew
    shorter is the kind of change nobody can audit later.
    """
    if not owned:
        return lock_text, []
    keep, dropped = [], []
    for raw in lock_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-r ", "-c ", "--")):
            keep.append(raw)
            continue
        stem = re.sub(r"^-e\s+", "", line)
        stem = re.split(r"\s+@\s+|===|==|>=|<=|~=|!=|<|>|@", stem, maxsplit=1)[0]
        if canonical_name(stem.split("[", 1)[0]) in owned:
            dropped.append(line)
        else:
            keep.append(raw)
    return "\n".join(keep) + ("\n" if lock_text.endswith("\n") else ""), dropped


def is_conda_build_url(url: str) -> bool:
    """True when ``url`` points into conda's own build tree (see ``_CONDA_BUILD_URL``)."""
    return bool(_CONDA_BUILD_URL.search(url))


def conda_owned_evidence(lock_text: str) -> list[str]:
    """Lines proving this lock came from a conda-built environment, which renest cannot
    reproduce: it rebuilds with uv/PyPI, and conda-only packages have no wheel on any
    index. Two tells, either is enough — a dependency pinned to a conda build-tree URL
    (``file:///croot/...``), or a package only a conda channel ships. Returns the
    offending lines (empty = no conda evidence).

    Kept separate from ``distro_owned_packages`` and from vendor ``+cuNNN`` builds:
    each of those has its own, different fix; this one's only fix is 'rebuild it in a
    virtual environment and pack again'.
    """
    hits: list[str] = []
    for raw in lock_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-r ", "-c ", "--")):
            continue
        if _CONDA_BUILD_URL.search(line):
            hits.append(line)
            continue
        stem = re.sub(r"^-e\s+", "", line)
        # Take the distribution name off the front, before any version or URL marker.
        stem = re.split(r"\s+@\s+|===|==|>=|<=|~=|!=|<|>|@", stem, maxsplit=1)[0]
        if canonical_name(stem.split("[", 1)[0]) in CONDA_ONLY_PACKAGES:
            hits.append(line)
    return hits


# --------------------------------------------------------- lock != reinstallable --
# A dependency lock can read as a clean list of ``name==version`` and still be
# impossible to rebuild byte-for-byte on another machine. ``conda_owned_evidence``
# above is one family of this; three more live here. The shared pathology: pip-level
# it looks fine, yet the pin either installs a different binary or does not install at
# all. Each is recognised by **shape** (never by a network call, so pack stays
# offline), and pack turns each into a warning at PACK time, next to the cause,
# instead of letting a restore stop far from it. None of them blocks: the same line as
# the OS-package and conda cases -- the archive is still a faithful record of this
# machine, and packing preserves the scene rather than policing it.

#: Local-version tags a vendor index still serves, so ``pack --pin-wheels`` can reach
#: them: the CUDA / ROCm / CPU / accelerator builds PyTorch and friends publish
#: (``torch==2.4.1+cu124``). Anything after the ``+`` that is not one of these is a
#: build that only ever existed on the machine, or inside the image, that made it.
_VENDOR_LOCAL_PREFIXES = ("cu", "rocm", "cpu", "xpu", "hpu", "cann", "mps", "musa")

#: A local part that spells out a from-source or baked-into-the-image build: a git
#: checkout (``2.0.1a0+gitc263bd4``), an NGC-container build (``+nv23.05``, or a bare
#: short commit hash like ``+29c30b1``), a nightly/dev stamp. None is published anywhere
#: a restore could fetch, and ``--pin-wheels`` cannot find it either.
_IMAGE_BUILD_LOCAL = re.compile(r"^(?:git|nv\d|dev|nightly|[0-9a-f]{7,40})", re.IGNORECASE)


def local_label_family(local: str) -> str:
    """Which family a PEP 440 local-version label belongs to — because each family
    has a **different fix**, and handing someone the wrong fix is worse than none:

    * ``vendor``: a build a vendor's own index still serves (``cu124``, ``rocm6.2``) —
      ``pack --pin-wheels`` reaches it;
    * ``image``: a from-source or baked-into-the-image build (``gitc263bd4``,
      ``nv23.05``) — published nowhere, ``--pin-wheels`` cannot find it, the only fix
      is rebuilding the environment from an installable release;
    * ``distro``: the operating system's own rebuild (``ubuntu3``) — never on any
      index, fix is packing from a virtual environment;
    * ``other``: a label none of the shapes above claim. Treated like ``vendor`` by
      the pinning path, which then answers honestly when the index has nothing.
    """
    low = (local or "").lower()
    if not low:
        return "other"
    if low.startswith(_VENDOR_LOCAL_PREFIXES):
        return "vendor"
    if any(("+" + low).startswith(m) for m in DISTRO_LOCAL_MARKERS):
        return "distro"
    if _IMAGE_BUILD_LOCAL.match(low):
        return "image"
    return "other"


def vendor_only_locals(lock_text: str) -> list[str]:
    """Lines pinning a **bare** local version that only a vendor's index can serve
    (``torch==2.4.1+cu124`` with no download address) — the pins ``--pin-wheels``
    exists for, and exactly the ones a rebuild against the public index can never
    install (2026-09-06, a real 64 GB restore died on this after the downloads).

    Excluded on purpose, because each is a different disease with a different fix
    and its own warning: distro-owned lines (``+ubuntu3``: no index ever had them)
    and image-build lines (``+gitc263bd4``: published nowhere, pinning cannot reach
    them either). Lines already pinned to a download address carry no ``==`` and do
    not match. Returns the offending lines (comment-stripped)."""
    distro = set(distro_owned_packages(lock_text))
    image = set(image_build_evidence(lock_text))
    hits: list[str] = []
    for raw in lock_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-") or "==" not in line:
            continue
        _, _, rest = line.partition("==")
        version = re.split(r"[;\s]", rest.strip(), maxsplit=1)[0]
        if "+" not in version:
            continue
        if line in distro or line in image:
            continue
        hits.append(line)
    return hits


def image_build_evidence(lock_text: str) -> list[str]:
    """Lines pinning a package to a local build that only existed on the packing
    machine or inside its image -- the torch-ecosystem case where
    ``torch==2.1.0a0+gitc263bd4`` reads as a normal pin and installs nowhere. Kept apart
    from the vendor ``+cuNNN`` builds, which ``--pin-wheels`` can still reach (those
    carry a prefix in ``_VENDOR_LOCAL_PREFIXES`` and are handled by the existing
    vendor-build path); these it cannot -- the only fixes are to rebuild the environment
    in a venv from an installable release, or to pin a direct wheel URL by hand. Returns
    the offending lines (empty = none)."""
    hits: list[str] = []
    for raw in lock_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-") or "==" not in line:
            continue
        _, _, rest = line.partition("==")
        version = re.split(r"[;\s]", rest.strip(), maxsplit=1)[0]
        if "+" not in version:
            continue
        local = version.split("+", 1)[1].lower()
        if not local or local.startswith(_VENDOR_LOCAL_PREFIXES):
            continue
        if _IMAGE_BUILD_LOCAL.match(local):
            hits.append(line)
    return hits


#: A ``file://`` URL anywhere in a lock line. ``file:///abs/...`` (empty host) is a path
#: on the packing machine; ``file://host/...`` is another machine outright. Either way
#: nothing at that address travels inside the nest, so a restore cannot reach it.
_FILE_URL = re.compile(r"file://\S+", re.IGNORECASE)
#: A version-control install (``git+https://...@<commit>``): it pins a commit and fetches
#: from a host the URL audit already checks, so it IS reproducible and is left alone here.
_VCS_INSTALL = re.compile(r"\b(?:git|hg|bzr|svn)\+", re.IGNORECASE)


def local_path_evidence(lock_text: str) -> list[str]:
    """Lines installing from a path on the packing machine that does not travel inside
    the nest: an editable install of a folder outside the environment root
    (``-e /opt/mylib``), or a wheel/sdist pinned by a ``file://`` URL. The environment
    root's own editable install is excluded -- it is tokenised (``ENV_ROOT_TOKEN``) and
    swapped back on restore, so it does travel. VCS installs and conda build trees are
    excluded too: the first is reproducible, the second has its own recognizer with its
    own fix. **Feed the tokenised lock text** so the environment-root marker is present.
    Returns the offending lines (empty = none)."""
    hits: list[str] = []
    for raw in lock_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ENV_ROOT_TOKEN in line:
            continue
        if _VCS_INSTALL.search(line) or is_conda_build_url(line):
            continue
        if _FILE_URL.search(line):
            hits.append(line)
            continue
        m = re.match(r"^-e\s+(\S+)", line)
        if m:
            target = m.group(1)
            if target.startswith(("/", "~")) or re.match(r"^[A-Za-z]:[\\/]", target):
                hits.append(line)
    return hits


#: The verdict a nest states, at pack time, for a package that must be rebuilt from
#: source on the machine that restores it. **This exact wording is the pre-registered
#: predicate a real-machine flash-attn run asserts against**, so it is a named constant,
#: never retyped -- a test imports it rather than copying the sentence.
COMPILE_REQUIRED_VERDICT = (
    "this package must be recompiled on the restore machine; the byte-for-byte "
    "guarantee does not cover it — use a venv + the official wheel"
)

#: Packages built from source against the exact torch / CUDA / GPU-architecture triple
#: of whatever machine installs them. A ``name==version`` line reads as installable and
#: then either finds no matching wheel and compiles for tens of minutes, or installs a
#: wheel built for another architecture that imports and dies at the first kernel launch.
#: renest cannot carry the built artifact byte-for-byte across a machine change, so it
#: says so at pack time. Deliberately a small, high-confidence set -- no unrelated PyPI
#: package shares these names; extend it the way ``CONDA_ONLY_PACKAGES`` is extended.
COMPILE_REQUIRED_PACKAGES = frozenset(
    canonical_name(n) for n in ("flash-attn", "mamba-ssm", "causal-conv1d")
)


def compile_required_evidence(lock_text: str) -> list[str]:
    """Lines naming a package that has to be recompiled on the restore machine (see
    ``COMPILE_REQUIRED_PACKAGES``). The nest is not expected to install these back; the
    verdict (``COMPILE_REQUIRED_VERDICT``) names the one route that works. Returns the
    offending lines (empty = none)."""
    hits: list[str] = []
    for raw in lock_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-r ", "-c ", "--")):
            continue
        stem = re.sub(r"^-e\s+", "", line)
        stem = re.split(r"\s+@\s+|===|==|>=|<=|~=|!=|<|>|@", stem, maxsplit=1)[0]
        if canonical_name(stem.split("[", 1)[0]) in COMPILE_REQUIRED_PACKAGES:
            hits.append(line)
    return hits


def env_python_matches_run_record(
    python_exe: str | Path, run_record: dict | None
) -> str | None:
    """A diagnostic, never a block: when the run record names the environment a working
    run used (``env.VIRTUAL_ENV``) and it is **not** the interpreter the dependency list
    was just read from, say so. The classic cause is a Jupyter kernel whose packages
    differ from the shell's -- the run happens in the kernel, the pack reads the shell.
    Returns a note, or ``None`` when they agree or the record cannot answer (unknown is
    never reported as a mismatch -- reporting it would misfire on every ordinary pack)."""
    ve = ((run_record or {}).get("env") or {}).get("VIRTUAL_ENV")
    if not ve:
        return None
    try:
        used = Path(str(python_exe)).resolve()
        recorded = Path(str(ve)).resolve()
    except (OSError, ValueError, RuntimeError):
        return None
    # The frozen interpreter sitting inside the recorded venv -> they agree.
    if used == recorded or str(used).startswith(str(recorded) + "/"):
        return None
    return (
        f"the dependency list was read from {python_exe}, but this run recorded it ran "
        f"under {ve}. If those are two different environments (a Jupyter kernel and the "
        f"shell around it are the usual case), what you are capturing may not be the "
        f"environment that ran the workflow — point --env-python at the one the run used."
    )


def is_system_interpreter(python_exe: str | Path) -> bool | None:
    """Is this the Python the operating system ships, rather than a venv?

    ``None`` when the interpreter would not answer — unknown is reported as unknown, we
    never guess. RunPod's official images run ComfyUI on the system Python, so this is
    the common case rather than the odd one.
    """
    try:
        out = subprocess.run(
            [str(python_exe), "-c", "import sys;print(sys.prefix==sys.base_prefix)"],
            capture_output=True, text=True, timeout=60, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    answer = out.stdout.strip()
    return answer == "True" if answer in ("True", "False") else None


def find_env_python(candidates: list[Path]) -> Path | None:
    """Pick the first interpreter that actually works: it exists, it runs, and it
    can report its own version.

    Only **explicitly given executables** count. We never fall back to guessing
    ``python`` from ``PATH``: that is usually a different environment, and passing
    its dependencies off as the dependencies of the run that worked is worse than
    having no list at all.
    """
    for c in candidates:
        if not c or not c.is_file():
            continue
        try:
            out = subprocess.run(
                [str(c), "-c", "import sys; print(sys.version_info[0])"],
                capture_output=True, text=True, timeout=30, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if out.returncode == 0 and out.stdout.strip() == "3":
            return c
    return None


def venv_python_candidates(*roots: Path) -> list[Path]:
    """The usual virtualenv locations: the standard install puts ``.venv`` at the
    environment root, while the desktop build puts it under the data dir.

    ``venv/Scripts/python.exe`` was missing until 2026-09-02: ``.venv`` was listed for
    both operating systems, ``venv`` only for POSIX. A Windows environment built with
    the second name therefore fell to the metadata-reading tier even though its
    interpreter sits right there and runs -- and that tier drops the origin of anything
    installed from a source folder.
    """
    out: list[Path] = []
    for r in roots:
        if r is None:
            continue
        for rel in (".venv/bin/python", ".venv/Scripts/python.exe",
                    "venv/bin/python", "venv/Scripts/python.exe"):
            out.append(r / rel)
    return out


def _uv_freeze(python_exe: str | Path) -> str | None:
    """Export through uv first. **This path is a correctness fix, not an optional
    optimisation.**

    The stdlib fallback below enumerates installed distributions, so it can only
    emit ``name==version``. The fine-tuning frameworks install themselves into the
    venv as editable installs, which come out as ``library==0.0.1`` /
    ``llamafactory==0.9.4`` — names that exist on no index, so a restore from such
    a line is guaranteed to fail. uv writes them as
    ``-e file:///absolute/path/to/source`` instead, which ``uv pip sync`` accepts.
    """
    venv = Path(python_exe).parent.parent
    try:
        out = subprocess.run(  # noqa: S603
            [uv_executable(), "pip", "freeze", "--python", str(python_exe)],
            capture_output=True, text=True, timeout=300, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 or not out.stdout.strip():
        return None
    _ = venv
    return out.stdout.strip()


def _pip_freeze(python_exe: str | Path) -> str | None:
    """``pip freeze`` from that interpreter, or None when pip is not there.

    ``--disable-pip-version-check`` keeps pip's own upgrade notice out of the lock.
    """
    try:
        out = subprocess.run(
            [str(python_exe), "-m", "pip", "freeze", "--disable-pip-version-check"],
            capture_output=True, text=True, timeout=180, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else None


#: Our own distribution name. ``pip install renest`` with a shell that has the
#: environment active lands us *inside the very environment being captured* —
#: measured 2026-09-02 on a real one, we came out in its lock as ``renest==0.1.8``.
#: A nest describes the environment that ran the workflow, not that plus us.

#: **Only the line naming us**: the packages we pulled in stay. ``pyyaml`` and
#: ``cryptography`` are used by the app too, and a freeze cannot tell "only here
#: because of us" from "the app needs it" — dropping one it needed gives a nest
#: that rebuilds and then cannot run, worse than carrying an extra line.
_OUR_DIST = "renest"


def drop_ourselves(body: str) -> str:
    """Take the line that names *this tool* out of a freeze. Everything else stays."""
    keep = []
    for line in body.splitlines():
        head = re.split(r"[=<>!~\[ @]", line.strip(), maxsplit=1)[0]
        if head.replace("_", "-").lower() == _OUR_DIST:
            continue
        keep.append(line)
    return "\n".join(keep)


def freeze_environment(python_exe: str | Path) -> str | None:
    """Ask the interpreter which packages it has and at which versions. Returns
    ``None`` when it cannot be read — we report that honestly rather than invent a
    list.

    Three routes, and **the order matters**: uv first, because it understands
    editable installs; **then pip**, which every ordinary environment has; the
    stdlib-only route last, so a machine with neither can still be captured, at the
    cost of not being able to express an editable install.

    **pip earns its place in the middle**: without it a machine that has no uv fell
    straight through to the last route, and a package installed from a repository
    came out as a bare ``name==version`` that no index carries -- a lock that cannot
    be installed, with nothing in the nest saying so.
    """
    body = _uv_freeze(python_exe)
    if body:
        return LOCK_FROM_ENV_HEADER + drop_ourselves(body) + "\n"
    body = _pip_freeze(python_exe)
    if body:
        return LOCK_FROM_ENV_HEADER + drop_ourselves(body) + "\n"
    try:
        out = subprocess.run(
            [str(python_exe), "-c", _FREEZE_SNIPPET],
            capture_output=True, text=True, timeout=180, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    body = out.stdout.strip()
    if not body:
        return None
    return LOCK_FROM_ENV_HEADER + drop_ourselves(body) + "\n"


# -------------------------------------------------- reading it without running it --
# Everything above needs the interpreter to run. A shared all-in-one bundle breaks
# that: 2026-08-13, a Windows bundle packed from a Mac had 132 installed packages and
# we recorded none, because its interpreter was a ``python310.dll`` we cannot execute.
# The files alone answer it -- every installed package leaves a ``.dist-info`` folder
# with its name and version. Weaker than asking the interpreter (an editable install
# has no honest pin here), so it stays the last resort, and the generated file says so.

LOCK_FROM_INSTALLED_HEADER = (
    "# Worked out from the packages installed in this environment, by reading their\n"
    "# own metadata files — there was no lock file, and this environment's Python\n"
    "# could not be found, or could not be run here. Versions are what is installed,\n"
    "# with one line left out: the tool that made this nest (packages it pulled in\n"
    "# are kept, because the app may need them too).\n"
    "# Package hashes and original index URLs were not recorded. Packages installed\n"
    "# from a source folder cannot be expressed this way and are missing here.\n"
)

#: Where a site-packages folder sits, relative to a root we were handed. Bounded on
#: purpose: a whole-tree search over an environment holding hundreds of GB of weights
#: costs minutes and finds nothing extra.
_SITE_PACKAGES_GLOBS = (
    "Lib/site-packages", "lib/site-packages", "lib/python*/site-packages",
    "*/Lib/site-packages", "*/lib/site-packages", "*/lib/python*/site-packages",
    "*/*/Lib/site-packages", "*/*/lib/python*/site-packages",
)


def find_site_packages(*roots: Path) -> Path | None:
    """First site-packages folder found under any of ``roots``, or ``None``."""
    for r in roots:
        if r is None or not r.is_dir():
            continue
        for pattern in _SITE_PACKAGES_GLOBS:
            for hit in sorted(r.glob(pattern)):
                if hit.is_dir():
                    return hit
    return None


def env_dir_of(site_packages: Path) -> Path:
    """The environment root a site-packages folder belongs to.

    Windows lays it out as ``<env>/Lib/site-packages``, POSIX as
    ``<env>/lib/python3.11/site-packages``.
    """
    parent = site_packages.parent
    if parent.name.startswith("python") and parent.parent.name.lower() == "lib":
        return parent.parent.parent
    if parent.name.lower() == "lib":
        return parent.parent
    return parent


def _name_and_version(dist_info: Path) -> tuple[str, str] | None:
    """Read Name/Version out of a dist-info METADATA header block."""
    meta = dist_info / "METADATA"
    if not meta.is_file():
        return None
    name = version = ""
    try:
        with meta.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    break               # headers end at the first blank line
                low = line.lower()
                if low.startswith("name:") and not name:
                    name = line.split(":", 1)[1].strip()
                elif low.startswith("version:") and not version:
                    version = line.split(":", 1)[1].strip()
                if name and version:
                    break
    except OSError:
        return None
    return (name, version) if name and version else None


def installed_dist_infos(site_packages: Path) -> dict[str, Path]:
    """Canonical distribution name -> its ``*.dist-info`` folder, for everything
    installed under ``site_packages``. Read off disk, so it works for an
    environment whose interpreter cannot run here."""
    found: dict[str, Path] = {}
    for d in sorted(site_packages.glob("*.dist-info")):
        pair = _name_and_version(d)
        if pair:
            found.setdefault(canonical_name(pair[0]), d)
    return found


#: Config files that can name the index an environment installs from, relative to the
#: environment root. Read in this order; the first that names one wins. Deliberately
#: short: these are the two files our own restore path and the two installers we
#: support actually write, not every place a setting could conceivably live.
_INDEX_CONFIG_FILES = ("pip.conf", "pip.ini", "uv.toml", ".uv.toml")

#: `index-url = https://...` / `index_url: https://...` / `url = "https://..."`, in
#: either installer's spelling. Only https is picked up -- a plain-http index is not
#: recorded (see the schema: recording one would read as a recommendation).
_INDEX_URL_LINE = re.compile(
    r"""^[^\S\n]*(?:index[-_]url|default[-_]index|url)[^\S\n]*[:=][^\S\n]*["']?(https://[^\s"'#]+)""",
    re.IGNORECASE | re.MULTILINE,
)


def _index_from_direct_url(dist_info: Path) -> str | None:
    """The index a package was installed from, out of its own ``direct_url.json``
    (PEP 610) -- what the installer wrote down at the time, not a guess.

    Only a plain archive URL counts. A `vcs_info` entry names a repository rather than
    an index, and a `dir_info` entry names a folder on the packing machine that exists
    nowhere else; neither answers "which index serves this package", so both are
    passed over rather than recorded as an answer to a different question.
    """
    try:
        info = json.loads((dist_info / "direct_url.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(info, dict) or info.get("vcs_info") or info.get("dir_info"):
        return None
    url = info.get("url")
    if not isinstance(url, str) or not url.startswith("https://"):
        return None
    # Strip back to the index root the wheel hangs off: the full wheel address is the
    # *pinned* answer and belongs in the lock line itself, not here. `.../whl/cu128/
    # torch-2.11.0%2Bcu128-cp311-...whl` -> `.../whl/cu128`.
    base = url.split("#", 1)[0].split("?", 1)[0]
    if not base.lower().endswith((".whl", ".tar.gz", ".zip")):
        return None
    trimmed = base.rsplit("/", 1)[0]
    # Some indexes serve `/<index>/<name>/<file>.whl` (PEP 503 simple layout); drop a
    # last segment that is just the package's own name so both layouts land on the
    # same index root.
    parent, _, last = trimmed.rpartition("/")
    pair = _name_and_version(dist_info)
    if parent.startswith("https://") and pair and canonical_name(last) == canonical_name(pair[0]):
        trimmed = parent
    return trimmed or None


def _index_from_config(*roots: Path) -> str | None:
    """The index configured for this environment, read off its own config files."""
    for r in roots:
        if r is None or not Path(r).is_dir():
            continue
        for name in _INDEX_CONFIG_FILES:
            p = Path(r) / name
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            m = _INDEX_URL_LINE.search(text)
            if m:
                return m.group(1).rstrip("/") or None
    return None


def local_version_sources(
    lock_text: str, site_packages: Path | None, *config_roots: Path
) -> dict[str, dict[str, str]]:
    """``{package: {"index_url": ..., "source": ...}}`` for every lock line still
    pinning a bare vendor-only local version (format 2.11).

    **Only the lines nothing else has already answered.** A line pinned to a direct
    wheel URL carries its address and its hash inside the lock and is the authoritative
    record; it has no entry here, so the two can never disagree about one package. What
    is left is the honest half: `torch==2.11.0+cu128`, a name and a version that no
    public index serves and, until this field, no address anywhere in the nest.

    **Read, never inferred.** Two routes, in order of strength: the package's own
    ``direct_url.json`` (``direct_url``, what the installer recorded at the time), then
    the index this environment is configured to use (``index_config``, weaker -- it says
    where packages came from in general, not where this one did). **There is deliberately
    no third route that works the address back from the ``+cu128`` suffix.** That mapping
    is a table someone would have to keep up to date against a vendor's URL layout, it
    is right until the vendor moves a path, and it would be indistinguishable in the
    manifest from something actually measured. When neither route answers, the package
    is left out -- a nest that says nothing is repairable, one that says something wrong
    sends the person repairing it to the wrong place.
    """
    bare = vendor_only_locals(lock_text)
    if not bare:
        return {}
    names = [ln.split("==", 1)[0].strip() for ln in bare]
    dist_infos = installed_dist_infos(site_packages) if site_packages else {}
    configured = _index_from_config(*config_roots) if config_roots else None
    out: dict[str, dict[str, str]] = {}
    for name in names:
        if not name:
            continue
        di = dist_infos.get(canonical_name(name))
        url = _index_from_direct_url(di) if di is not None else None
        if url:
            out[name] = {"index_url": url, "source": "direct_url"}
        elif configured:
            out[name] = {"index_url": configured, "source": "index_config"}
    return dict(sorted(out.items(), key=lambda kv: kv[0].lower()))


def freeze_from_installed(site_packages: Path) -> str | None:
    """``name==version`` for every package installed under ``site_packages``."""
    found: dict[str, str] = {}
    for d in sorted(site_packages.glob("*.dist-info")):
        pair = _name_and_version(d)
        if pair:
            found.setdefault(pair[0], pair[1])
    if not found:
        return None
    body = "\n".join(f"{n}=={v}" for n, v in sorted(found.items(), key=lambda kv: kv[0].lower()))
    return LOCK_FROM_INSTALLED_HEADER + drop_ourselves(body) + "\n"


#: Start scripts a shared bundle puts beside the application. Only the top two levels
#: are looked at: this is the file a user double-clicks, not something buried deep.
_LAUNCHER_SUFFIXES = (".bat", ".cmd", ".ps1", ".sh", ".command")
#: A start script is a few kilobytes. Anything larger is not one, and reading it would
#: only cost time.
_LAUNCHER_MAX_BYTES = 64 * 1024
_ASSIGNMENT = re.compile(r"^\s*(?:set\s+|export\s+|\$env:)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")
_VAR_REF = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%|\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_SCRIPT_DIR_REF = re.compile(r"%~[a-zA-Z]*0")


def find_launchers(env_root: Path) -> list[Path]:
    """Start scripts sitting at or just below the environment root."""
    if not env_root.is_dir():
        return []
    out = [p for pattern in ("*", "*/*") for p in sorted(env_root.glob(pattern))
           if p.is_file() and p.suffix.lower() in _LAUNCHER_SUFFIXES
           and p.stat().st_size <= _LAUNCHER_MAX_BYTES]
    return out


#: A launcher that calls the interpreter straight, no variable in between:
#: ``.\python_embeded\python.exe -s main.py``, ``"%~dp0venv/bin/python" main.py``.
_DIRECT_CALL = re.compile(r'["\']?((?:[^\s"\';|&]*[\\/])?python(?:\d[\d.]*)?(?:\.exe)?)["\']?(?=\s|$)')

def launcher_interpreter_dir(script: Path) -> Path | None:
    """The interpreter folder a start script points at, if it names one that exists.

    A bundle's launcher spells out what the layout alone only implies -- which folder
    holds the Python, where the entry file is, which extra folders have to be on the
    search path. We read the variable assignments and follow the ones that turn out
    to be a real interpreter folder on disk. Anything we cannot resolve is skipped:
    guessing here would be worse than the layout scan this backs up.
    """
    try:
        text = script.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    here = script.parent
    values: dict[str, str] = {}
    for line in text.splitlines():
        m = _ASSIGNMENT.match(line)
        if not m or line.lstrip().startswith(("#", "::", "rem ", "REM ")):
            continue
        values[m.group(1).upper()] = m.group(2).strip('"')
    for raw in values.values():
        resolved = _expand(raw, values, here)
        if resolved is None:
            continue
        cand = resolved if resolved.is_dir() else resolved.parent
        if interpreter_kernel(cand):
            return cand
    # Launchers that call the interpreter straight, with no variable in between --
    # ``.\python_embeded\python.exe -s main.py`` is the common shape, and reading only
    # assignments missed it entirely (measured 2026-09-02 with this repo's own code:
    # the assignment form resolved, the direct call returned None). Wrong guesses cost
    # nothing here: a candidate is only accepted when the folder really does hold an
    # interpreter, same check as above.
    for m in _DIRECT_CALL.finditer(text):
        resolved = _expand(m.group(1), values, here)
        if resolved is None:
            continue
        cand = resolved.parent if resolved.suffix or not resolved.is_dir() else resolved
        if interpreter_kernel(cand):
            return cand
    return None


def _expand(raw: str, values: dict[str, str], here: Path) -> Path | None:
    """``%PYTHON_ENV%\\python.exe`` -> an absolute path, or ``None`` if we can't."""
    def sub(m: re.Match[str]) -> str:
        name = (m.group(1) or m.group(2) or "").upper()
        return values.get(name, "\x00")     # unknown -> poison, so we give up below
    # Variables are built out of each other (`PYTHON_ENV=%ROOT_DIR%\...`), so one pass
    # only swaps in another variable's still-unexpanded text. Repeat until it settles.
    # `%~dp0` (the folder the script sits in) carries no closing %, unlike everything
    # else in a .bat, so it needs its own pass inside the loop.
    text = raw
    for _ in range(8):
        nxt = _VAR_REF.sub(sub, _SCRIPT_DIR_REF.sub(str(here) + "/", text))
        if nxt == text:
            break
        text = nxt
    text = text.replace("\\", "/")
    if "\x00" in text or "%" in text or "$" in text or not text.strip():
        return None
    p = Path(text.replace("//", "/"))
    if not p.is_absolute():
        p = here / p
    try:
        return p.resolve() if p.exists() else None
    except OSError:
        return None


def interpreter_kernel(env_dir: Path) -> str | None:
    """Which operating-system family this environment's interpreter is built for.

    Read off the files, never off the machine we happen to be running on: told apart
    by ``python.exe``/``pythonNN.dll`` versus a ``bin/python``. ``None`` means we
    could not tell, which must stay distinguishable from "same as here".
    """
    if not env_dir.is_dir():
        return None
    if (env_dir / "python.exe").is_file() or any(env_dir.glob("python*.dll")):
        return "windows"
    if (env_dir / "bin" / "python").exists() or any(env_dir.glob("bin/python3*")):
        return "posix"
    return None


def interpreter_python_series(env_dir: Path) -> str | None:
    """``3.10`` from ``python310.dll`` or ``lib/python3.10/``. Two components only.

    Deliberately not passed off as ``runtime.python_version``: that field is spelled
    ``3.x.y`` and the third number is not written anywhere in these layouts. Half an
    answer belongs in a warning, never in the manifest.
    """
    if not env_dir.is_dir():
        return None
    for dll in sorted(env_dir.glob("python[0-9][0-9]*.dll")):
        digits = dll.stem.removeprefix("python")
        if digits.isdigit() and len(digits) >= 2:
            return f"{digits[0]}.{digits[1:]}"
    for lib in sorted(env_dir.glob("lib/python3.*")):
        if lib.is_dir():
            return lib.name.removeprefix("python")
    return None
