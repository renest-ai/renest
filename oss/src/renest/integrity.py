"""Bad-byte health checks: model structure probes plus dirty-git probes.

sha256 answers "did the bytes change", never "are the bytes right": a
half-downloaded .safetensors, or a clone that pulled down nothing but Git LFS
pointer text, is reproduced just as faithfully — a nest that passes every
checksum and crashes the moment the app starts. Capture, pack / lint and restore
all call in here, so the same judgement is made at every end.

Two rules hold everywhere: **report, never block** (an unsure probe says "looks
like / please confirm yourself"; lint warns, and only ``--strict`` makes it an
error), and **stay cheap** (a few bytes of head or tail, never a full parse,
never a model library import).
"""

from __future__ import annotations

import json
import re
import subprocess
import tomllib
from pathlib import Path

__all__ = [
    "GGUF_MAGIC",
    "PROBED_SUFFIXES",
    "TINY_BYTES",
    "WEIGHT_SUFFIXES",
    "declared_base_model",
    "dirty_gap",
    "git_dirty",
    "git_identity",
    "is_probed",
    "looks_like_lfs_pointer",
    "probe_model_bytes",
    "run_git",
    "safetensors_metadata",
]

TINY_BYTES = 1024               # any "model" this small is suspect (real weights are MBs)
LFS_POINTER_PREFIX = b"version https://git-lfs"
GGUF_MAGIC = b"GGUF"
ZIP_MAGIC = b"PK\x03\x04"       # a torch>=1.6 .pt/.ckpt is just a zip
ZIP_EOCD = b"PK\x05\x06"        # end of the zip directory; missing = truncated
PICKLE_PROTOS = frozenset({b"\x02", b"\x03", b"\x04", b"\x05"})  # old torch.save bare pickle
MAX_HEADER_BYTES = 100 << 20    # a safetensors JSON header should never exceed this

_TORCH_CONTAINER = frozenset({".ckpt", ".pt", ".pth"})
#: Extensions that have a structure probe (we can check whether the skeleton of
#: this pile of bytes is right).
PROBED_SUFFIXES = frozenset({".safetensors", ".gguf"}) | _TORCH_CONTAINER
#: Extensions we recognise as "this is supposed to be a weight file" -- only these
#: get the "suspiciously small" judgement. A .yaml or .png is legitimately tiny,
#: and false alarms teach people to ignore alarms.
WEIGHT_SUFFIXES = PROBED_SUFFIXES | frozenset({".bin", ".onnx", ".sft"})


def is_probed(name: str) -> bool:
    """Does this name's extension have a structure probe?

    For callers that want to count or pre-select; the probe itself already
    filters by extension.
    """
    return Path(name).suffix.lower() in PROBED_SUFFIXES


def looks_like_lfs_pointer(path: Path, size: int | None = None) -> bool:
    """Is this file Git LFS pointer text standing in for the real content?

    A pointer is a few hundred bytes of text, so anything from ``TINY_BYTES``
    (1 KiB) up is real content and never gets opened. Unreadable -> False: this
    answers "is it definitely a pointer", never "is it fine".
    """
    try:
        if size is None:
            size = path.stat().st_size
        if size >= TINY_BYTES:
            return False
        with path.open("rb") as f:
            return f.read(len(LFS_POINTER_PREFIX)).startswith(LFS_POINTER_PREFIX)
    except OSError:
        return False


def probe_model_bytes(
    path: Path, size: int | None = None, *, logical_name: str | None = None
) -> str | None:
    """Cheap structure probe: do these bytes look like a whole model?

    Returns a plain-language description of the problem, or None if healthy. Safe
    to call on any file: the probe picks its work by extension, and what it does
    not recognise it neither guesses at nor reports.

    ``logical_name`` is for content-addressed storage: a blob is named after its
    hash and has no extension, so the caller passes the manifest path -- the probe
    picks the structure from it and speaks in terms of it.
    """
    name = Path(logical_name or path.name).name
    suffix = Path(name).suffix.lower()
    try:
        if size is None:
            size = path.stat().st_size
        # 1. Git LFS pointer / suspiciously small file: a scrap of text or a
        #    placeholder, not a real model.
        if size < TINY_BYTES:
            if looks_like_lfs_pointer(path, size):
                return (f"{name} is only {size}B of Git LFS pointer text, not a real "
                        f"model — the clone most likely skipped the big LFS files. "
                        f"Swap in the real weights before you pack.")
            if suffix in WEIGHT_SUFFIXES:
                return (f"{name} is only {size}B, far too small for a model file — "
                        f"looks like a broken download or a placeholder. "
                        f"Please check it yourself before you pack.")
            return None
        if suffix == ".safetensors":
            return _probe_safetensors(path, size, name)
        if suffix in _TORCH_CONTAINER:
            return _probe_torch_container(path, size, name)
        if suffix == ".gguf":
            return _probe_gguf(path, size, name)
    except OSError as e:
        return (f"Can't read {name} ({e}), so we couldn't check whether it is a "
                f"whole model. Please check it yourself before you pack.")
    return None


#: The one digest of a base model that is comparable with the addresses used
#: everywhere else here: the whole file. Trainers also write a 32-bit window
#: digest under a similar name, and two more that skip the header -- none of
#: those can be matched against a content address, so none are read.
_WHOLE_FILE_BASE_HASH_KEY = "ss_new_sd_model_hash"
_BASE_FAMILY_KEY = "ss_base_model_version"


def safetensors_metadata(path: Path) -> dict | None:
    """The ``__metadata__`` block of a safetensors file, or ``None``.

    Reads the header only -- a few kilobytes -- so it costs nothing on a 20 GB
    file. Never raises: an unreadable or truncated file is an ordinary case here
    and must not stop a pack.
    """
    try:
        with path.open("rb") as f:
            raw = f.read(8)
            if len(raw) < 8:
                return None
            n = int.from_bytes(raw, "little")
            if n <= 0 or n > MAX_HEADER_BYTES:
                return None
            header = json.loads(f.read(n))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict):
        return None
    meta = header.get("__metadata__")
    return meta if isinstance(meta, dict) else None


def declared_base_model(path: Path) -> dict | None:
    """Copy across what this file's header says about the model it was trained on.

    A transcription, never a judgement: the trainer wrote these values, we name
    where they came from and stop there. Whether an asset and a base model go
    together is not decided here.

    Returns ``None`` when the header says nothing about it -- which must be read
    as "the header was silent", not "there is no base model".
    """
    meta = safetensors_metadata(path)
    if not meta:
        return None
    out: dict[str, str] = {}
    got = str(meta.get(_WHOLE_FILE_BASE_HASH_KEY) or "").strip().lower()
    # Lower case on purpose: one public index answers in upper case while
    # trainers write lower, so a plain comparison would fail.
    if len(got) == 64 and all(c in "0123456789abcdef" for c in got):
        out["sha256"] = got
    family = str(meta.get(_BASE_FAMILY_KEY) or "").strip()
    if family and family.lower() != "none":
        out["family"] = family
    if not out:
        return None
    out["stated_by"] = "safetensors_header"
    return out


def _probe_safetensors(path: Path, size: int, name: str) -> str | None:
    """The first 8 bytes, little-endian, are the JSON header length N; then N
    bytes of JSON; then the tensor data area. That is enough to tell whether
    the header is complete and whether the tensors it declares are cut off by
    the end of the file."""
    with path.open("rb") as f:
        raw = f.read(8)
        if len(raw) < 8:
            return (f"{name} is under 8 bytes — even the .safetensors header is "
                    f"incomplete. The file is broken.")
        n = int.from_bytes(raw, "little")
        if n <= 0 or n > size - 8 or n > MAX_HEADER_BYTES:
            return (f"{name} declares a .safetensors header of {n} bytes, which "
                    f"doesn't fit in its {size}B — the file was cut short, or it "
                    f"isn't a real safetensors.")
        try:
            header = json.loads(f.read(n))
        except (ValueError, UnicodeDecodeError):
            return (f"{name} has an unreadable .safetensors header — the file is "
                    f"broken or only half downloaded.")
    if not isinstance(header, dict):
        return (f"{name}'s .safetensors header isn't a JSON object — this isn't a "
                f"real safetensors file.")
    declared_end = 0
    for key, meta in header.items():
        if key == "__metadata__":
            continue
        if isinstance(meta, dict) and isinstance(meta.get("data_offsets"), list):
            try:
                declared_end = max(declared_end, int(meta["data_offsets"][1]))
            except (IndexError, TypeError, ValueError):
                return (f"{name}'s .safetensors header has a malformed data_offsets "
                        f"entry for {key} — the file is broken.")
    if 8 + n + declared_end > size:
        return (f"{name} says its weights run to {8 + n + declared_end}B but the "
                f"file is only {size}B — it was cut short, so the model is incomplete.")
    return None


def _probe_torch_container(path: Path, size: int, name: str) -> str | None:
    """The two legal shapes of a .ckpt/.pt/.pth: a torch>=1.6 zip container, or an
    old-style bare pickle. Neither means this is not a weight file at all (half a
    download, an error page saved to disk); a zip whose tail has no directory
    record was truncated."""
    with path.open("rb") as f:
        head = f.read(4)
        if head.startswith(ZIP_MAGIC):
            tail_span = min(size, 1 << 16)      # the zip tail may carry a comment; 64 KiB is enough
            f.seek(size - tail_span)
            if ZIP_EOCD not in f.read(tail_span):
                return (f"{name} is a zip-style torch model but its end-of-archive "
                        f"record is missing — the file was cut short (the download "
                        f"or the write stopped partway), so the model is incomplete.")
            return None
        if head[:1] == b"\x80" and head[1:2] in PICKLE_PROTOS:
            return None                          # old-style torch.save bare pickle, legal
    return (f"{name} doesn't start like a torch model — it is neither a zip nor a "
            f"pickle (it starts with {head.hex()}). You probably downloaded an error "
            f"page or a placeholder. Please check it yourself before you pack.")


def _probe_gguf(path: Path, size: int, name: str) -> str | None:
    """GGUF: the magic "GGUF", a little-endian uint32 version, a uint64 tensor
    count and a uint64 metadata (KV) count. We only check that those leading
    header bytes are self-consistent and never parse the KV area (stay
    cheap)."""
    with path.open("rb") as f:
        head = f.read(24)
    if not head.startswith(GGUF_MAGIC):
        return (f"{name} doesn't start with the GGUF marker (it starts with "
                f"{head[:4].hex()}) — this isn't a real gguf model, probably a wrong "
                f"download or a placeholder. Please check it yourself before you pack.")
    if len(head) < 24:
        return (f"{name} is under 24 bytes — even the GGUF header is incomplete. "
                f"The file is broken.")
    version = int.from_bytes(head[4:8], "little")
    if not 1 <= version <= 3:
        return (f"{name} claims GGUF format version {version} (only 1, 2 and 3 exist "
                f"today) — the file is broken, or it uses a newer format this tool "
                f"doesn't know yet. Please check it yourself before you pack.")
    n_tensors = int.from_bytes(head[8:16], "little")
    n_kv = int.from_bytes(head[16:24], "little")
    if n_tensors > (1 << 22) or n_kv > (1 << 22):
        return (f"{name}'s GGUF header claims {n_tensors} tensors and {n_kv} metadata "
                f"entries — impossibly many, so the header bytes are damaged. "
                f"Please check it yourself before you pack.")
    return None


# ------------------------------------------------------------------ git ----

def run_git(cwd: Path, *args: str) -> str | None:
    """Run git as a subprocess (GPL isolation: read its metadata only, never
    import or vendor any of its code).
    Returns None on failure or empty output; never raises."""
    try:
        r = subprocess.run(["git", "-C", str(cwd), *args],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def git_identity(repo_dir: Path) -> dict | None:
    """Read a repository's remote url + HEAD commit; returns None when either
    is missing (report honestly, never invent).

    We must confirm the repository root is this directory itself: with no .git of
    its own, git -C walks upwards to the enclosing repository and pins the host's
    identity onto an extension package -- wrong coordinates are more dangerous
    than no coordinates."""
    toplevel = run_git(repo_dir, "rev-parse", "--show-toplevel")
    if not toplevel or Path(toplevel).resolve() != repo_dir.resolve():
        return None
    commit = run_git(repo_dir, "rev-parse", "HEAD")
    url = run_git(repo_dir, "remote", "get-url", "origin")
    if not commit or not re.fullmatch(r"[a-f0-9]{40}", commit) or not url:
        return None
    return {"repo_url": url, "commit": commit}


def registry_identity(node_dir: Path) -> dict | None:
    """Read where a node came from out of its own ``pyproject.toml`` -- the
    second source of identity, next to git.

    Needed because the ComfyUI desktop build and the node manager install from
    the node registry by default, and what lands has **no .git**: accept only git
    and most nodes in a real environment cannot say where they came from. A
    registry node must declare ``[tool.comfy] PublisherId/Repository`` in order to
    publish, so that declaration is the origin itself.

    Returns ``{"repo_url": ...}`` **without a commit** -- a registry package
    carries none, and inventing one would be fabrication. Unreadable url -> None.
    """
    pyproject = node_dir / "pyproject.toml"
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    comfy = data.get("tool", {}).get("comfy", {})
    url = comfy.get("Repository") or data.get("project", {}).get("urls", {}).get("Repository")
    if not isinstance(url, str) or not url.startswith(("https://", "http://", "git@")):
        return None
    return {"repo_url": url}


def git_dirty(repo_dir: Path) -> dict | None:
    """Check whether a repository has uncommitted changes.

    A rebuild re-clones a clean copy from repo_url+commit, so hand edits that were
    never committed evaporate and the workflow mysteriously stops working. Report
    it before packing and let people commit or revert it themselves.
    Returns {tracked: n, untracked: m, sample: [...]} or None (clean, or we could
    not check).

    **First confirm repo_dir is itself the repository root**: otherwise ``git
    status`` reports against the enclosing repository, and unrelated files drown
    the signal this warning exists to give.
    """
    top = run_git(repo_dir, "rev-parse", "--show-toplevel")
    if not top:
        return None
    try:
        same = Path(top).resolve() == Path(repo_dir).resolve()
    except OSError:  # pragma: no cover
        same = False
    if not same:
        return None
    out = run_git(repo_dir, "status", "--porcelain")
    if not out:
        return None
    tracked, untracked, sample = 0, 0, []
    for line in out.splitlines():
        if not line.strip():
            continue
        # Note: run_git strips its output, which eats the leading space on the
        # first porcelain line, so split rather than slice at fixed widths.
        parts = line.split(maxsplit=1)
        code = parts[0]
        rel = parts[1].strip() if len(parts) > 1 else ""
        if code == "??":
            untracked += 1
        else:                       # M/A/D/R/C etc = tracked file edited (edits that get lost)
            tracked += 1
            if len(sample) < 4 and rel:
                sample.append(rel)
    # A tree unpacked on Windows has every line ending in CR-LF while the repository
    # holds LF, so `git status` calls the whole checkout modified. Measured on a real
    # shared bundle: 406 files "changed", exactly one of them really was -- and that
    # one mattered (42 added lines pulling in a package the requirements never named).
    # Counting the noise buries the signal, so ask git again with line endings ignored
    # and report the two numbers apart.
    real = _content_changed_files(repo_dir)
    line_endings_only = 0
    if real is not None and tracked:
        line_endings_only = max(0, tracked - len(real))
        tracked = len(real)
        sample = sorted(real)[:4]
    if tracked == 0 and untracked == 0 and line_endings_only == 0:
        return None
    return {"tracked": tracked, "untracked": untracked, "sample": sample,
            "line_endings_only": line_endings_only}


def _content_changed_files(repo_dir: Path) -> set[str] | None:
    """Tracked files that differ from HEAD by more than their line endings.

    ``--numstat`` honours ``--ignore-cr-at-eol``; ``--name-only`` does not and
    lists every file regardless, which is the trap this exists to avoid.
    ``None`` means we could not ask (no HEAD yet), and the caller keeps its own count.
    """
    out = run_git(repo_dir, "diff", "--ignore-cr-at-eol", "--numstat", "HEAD")
    if out is None:
        return set() if run_git(repo_dir, "rev-parse", "HEAD") else None
    files = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[-1].strip():
            files.add(parts[-1].strip())
    return files


def dirty_gap(label: str, repo_dir: Path) -> str | None:
    """Dirty git -> one plain-language gap/warning (one shared wording for all
    three ends; nobody gets to write their own version). None when clean."""
    dirty = git_dirty(repo_dir)
    if not dirty or not dirty["tracked"]:
        return None
    # The line-endings count rides along instead of being dropped: seeing "and 405
    # more differ only in line endings" is what tells someone their checkout came out
    # of a Windows zip, rather than leaving them to wonder where 405 warnings went.
    endings = dirty.get("line_endings_only") or 0
    tail = (f" ({endings} more file(s) differ only in how lines end — normal for a "
            f"folder unpacked on Windows, nothing is lost there.)" if endings else "")
    return (f"{label} has {dirty['tracked']} uncommitted code change(s) "
            f"(such as {', '.join(dirty['sample'])}) — a restore pulls a clean copy "
            f"from git, so these hand edits will be lost. Commit or undo them before "
            f"you pack, or accept losing them." + tail)


# --------------------------------------------------------------------------
# Does loading this file execute code / was this code modified
# --------------------------------------------------------------------------
#: safetensors: the first 8 bytes are a little-endian length. We never parse the
#: JSON that follows -- telling the type apart needs no content.
_ST_SUFFIXES = (".safetensors", ".sft")
#: Python's serialization format (pickle). **Loading it executes code.** In this
#: ecosystem `.pt`/`.pth`/`.ckpt`/`.bin` are pickle-wrapped weights.
_PICKLE_SUFFIXES = (".ckpt", ".pt", ".pth", ".bin", ".pkl")
#: Opening byte of a pickle stream, followed by the protocol number.
_PICKLE_MAGIC = b"\x80"
#: Zip opening bytes (PyTorch's newer .pt is a zip with a pickle inside).
_ZIP_MAGIC = b"PK\x03\x04"


def serialization_of(path: Path, *, logical_name: str | None = None) -> str | None:
    """Does loading this file **execute code**: ``safetensors`` / ``pickle`` /
    ``other``.

    The `.ckpt`/`.pt` family is Python's serialization format and **loading it
    executes code**; `safetensors` is only data. The file header tells them apart.

    **A different split from ``kind``**: ``kind`` splits by purpose (checkpoint /
    lora / vae), this by format -- a lora may be either.

    **Cannot tell -> None: leave the slot empty, never make one up.**

    ``logical_name``: a content-addressed blob is named after its hash and has no
    extension, so the caller passes the logical path from the manifest.
    """
    name = Path(logical_name or path.name).name
    suffix = Path(name).suffix.lower()
    try:
        with path.open("rb") as f:
            head = f.read(8)
    except OSError:
        return None
    if not head:
        return None

    if suffix in _ST_SUFFIXES:
        # The first 8 bytes are a length, not the opening of an executable
        # stream -- if it matches we accept it, if not we do not guess.
        if not head.startswith(_PICKLE_MAGIC) and not head.startswith(_ZIP_MAGIC):
            return "safetensors"
        return None
    if suffix in _PICKLE_SUFFIXES:
        if head.startswith(_PICKLE_MAGIC) or head.startswith(_ZIP_MAGIC):
            return "pickle"
        return None
    # Outside the two kinds we recognise: data is data -- do not call a
    # json/txt/png something that "might execute code".
    if head.startswith(_PICKLE_MAGIC):
        return "pickle"
    return "other"


def upstream_match(repo_dir: Path) -> dict | None:
    """Does this code **match the upstream version it claims**.

    This is the one line of disclosure that catches "take a popular extension and
    add three lines of your own" -- a change that hides among thousands of lines
    and that the recipient will never spot by eye.

    Three states: ``clean`` (upstream identity, nothing uncommitted);
    ``modified`` (upstream identity plus uncommitted changes, count attached);
    ``no_upstream`` (in no repository at all -- an honest state, since a training
    user's configs and launch scripts often live in none).

    **No git identity -> None and the whole block is omitted; never a guess.**
    """
    if not repo_dir.is_dir():
        return None
    ident = git_identity(repo_dir)
    if ident is None:
        # Being in no repository at all is not the same as failing to read the
        # repository. The first is a fact, the second is us not knowing.
        toplevel = run_git(repo_dir, "rev-parse", "--show-toplevel")
        if not toplevel:
            return {"state": "no_upstream"}
        return None
    dirty = git_dirty(repo_dir)
    if dirty and dirty.get("tracked"):
        return {"state": "modified", "changed_files": int(dirty["tracked"])}
    return {"state": "clean"}
