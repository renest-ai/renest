"""[SECURITY-REVIEW] Credential-shape scan, run before packing.

The gate sits on the packing side because packing is the irreversible step: once the
bytes are uploaded, withdrawing a hand-off only withdraws the index entry. It covers
``code_deps[].archive`` as well as ``entrypoint.env`` -- an archive is a whole
directory, and a user's scripts folder (no repository, so no .gitignore ever guarded
it) routinely holds a ``.env`` or a deploy key. The exposure hurts the sender, so it
is a hard stop, not a notice.

Precision discipline: a false positive means the user cannot pack at all, so hard
stops fire only on unambiguous shapes -- recognizable prefix plus fixed length, or a
private-key header. Suspicious file *names* (``.env``, ``id_rsa``) only warn; a real
key inside one is caught by shape anyway. Findings never enter the nest, only
``PackReport.findings`` and error text: "this file contains a key" is a signpost.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

__all__ = ["SecretHit", "scan_tree", "scan_file", "scan_recipe_json", "SUSPICIOUS_NAMES"]

#: Only files up to this size are scanned. A key is a short string and will not
#: be hiding inside a 2 GB weights file, while scanning everything blindly would
#: add the whole read to packing time.
_MAX_BYTES = 2 * 1024 * 1024
#: Directories never entered. Kept aligned with the junk list in
#: ``_tar_code_dep``, since those do not go into the nest in the first place.
#: ``site-packages``/``dist-packages`` are here for a different reason, learned
#: 2026-08-13 on a real all-in-one bundle: installed libraries ship their own test
#: fixtures (tornado's test.key, transformers' sample token) and ComfyUI's own
#: ``comfyui-workflow-templates`` ships example JWTs. Those are nobody's credentials,
#: yet they hard-stopped the pack -- i.e. every ComfyUI on earth. The boundary must be
#: the path, not a keyword allowlist: only scan where a user could have typed.
_SKIP_DIRS = frozenset(
    {".git", "__pycache__", ".venv", "venv", "node_modules", ".mypy_cache",
     "site-packages", "dist-packages"}
)

#: Shapes used for a HARD STOP. Every one of them carries a recognizable prefix
#: or a fixed header, so the false-positive rate is very low.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("a Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34,}")),
    ("an OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9]{32,}")),
    ("an AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("a GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}")),
    ("a Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("a private key file", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    # Cloud video/image services hand out signed tokens in this shape. Added as a shape
    # (three base64url parts, fixed header prefix) rather than per vendor: a new hosted
    # model ships every month and the vendor list would never be complete.
    ("a signed access token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
)

#: Filenames that only produce a WARNING: a ``.env`` holding nothing but ``DEBUG=1``
#: is a pure false positive, and a real key inside one is caught by shape anyway.
SUSPICIOUS_NAMES: frozenset[str] = frozenset(
    {".env", ".env.local", ".netrc", "id_rsa", "id_ed25519", "credentials", ".npmrc"}
)


@dataclass(frozen=True)
class SecretHit:
    """One match. ``line`` is 1-based; ``sample`` is a MASKED fragment."""

    path: str
    line: int
    what: str
    sample: str

    def human(self) -> str:
        return f"{self.path}:{self.line} looks like {self.what} ({self.sample})"


def _mask(token: str) -> str:
    """Keep just enough to recognize which credential it was.

    Not even the error text is allowed to print a key in full: terminals get
    screenshotted and pasted into chat, and that is a second leak.
    """
    return token[:6] + "…" + token[-2:] if len(token) > 12 else token[:3] + "…"


def _is_probably_text(head: bytes) -> bool:
    return b"\x00" not in head


def scan_tree(src_dir: Path, *, exclude: frozenset[str] = frozenset()) -> tuple[list[SecretHit], list[str]]:
    """Scan a directory tree. Returns ``(hard-stop hits, suspicious filenames)``.

    ``exclude`` names subdirectories, relative to ``src_dir``, that count as a
    code_dep of their own -- skipping them avoids scanning the same bytes twice.
    """
    hits: list[SecretHit] = []
    suspicious: list[str] = []
    if not src_dir.is_dir():
        return hits, suspicious
    for p in sorted(src_dir.rglob("*")):
        rel = p.relative_to(src_dir)
        if _SKIP_DIRS.intersection(rel.parts) or (rel.parts and rel.parts[0] in exclude):
            continue
        if not p.is_file() or p.is_symlink():
            continue
        if p.name in SUSPICIOUS_NAMES:
            suspicious.append(str(rel))
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
            raw = p.read_bytes()
        except OSError:
            continue
        if not _is_probably_text(raw[:4096]):
            continue
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover - decode with replace does not raise
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for what, pat in _PATTERNS:
                m = pat.search(line)
                if m:
                    hits.append(SecretHit(str(rel), lineno, what, _mask(m.group(0))))
                    break
    return hits, suspicious


def scan_file(path: Path, *, label: str = "") -> list[SecretHit]:
    """Scan a SINGLE file. Recipe files are named into the nest one by one, so no
    directory walk ever reaches them -- yet a ``hub_token`` written straight into a
    training recipe is ordinary practice."""
    if not path.is_file() or path.is_symlink():
        return []
    try:
        if path.stat().st_size > _MAX_BYTES:
            return []
        raw = path.read_bytes()
    except OSError:
        return []
    if not _is_probably_text(raw[:4096]):
        return []
    text = raw.decode("utf-8", errors="replace")
    out: list[SecretHit] = []
    name = label or path.name
    for lineno, line in enumerate(text.splitlines(), 1):
        for what, pat in _PATTERNS:
            m = pat.search(line)
            if m:
                out.append(SecretHit(name, lineno, what, _mask(m.group(0))))
                break
    return out


#: Input names that hold a credential in a recipe. Vendor key *formats* cannot be
#: enumerated -- a new hosted video model ships every month -- but the input *name*
#: can: an API node keeps its key in an input called api_key, token or auth. Being
#: name-driven, this catches vendors we have never heard of.
_SECRET_FIELD = re.compile(
    r"(api[_-]?key|access[_-]?token|auth[_-]?token|bearer|secret|password|passwd)", re.I
)
#: Values that are plainly not a key, so the gate stays quiet on them. An unfilled
#: input is the normal state of a shared workflow and must never block packing.
_PLACEHOLDER_WORDS = ("your", "xxx", "here", "replace", "example", "paste", "todo", "<", ">")
_NOT_A_KEY = frozenset({"", "none", "null", "nil", "false", "true", "0", "1"})
#: Below this length nothing is treated as a credential by name alone.
_MIN_NAMED_SECRET = 16


def _looks_like_a_key(value: str) -> bool:
    v = value.strip()
    if v.lower() in _NOT_A_KEY or len(v) < _MIN_NAMED_SECRET:
        return False
    low = v.lower()
    return not any(w in low for w in _PLACEHOLDER_WORDS)


def scan_recipe_json(path: Path, *, label: str = "") -> list[SecretHit]:
    """[SECURITY-REVIEW] Scan an image-gen recipe for a credential someone typed into it.

    Why this exists as its own scan: a recipe using a hosted model keeps that service's
    key in a plain node input, and a nest is *handed to other people* -- so a key left
    in one leaks to the recipient, not merely to us. The line-based scans miss it twice
    over: a recipe is one long line, and the key's shape is a vendor's private business.
    So both tests run here -- the known shapes, plus any input whose *name* says
    credential and whose value is long enough to be one. The report names the exact
    input, because "somewhere in your recipe" is not something anyone can act on.
    """
    if not path.is_file() or path.is_symlink():
        return []
    try:
        if path.stat().st_size > _MAX_BYTES:
            return []
        import json

        data = json.loads(path.read_text(errors="replace"))
    except (OSError, ValueError):
        return []
    name = label or path.name
    out: list[SecretHit] = []
    seen: set[tuple[str, str]] = set()

    def walk(node: object, trail: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                where = f"{trail}.{k}" if trail else str(k)
                if isinstance(v, str) and _SECRET_FIELD.search(str(k)) and _looks_like_a_key(v):
                    key = (where, "named")
                    if key not in seen:
                        seen.add(key)
                        out.append(SecretHit(f"{name} ({where})", 1,
                                             "a credential typed into the recipe", _mask(v)))
                walk(v, where)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{trail}[{i}]")
        elif isinstance(node, str):
            for what, pat in _PATTERNS:
                m = pat.search(node)
                if m:
                    key = (trail, what)
                    if key not in seen:
                        seen.add(key)
                        out.append(SecretHit(f"{name} ({trail})", 1, what, _mask(m.group(0))))
                    break

    walk(data, "")
    return out
