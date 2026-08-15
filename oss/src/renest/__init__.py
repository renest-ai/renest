"""Renest agent CLI (`renest`).

Packs a working GPU setup (an image workflow, or a fine-tuning run) into an
open-format nest and restores it byte-identical on any machine. The nest
format itself is open (Apache-2.0, see specs/), as is the escape hatch under
``escape/`` — this tool reads and writes an open format, but is not itself
open-source software.

Copyright 2026 Tensor Logic Digital, LLC. Licensed as described in the
LICENSE-CLI and NOTICE files distributed with this package.
"""

from __future__ import annotations

__version__ = "0.1.2"

def _supported_manifest_versions() -> tuple[str, ...]:
    """Manifest versions this CLI can read — **derived, never copied by hand**.

    This used to be a hand-written literal, and it drifted: it still claimed the
    1.x format long after the reader had moved to 2.x. That is not a harmless
    documentation slip. The usual reason someone runs ``renest --version`` is to
    answer "can this build read the nest I have?", so a stale literal answers that
    question wrongly; ``serve``'s health endpoint reads the same value, so the
    ComfyUI plugin was told the same wrong thing.

    Deriving it instead of re-copying the right value is the actual fix: a copied
    constant will drift again, while whoever bumps the format only ever remembers
    to edit ``restore.py``. The import is deferred because ``restore`` imports
    this package back.
    """
    from .restore import SUPPORTED_FORMAT_VERSIONS

    return tuple(SUPPORTED_FORMAT_VERSIONS)


def __getattr__(name: str):
    # Lazy: do not touch ``restore`` at import time (it imports this package back).
    if name == "MANIFEST_VERSIONS":
        return _supported_manifest_versions()
    raise AttributeError(name)
