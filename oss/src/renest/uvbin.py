"""Which ``uv`` this tool runs: the copy shipped beside it first, PATH second.

``uv`` is a dependency of this package, so installing renest puts a uv binary next
to the interpreter that runs it. Until 2026-08-15 every call site said ``["uv", ...]``
-- PATH -- so that copy was downloaded on every install (40 MB) and never used, while
a virtualenv that is not activated still died at the dependency step: the exact
failure the dependency was added to prevent. Looking beside the interpreter first
collects the guarantee we already paid for, and pins the uv we tested against.

Nothing here installs anything. A missing uv stays a missing uv, and ``renest doctor``
says so with the command that fixes it.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

#: Windows names it uv.exe; everywhere else it is plain uv.
_EXE_NAME = "uv.exe" if os.name == "nt" else "uv"


def uv_executable() -> str:
    """The uv to run. Never raises: with nothing found it returns ``"uv"``, so the
    caller fails exactly as before -- a missing-binary error that names uv."""
    # Do not resolve() the interpreter path: inside a virtualenv ``python`` is usually
    # a symlink to the system interpreter, and following it lands in the system
    # directory where our own copy is not. Found by installing for real; the unit
    # test used a plain file and could not see it.
    beside = Path(sys.executable).parent / _EXE_NAME
    if beside.is_file() and os.access(beside, os.X_OK):
        return str(beside)
    return shutil.which("uv") or "uv"


def uv_is_available() -> bool:
    """Is there a uv we can actually run? ``renest doctor`` has to ask this the same
    way the rebuild does, or it can pass while the real call fails."""
    return uv_executable() != "uv" or shutil.which("uv") is not None
