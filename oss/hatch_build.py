"""Strip the internal notes out of the rules data while the package is built.

The rules files carry `note` / `provenance` keys written for ourselves: what a
threshold is based on, where our own coverage is still thin. The data is public,
the reasoning is not -- the published rules bundle has been stripped since
2026-08-09, and this hook makes the wheel and the sdist say the same thing.

Only note-shaped keys are removed. Every value the tool reads stays as it is,
so a stripped file drives exactly the same decisions as the one in the repo.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

try:
    from hatchling.builders.hooks.plugin.interface import BuildHookInterface
except ImportError:  # also imported as a plain module by the publishing script
    BuildHookInterface = object

#: Keys that hold reasoning rather than data.
NOTE_KEYS = ("note", "provenance", "coverage_note", "boundary_note")

#: Rules data, relative to the project root, and where it lands in each artifact.
DATA_DIR = "src/renest/data"
TARGET_PREFIX = {"wheel": "renest/data", "sdist": DATA_DIR}


def is_note_key(key: str) -> bool:
    return key in NOTE_KEYS or key.endswith(("_note", "_notes"))


def strip_notes(node):
    """Drop note-shaped keys anywhere in the tree; leave every other value alone."""
    if isinstance(node, dict):
        return {k: strip_notes(v) for k, v in node.items() if not is_note_key(k)}
    if isinstance(node, list):
        return [strip_notes(x) for x in node]
    return node


def strip_file(src: Path, dest: Path) -> Path:
    """Write a stripped copy of one rules file, keeping the original key order."""
    data = strip_notes(json.loads(src.read_text(encoding="utf-8")))
    dest.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return dest


class CustomBuildHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version, build_data):
        prefix = TARGET_PREFIX.get(self.target_name)
        if prefix is None:
            return
        self._tmp = tempfile.mkdtemp(prefix="renest-rules-")
        root = Path(self.root) / DATA_DIR
        # The whole data tree, licence catalogue included: one rule to remember,
        # and no shipped file reads a note key anyway.
        for src in sorted(root.rglob("*.json")):
            # Publishing intermediates are excluded from the build already; they
            # must not sneak back in through a forced include.
            if src.name.endswith((".signed.json", ".public.json")):
                continue
            rel = src.relative_to(root)
            dest = Path(self._tmp) / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            build_data["force_include"][str(strip_file(src, dest))] = f"{prefix}/{rel.as_posix()}"

    def finalize(self, version, build_data, artifact_path):
        shutil.rmtree(getattr(self, "_tmp", ""), ignore_errors=True)
