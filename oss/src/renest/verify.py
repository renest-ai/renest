"""Nest verification — bytes / image / report.

The last gate, runnable on its own after a restore or on suspected drift.

* ``bytes``: per-file sha256 of the target tree against the manifest's ``files[]``,
  classified into missing / hash-mismatch / ok; any discrepancy exits
  S2_HASH_MISMATCH.
* ``image``: compares a picture you rendered against a baseline **only nests packed
  before 2026-08-11 carry** -- packing stores none since and never will, so for
  anything newer this answers "nothing to compare, and that is normal". Needs an
  injected verifier (and a GPU); below threshold exits S5_IMAGE_MISMATCH.
* ``report``: full JSON report to a file (``--report FILE``).

verify judges, never repairs -- repair is ``restore --resume`` or a re-run.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .errors import ExitCode
from .events import EventEmitter
from .restore import LOCKFILE_LANDING_REL

__all__ = [
    "ByteDiff",
    "ImageResult",
    "VerifyReport",
    "run_from_args",
    "verify",
    "verify_bytes",
]

#: image verifier: (manifest, target, threshold) -> (ok, ssim, detail)
ImageVerifier = Callable[[dict, Path, float], "ImageResult"]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class ByteDiff:
    ok: int = 0
    missing: list[str] = field(default_factory=list)  # declared path absent on disk
    mismatch: list[dict] = field(default_factory=list)  # {path, expected, got, reason}

    @property
    def passed(self) -> bool:
        return not self.missing and not self.mismatch


@dataclass
class ImageResult:
    ok: bool
    ssim: float | None = None
    threshold: float = 0.98
    detail: str = ""
    #: where the freshly rendered picture landed (only set when --render was used)
    rendered_path: str | None = None
    #: where the side-by-side comparison picture landed. Written on pass and on fail
    #: alike: a similarity number cannot say the picture is right (two identical grey
    #: images also score 1.0), so it always goes to a human eye.
    side_by_side_path: str | None = None


@dataclass
class VerifyReport:
    ok: bool = False
    exit_code: int = int(ExitCode.OK)
    level: str = "bytes"
    nest_id: str = ""
    bytes_diff: ByteDiff | None = None
    image: ImageResult | None = None
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "exit_code": self.exit_code,
            "level": self.level,
            "nest_id": self.nest_id,
            "bytes": asdict(self.bytes_diff) if self.bytes_diff is not None else None,
            "image": asdict(self.image) if self.image is not None else None,
            "summary": self.summary,
        }


def _check_one(diff: ByteDiff, path_label: str, dest: Path, blob: dict) -> None:
    if not dest.is_file():
        diff.missing.append(path_label)
        return
    size = dest.stat().st_size
    if size != blob["size_bytes"]:
        diff.mismatch.append(
            {
                "path": path_label,
                "expected": blob["sha256"],
                "got": None,
                "reason": f"size {size} ≠ {blob['size_bytes']}",
            }
        )
        return
    got = _sha256_file(dest)
    if got != blob["sha256"]:
        diff.mismatch.append(
            {
                "path": path_label,
                "expected": blob["sha256"],
                "got": got,
                "reason": "sha256 does not match",
            }
        )
    else:
        diff.ok += 1


def verify_bytes(manifest: dict, target: Path) -> ByteDiff:
    """Full per-file sha256 of ``files[]`` plus the landed lock file, classified.

    The lock file (:data:`renest.restore.LOCKFILE_LANDING_REL`) is checked here too,
    so "byte-for-byte identical" covers it and not just the ``files[]`` entries."""
    diff = ByteDiff()
    for f in manifest.get("files", []):
        _check_one(diff, f["path"], target / f["path"], f["blob"])
    pl = manifest.get("python_lock")
    if pl and "lockfile" in pl:
        _check_one(diff, LOCKFILE_LANDING_REL, target / LOCKFILE_LANDING_REL, pl["lockfile"])
    return diff


def verify(
    manifest: dict,
    target: str | os.PathLike[str],
    *,
    level: str = "both",
    ssim_threshold: float = 0.98,
    image_verifier: ImageVerifier | None = None,
    emitter: EventEmitter | None = None,
) -> VerifyReport:
    """Verify a restored target against a manifest. ``level`` ∈
    ``bytes`` / ``image`` / ``both``. Never raises for a verification failure —
    the report's ``exit_code`` carries the verdict."""
    target = Path(target)
    report = VerifyReport(level=level, nest_id=manifest.get("id", ""))

    if level in ("bytes", "both"):
        diff = verify_bytes(manifest, target)
        report.bytes_diff = diff
        if emitter is not None:
            emitter.log(
                f"Byte check: {diff.ok} match / {len(diff.missing)} missing / "
                f"{len(diff.mismatch)} differ",
                stage="S2",
            )
        if not diff.passed:
            report.exit_code = int(ExitCode.S2_HASH_MISMATCH)
            report.summary = (
                f"Byte check failed: {len(diff.missing)} missing, "
                f"{len(diff.mismatch)} with the wrong bytes or size"
            )
            report.ok = False
            return report

    if level in ("image", "both"):
        if image_verifier is None:
            report.exit_code = int(ExitCode.USAGE)
            report.summary = (
                "Checking by re-rendering needs a GPU and a renderer "
                "(no image_verifier was provided); without a GPU use --check bytes"
            )
            report.ok = False
            return report
        img = image_verifier(manifest, target, ssim_threshold)
        report.image = img
        if emitter is not None:
            emitter.log(f"Image check: SSIM {img.ssim} (threshold {img.threshold})", stage="S5")
        if not img.ok:
            report.exit_code = int(ExitCode.S5_IMAGE_MISMATCH)
            report.summary = f"Image check failed: SSIM {img.ssim} < {img.threshold}"
            report.ok = False
            return report

    report.ok = True
    report.exit_code = int(ExitCode.OK)
    parts = []
    if report.bytes_diff is not None:
        parts.append(f"{report.bytes_diff.ok} files byte-checked")
    if report.image is not None:
        parts.append(f"image similarity {report.image.ssim}")
    report.summary = "Verified (" + ", ".join(parts) + ")"
    if report.image is not None and report.image.side_by_side_path:
        # Hand the picture over even on a pass: similarity is a number and cannot
        # prove the picture is right. What needs a human eye goes to the human.
        report.summary += (
            f"\n  The two pictures side by side: {report.image.side_by_side_path}"
            f"\n  Look at it — the number cannot tell you the picture is right."
        )
    return report


def _evidence_dir(target: Path) -> Path:
    """Where the evidence of this one check goes.

    Same layout as the restore side: ``.renest/evidence/<this-run>/``. One directory
    per run is a rule, not taste: remote machines are ephemeral, and anything left
    outside the run directory gets missed when the evidence is pulled off in a hurry.
    """
    import time
    import uuid

    from renest.restore import EVIDENCE_REL

    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    return Path(target) / EVIDENCE_REL / run_id / "image-check"


def _rendered_image_verifier(rendered: str, out_dir: Path | None = None):
    """Compare a picture the user rendered themselves against the nest's baseline.

    This half never renders: that would spend their GPU, and their money on a rented
    machine, without asking. When to pay for the rendering half is their call.

    The baseline comes from ``adapters.comfyui.verified_run.output_samples``, which
    **packing has never written since 2026-08-11 and never will**: keeping a sample
    would mean holding the user's own artwork and handing it on with the nest. So this
    half only ever answers for nests packed before that, and its "no baseline" branch
    is the normal answer, not a fault in the nest. No other picture is substituted.
    """
    def _verify(manifest: dict, target: Path, threshold: float) -> ImageResult:
        from renest.proof_image import compare_images

        run = ((manifest.get("adapters") or {}).get("comfyui") or {}).get("verified_run") or {}
        samples = run.get("output_samples") or []
        if not samples:
            return ImageResult(
                ok=False,
                threshold=threshold,
                detail="This nest carries no sample picture from packing time, and by "
                       "design it never will — keeping one would mean holding your "
                       "artwork and passing it on with the nest, so we do not. Nothing "
                       "is wrong with this nest. Check the bytes instead "
                       "(--check bytes); to know the rebuilt environment still works, "
                       "restore it and let it run the recipe once.",
            )
        sha = (samples[0] or {}).get("sha256") or ""
        baseline = Path(target) / ".renest" / "evidence" / f"baseline-{sha[:12]}.png"
        if not baseline.is_file():
            found = [
                p for p in (Path(target) / ".renest").rglob("*")
                if p.is_file() and _sha256_file(p) == sha
            ]
            if not found:
                return ImageResult(
                    ok=False,
                    threshold=threshold,
                    detail=f"Cannot find the sample picture from packing time "
                           f"(fingerprint {sha[:12]}…) under {target}/.renest/. "
                           f"It travels with the nest — restore it first, then check again.",
                )
            baseline = found[0]
        try:
            result = compare_images(
                baseline, Path(rendered),
                out_dir=out_dir or _evidence_dir(target),
                threshold=threshold,
            )
        except (RuntimeError, OSError) as exc:
            return ImageResult(ok=False, threshold=threshold, detail=str(exc))
        return ImageResult(
            ok=result.ok,
            ssim=result.ssim,
            threshold=threshold,
            detail=result.detail,
            rendered_path=str(rendered),
            side_by_side_path=str(result.side_by_side) if result.side_by_side else None,
        )

    return _verify


def _rendering_image_verifier(*, assume_yes: bool = False):
    """The half that renders: start the rebuilt app, run the workflow this nest
    recorded, compare the output.

    It must ask first -- rendering occupies this machine's GPU, which is real money
    on a rented one. No yes, no run; a non-interactive terminal counts as a no.
    """
    def _verify(manifest: dict, target: Path, threshold: float) -> ImageResult:
        from renest.proof_image import ask_before_rendering, render_recorded_workflow
        from renest.restore import ComfyUILauncher

        evidence = _evidence_dir(target)
        if not ask_before_rendering(assume_yes=assume_yes):
            return ImageResult(
                ok=False,
                threshold=threshold,
                detail="Rendering was not run (you did not confirm). The byte check "
                       "above still stands; run again with --render and answer yes, "
                       "or render it yourself and pass --rendered <file>.",
            )
        comfy = (manifest.get("adapters") or {}).get("comfyui") or {}
        wf_blob = comfy.get("workflow") or {}
        wf_sha = wf_blob.get("sha256") or ""
        target = Path(target)
        wf_files = [
            p for p in target.rglob("*.json")
            if p.is_file() and _sha256_file(p) == wf_sha
        ] if wf_sha else []
        if not wf_files:
            return ImageResult(
                ok=False,
                threshold=threshold,
                detail="This nest records no workflow to run (or it is missing from the "
                       "rebuilt folder), so there is nothing to render.",
            )
        workflow = json.loads(wf_files[0].read_text())

        # The working directory follows the same rule as S4: honour entrypoint.cwd
        # first (the format decides), and otherwise find the host through the
        # code_deps entry whose role == "host" -- never by guessing from its name.
        ep = manifest.get("entrypoint")
        deps = manifest.get("code_deps") or []
        if isinstance(ep, dict) and ep.get("cwd"):
            app_dir = target / ep["cwd"]
        else:
            host = next((d for d in deps if d.get("role") == "host"), deps[0] if deps else None)
            app_dir = target / host["install_path"] if host else target
        python_bin = target / ".venv" / "bin" / "python"
        if not python_bin.is_file():
            return ImageResult(
                ok=False,
                threshold=threshold,
                detail=f"Cannot find the rebuilt Python environment at {python_bin} — "
                       f"restore this nest first, then check again.",
            )
        launcher = ComfyUILauncher()
        handle = launcher.launch(
            app_dir, python_bin,
            evidence / "render.log",
            entrypoint=manifest.get("entrypoint"),
        )
        try:
            rendered = render_recorded_workflow(
                port=handle.port,
                workflow=workflow,
                out_dir=evidence / "rendered",
            )
        except RuntimeError as exc:
            return ImageResult(ok=False, threshold=threshold, detail=str(exc))
        finally:
            with contextlib.suppress(Exception):
                launcher.shutdown(handle)
        # All evidence of one check lands under the same run directory: split across
        # two places, one half gets missed when the evidence is collected.
        return _rendered_image_verifier(str(rendered), out_dir=evidence)(manifest, target, threshold)

    return _verify


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("manifest", help="path to the local manifest")
    parser.add_argument("--dir", required=True, help="the rebuilt folder to check")
    parser.add_argument(
        "--check",
        choices=["bytes", "image", "both"],
        default="bytes",
        help="how closely to check. Default 'bytes' checks every file against its "
             "fingerprint and costs nothing. 'image' compares a picture you rendered "
             "after rebuilding against the one from packing time — you have to render "
             "it yourself first (that uses your GPU for a minute or two, which is why "
             "we never do it behind your back) and pass it with --rendered",
    )
    parser.add_argument(
        "--render",
        action="store_true",
        help="let Renest render the picture for you: it starts the rebuilt app, runs the "
             "very workflow this nest recorded, and compares the result. **It asks first** "
             "— rendering uses this machine's GPU and on a rented machine that is real "
             "money, so it never happens behind your back",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="answer yes to the rendering question up front (for unattended scripts)",
    )
    parser.add_argument(
        "--rendered",
        help="the image you rendered after rebuilding (needed by --check image/both). "
             "Compared against the nest's own sample from packing time",
    )
    parser.add_argument("--ssim-threshold", type=float, default=0.98)
    parser.add_argument("--report", help="write the full JSON report to this file")


def run_from_args(args: argparse.Namespace, emitter: EventEmitter) -> int:
    try:
        manifest = json.loads(Path(args.manifest).read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"✗ Cannot read the manifest: {e}", file=sys.stderr)
        return int(ExitCode.USAGE)
    # single-object command: keep internal narration off stdout for clean --json
    report = verify(
        manifest,
        args.dir,
        level=args.check,
        ssim_threshold=args.ssim_threshold,
        image_verifier=(
            _rendered_image_verifier(args.rendered)
            if args.rendered
            else (_rendering_image_verifier(assume_yes=args.yes) if args.render else None)
        ),
        emitter=None,
    )
    if args.report:
        Path(args.report).write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(report.summary, file=sys.stderr)
    return report.exit_code
