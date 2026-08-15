"""Prove a rebuild by actually rendering a picture and comparing it.

Byte-for-byte verification can hand a broken environment a perfect score: an install
that is missing whole modules still passes, because every file that *is* present
really is correct. So the only conclusive acceptance test is to run the recorded
workflow once and compare the picture against the one made at packing time.

It never runs by default -- rendering burns the user's GPU, which is real money on a
rented machine. It runs only when asked, and states the cost before it starts.

The pass mark is a structural similarity of 0.98 or better, never quietly relaxed to
make a run pass; a run that falls short still writes the side-by-side picture out.
Pillow and scikit-image are optional and imported inside the functions, so people who
only move environments never install them and no other command is affected.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

__all__ = ["MISSING_DEPS_HINT", "ProofResult", "compare_images"]

#: Pass mark for the comparison. Anything below it is a failure, and this value
#: must never be lowered just to make some particular run come out green.
DEFAULT_THRESHOLD = 0.98

MISSING_DEPS_HINT = (
    "Comparing images needs two extra packages that Renest does not install by "
    "default (most people only ever move environments). Install them with:\n"
    "    uv pip install pillow scikit-image"
)


@dataclass
class ProofResult:
    """Result of one picture comparison. ``side_by_side`` is filled in even when ``ok``
    is false: falling short can mean a broken environment or just the normal drift of
    a different GPU model, so that is exactly when a human needs to see both."""

    ok: bool
    ssim: float
    threshold: float
    side_by_side: Path | None
    detail: str


def compare_images(
    baseline: Path,
    rebuilt: Path,
    *,
    out_dir: Path,
    threshold: float = DEFAULT_THRESHOLD,
) -> ProofResult:
    """Compare two pictures and save a side-by-side copy for a human to check.

    Structural similarity (SSIM), not a pixel diff: on a different GPU, floating-point
    sampling drifts, so a pixel comparison always differs while no eye can tell -- that
    must not read as a failure. A genuinely broken rebuild lands far below the mark.
    """
    try:
        import numpy as np
        from PIL import Image
        from skimage.metrics import structural_similarity
    except ImportError as exc:  # Optional deps missing: plain words, not a traceback
        raise RuntimeError(MISSING_DEPS_HINT) from exc

    def _load(p: Path):
        return np.array(Image.open(p).convert("RGB"))

    a, b = _load(baseline), _load(rebuilt)
    h, w = min(a.shape[0], b.shape[0]), min(a.shape[1], b.shape[1])
    a, b = a[:h, :w], b[:h, :w]
    score = float(structural_similarity(a, b, channel_axis=2))

    out_dir.mkdir(parents=True, exist_ok=True)
    canvas = Image.new("RGB", (w * 2 + 8, h), (255, 255, 255))
    canvas.paste(Image.fromarray(a), (0, 0))
    canvas.paste(Image.fromarray(b), (w + 8, 0))
    side = out_dir / "side-by-side.png"
    canvas.save(side)

    ok = score >= threshold
    detail = (
        f"The rebuilt image matches the one from packing time (similarity "
        f"{score:.6f})."
        if ok
        else (
            f"The rebuilt image differs from the one from packing time "
            f"(similarity {score:.6f}, below {threshold}). That can mean the "
            f"environment is broken — or just a different GPU model. Look at "
            f"{side} and judge for yourself."
        )
    )
    (out_dir / "proof.json").write_text(
        json.dumps(
            {
                "ssim": score,
                "threshold": threshold,
                "ok": ok,
                "baseline": str(baseline),
                "rebuilt": str(rebuilt),
                "side_by_side": str(side),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return ProofResult(ok=ok, ssim=score, threshold=threshold, side_by_side=side, detail=detail)


# ══════════════════════════════════════════════════════════════════════
# The rendering half: run the recorded workflow once in the rebuilt environment.
# ══════════════════════════════════════════════════════════════════════
#: Order of magnitude for one render, shown so the cost is stated before asking.
#: An estimate to reason with, not a promise.
TYPICAL_RENDER_SECONDS = 60

RENDER_COST_NOTICE = (
    "Rendering a picture uses this machine's GPU for roughly {seconds} seconds "
    "(longer for video or large models). Renest never does this behind your back "
    "— it costs you real money on a rented machine. Run it now?"
)


def ask_before_rendering(*, assume_yes: bool = False, stream=None) -> bool:
    """Ask before rendering. Rendering never happens without a yes.

    ``assume_yes`` is for scripts, which must not hang on input with nobody watching.
    A non-interactive terminal returns False: declining costs nothing, while burning
    someone's GPU behind their back costs money.
    """
    import sys

    out = stream or sys.stderr
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print(
            "Not asking about rendering because this isn't an interactive terminal; "
            "skipping it. Pass --yes if you want it to run unattended.",
            file=out,
        )
        return False
    print(RENDER_COST_NOTICE.format(seconds=TYPICAL_RENDER_SECONDS), file=out)
    try:
        answer = input("  [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def render_recorded_workflow(
    *,
    port: int,
    workflow: dict,
    out_dir: Path,
    timeout_s: float = 900.0,
    poll_s: float = 2.0,
) -> Path:
    """Hand the recorded workflow to a running ComfyUI and fetch the first picture.

    License isolation: talks to the app over its HTTP API only, never imports its code.

    Returns the path written. If nothing comes out it raises RuntimeError with a
    plain-language reason -- "rebuilt but will not run" is itself an answer worth
    having, so it must never be swallowed.
    """
    import time

    import httpx

    out_dir.mkdir(parents=True, exist_ok=True)
    base = f"http://127.0.0.1:{port}"
    with httpx.Client(timeout=30.0) as client:
        resp = client.post(f"{base}/prompt", json={"prompt": workflow})
        if resp.status_code >= 400:
            raise RuntimeError(
                f"The rebuilt app refused to run the workflow ({resp.status_code}): "
                f"{resp.text[:300]}"
            )
        prompt_id = (resp.json() or {}).get("prompt_id")
        if not prompt_id:
            raise RuntimeError("The rebuilt app accepted the workflow but returned no job id")

        deadline = time.monotonic() + timeout_s
        history: dict = {}
        while time.monotonic() < deadline:
            h = client.get(f"{base}/history/{prompt_id}")
            if h.status_code < 400 and (data := h.json() or {}).get(prompt_id):
                history = data[prompt_id]
                break
            time.sleep(poll_s)
        if not history:
            raise RuntimeError(
                f"The workflow was still running after {int(timeout_s)} seconds — "
                f"stopped waiting. The app's own log says what it was doing."
            )

        for node_out in (history.get("outputs") or {}).values():
            for img in node_out.get("images") or []:
                got = client.get(
                    f"{base}/view",
                    params={
                        "filename": img.get("filename", ""),
                        "subfolder": img.get("subfolder", ""),
                        "type": img.get("type", "output"),
                    },
                )
                if got.status_code < 400 and got.content:
                    dest = out_dir / (img.get("filename") or "rendered.png")
                    dest.write_bytes(got.content)
                    return dest
    raise RuntimeError(
        "The workflow finished but produced no image — the environment rebuilt, "
        "but this run did not render anything."
    )
