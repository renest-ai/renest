"""Turn a "pick a preset" loader into the files it really loads, by asking the node pack.

Some loaders never name a file. ``IPAdapterUnifiedLoader`` takes ``"PLUS (high
strength)"`` and the pack works out, at run time, which weights that means. No table of
ours can answer that without becoming a second copy of the pack's own logic, which
drifts the day the pack changes. So we ask the pack itself.

**How, and why this way (GPL isolation).** The packs are GPL-3.0. We never import one
into this process and never copy its code here. Instead we start the *target* ComfyUI's
own Python interpreter as a child process, load the pack there the way ComfyUI does,
call the pack's own lookup function, and read back plain JSON. The child script below
is ours; the only thing it does with the pack is call it.

Anything that goes wrong -- no interpreter, the pack will not import, the function moved
or changed shape -- is not an error. The caller falls back to naming the files the
loader reads from and giving the command that packs them.

**Why the table lives in code and not in the world-rules data file.** A row here says
*which function to execute inside the user's interpreter, with which arguments*. That is
an instruction to run code, not vocabulary. The rules file can be updated remotely; we do
not want a remote update to be able to choose what runs on someone's machine. Adding a
row is a release, which is the right amount of friction for that.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

#: How long the child may take. Importing a node pack pulls in torch and ComfyUI's
#: model code; on a cold disk that is tens of seconds, never minutes.
TIMEOUT_S = 180


@dataclass(frozen=True)
class Resolver:
    """One kind of preset loader.

    ``input``: the input that carries the preset name.
    ``calls``: functions in the pack to call with that name, as
    ``(module inside the pack, function, extra args)``; the preset goes first.
    ``follow``: for a call that returns a tuple, the position holding a *pattern* that
    a second function turns into one more file -- ``(position, module, function)``.
    ``reads_from``: the folders under ComfyUI/ the loader picks from. Used only when
    the pack cannot be asked: those files are named, with the command to pack them.
    ``ambiguity``: said when the ``alternatives`` calls -- which differ only in a guess
    we cannot make from the workflow -- find different files, so the reader knows why
    both travel.
    ``flag_reads_from``: ``(position, folder)`` -- when a returned tuple is true at that
    position, the loader also reads that folder in a way no function hands us a path for
    (IPAdapter's FaceID presets and InsightFace), so its files are named for --add.
    """

    input: str
    calls: tuple[tuple[str, str, tuple], ...]
    follow: tuple[int, str, str] | None = None
    reads_from: tuple[str, ...] = ()
    ambiguity: str = ""
    alternatives: tuple[int, ...] = ()
    flag_reads_from: tuple[int, str] | None = None


# Read off ComfyUI_IPAdapter_plus at a0f451a5 (2025-04-14), utils.py:
#   get_clipvision_file(preset) -> full path or None
#   get_ipadapter_file(preset, is_sdxl) -> (full path or None, is_insightface, lora_pattern)
#   get_lora_file(pattern) -> full path or None
# ``is_sdxl`` is decided at run time from the loaded checkpoint, which a workflow does not
# say -- so both answers are asked for; the one that does not apply usually finds nothing
# or raises ("light model is not supported for SDXL").
_IPADAPTER = Resolver(
    input="preset",
    calls=(
        ("utils", "get_clipvision_file", ()),
        ("utils", "get_ipadapter_file", (False,)),
        ("utils", "get_ipadapter_file", (True,)),
    ),
    follow=(2, "utils", "get_lora_file"),
    reads_from=("models/ipadapter", "models/clip_vision"),
    ambiguity=("whether this preset loads the SD1.5 or the SDXL model is decided when the "
               "checkpoint loads, which the workflow does not say; both files this preset "
               "can mean are here, so both travel"),
    alternatives=(1, 2),
    flag_reads_from=(1, "models/insightface"),
)

PRESET_RESOLVERS: dict[str, Resolver] = {
    "IPAdapterUnifiedLoader": _IPADAPTER,
    "IPAdapterUnifiedLoaderFaceID": _IPADAPTER,
    "IPAdapterUnifiedLoaderCommunity": _IPADAPTER,
}


# The child. Runs in the target environment's interpreter, never in ours. It prints
# exactly one marked JSON line on stdout; everything the pack prints goes to stderr.
_CHILD = r'''
import importlib, importlib.util, json, os, sys
req = json.loads(sys.stdin.read())
real_out = sys.stdout
sys.stdout = sys.stderr
res = {"error": None, "results": []}

def plain(v):
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    if isinstance(v, (list, tuple)):
        return [plain(x) for x in v]
    return repr(v)

try:
    root = req["program_dir"]
    sys.path.insert(0, root)
    os.chdir(root)
    # No GPU work happens here; keep ComfyUI from touching the device at import.
    sys.argv = [sys.argv[0], "--cpu"] + (
        ["--base-directory", req["data_dir"]] if req["data_dir"] != root else [])
    try:
        import comfy.options
        comfy.options.enable_args_parsing()
    except Exception:
        pass
    import folder_paths
    for y in req["extra_model_paths"]:
        try:
            from utils.extra_config import load_extra_path_config
            load_extra_path_config(y)
        except Exception:
            pass
    node_dir = req["node_dir"]
    name = "renest_probe_" + "".join(c if c.isalnum() else "_" for c in os.path.basename(node_dir))
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(node_dir, "__init__.py"), submodule_search_locations=[node_dir])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    for call in req["calls"]:
        one = {"ok": False}
        try:
            m = importlib.import_module(name + "." + call["module"])
            got = getattr(m, call["func"])(*call["args"])
            one = {"ok": True, "value": plain(got)}
            f = call.get("follow")
            if f and isinstance(got, (list, tuple)) and len(got) > f[0] and got[f[0]]:
                fm = importlib.import_module(name + "." + f[1])
                one["followed"] = plain(getattr(fm, f[2])(got[f[0]]))
        except BaseException as e:
            one = {"ok": False, "error": type(e).__name__ + ": " + str(e)[:300]}
        res["results"].append(one)
except BaseException as e:
    res["error"] = type(e).__name__ + ": " + str(e)[:300]
real_out.write("\n@@RENEST-PRESETS@@" + json.dumps(res) + "\n")
real_out.flush()
'''

_MARK = "@@RENEST-PRESETS@@"


@dataclass
class Asked:
    """What the pack said for one node. ``files`` are absolute paths that exist;
    ``by_call`` keeps which call found which, for the ambiguity note; ``flags`` the
    raw tuple values; ``error`` is set when the pack could not be asked at all."""

    files: list[str] = field(default_factory=list)
    by_call: list[list[str]] = field(default_factory=list)
    flags: list[list] = field(default_factory=list)
    error: str | None = None


def ask_pack(python: str | Path | None, program_dir: Path, data_dir: Path, node_dir: Path,
             presets: list[tuple[Resolver, str]],
             extra_model_paths: list[Path] = ()) -> list[Asked]:
    """Ask the pack in ``node_dir`` about each ``(resolver, preset)`` -- one child for all
    of them, since importing the pack is the slow part. Never raises."""
    if not presets:
        return []
    fail = lambda why: [Asked(error=why) for _ in presets]  # noqa: E731
    if not python:
        return fail("no Python interpreter for this ComfyUI was found (pass --env-python)")
    calls, spans = [], []
    for res, preset in presets:
        start = len(calls)
        for mod, fn, extra in res.calls:
            c = {"module": mod, "func": fn, "args": [preset, *extra]}
            if res.follow is not None:
                c["follow"] = list(res.follow)
            calls.append(c)
        spans.append((start, len(calls)))
    req = {"program_dir": str(program_dir), "data_dir": str(data_dir),
           "node_dir": str(node_dir), "calls": calls,
           "extra_model_paths": [str(p) for p in extra_model_paths]}
    try:
        out = subprocess.run([str(python), "-c", _CHILD], input=json.dumps(req),
                             capture_output=True, text=True, timeout=TIMEOUT_S, check=False,
                             cwd=str(program_dir))
    except (OSError, subprocess.SubprocessError) as e:
        return fail(f"could not start {python}: {e}")
    line = next((ln for ln in reversed(out.stdout.splitlines()) if ln.startswith(_MARK)), None)
    if line is None:
        tail = (out.stderr or "").strip().splitlines()[-1:] or [f"exit code {out.returncode}"]
        return fail(f"the lookup did not finish ({tail[0][:200]})")
    try:
        data = json.loads(line[len(_MARK):])
    except ValueError:
        return fail("the lookup answered with something we could not read")
    if data.get("error"):
        return fail(f"the node pack would not load: {data['error']}")
    results = data.get("results") or []
    answers: list[Asked] = []
    for start, end in spans:
        a = Asked()
        for r in results[start:end]:
            found: list[str] = []
            if r.get("ok"):
                v = r.get("value")
                head = v[0] if isinstance(v, list) and v else v
                if isinstance(v, list):
                    a.flags.append(v)
                for cand in (head, r.get("followed")):
                    if isinstance(cand, str) and cand and Path(cand).is_file():
                        found.append(cand)
            a.by_call.append(found)
            for f in found:
                if f not in a.files:
                    a.files.append(f)
        if not any(r.get("ok") for r in results[start:end]):
            errs = [r.get("error") for r in results[start:end] if r.get("error")]
            a.error = "the node pack's lookup failed" + (f" ({errs[0]})" if errs else "")
        answers.append(a)
    return answers
