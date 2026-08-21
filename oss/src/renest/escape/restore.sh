#!/usr/bin/env bash
# =============================================================================
# Renest restore.sh — the escape hatch
#
# Nest formats this copy reads: 2.0, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8  (and, with a warning,
#   any later 2.x — a higher minor version only ever adds optional fields, and
#   refusing one would turn a nest whose bytes restore perfectly into a brick).
#   Written for format 2.8, 2026-08-17. Keep this line: from format 2.3 on a
#   copy of this script travels inside every nest at .renest/escape/restore.sh,
#   and this comment is how you tell which copy you are holding — there is no
#   version field anywhere else.
#
#   The copy inside a nest is frozen: fixes made after that nest was packed will
#   never reach it. So, honestly, in two layers — the copy in your nest is the
#   floor (it will always get your bytes back, even if we no longer exist); the
#   latest copy from us is better (bugs fixed, and it reads several formats).
#   Use the latest one when you can reach us.
#
#   Someone else's nest: do not run the script inside it without looking. That
#   is their code on your machine. Use your own copy, or check its hash against
#   the one recorded in the nest's own file list first.
#
# Promise: this script needs only curl, jq, sha256sum (or shasum), tar and uv,
# plus the stock Unix text tools every base system already ships (grep, sed,
# sort, cut, tr, paste, df). It does not need Renest, our servers, or anything
# else we ship. Read it, keep a copy, and you can always rebuild a nest without us.
# (git was on this list until 2026-08-08 but the script never once called it —
# code archives are unpacked from tar, never cloned — so it is no longer required.)
#
# Usage:
#   GRANT=<grant.json path or URL>  TARGET=/workspace  bash restore.sh
#   NEST_URL=https://<bucket>/nests/<id>  TARGET=/workspace  bash restore.sh
#     Slow to install? Point packages at a closer place:
#     PACKAGE_SOURCE=https://<mirror>/simple  (every package is still checked
#     against the fingerprint recorded in the nest, so a wrong mirror stops you)
#     Private bucket: also pass MANIFEST_URL=<presigned URL of manifest.json>
#     and BLOB_MANIFEST=<presigned blob list>. This script cannot sign links itself
#     — it has no openssl and never will (see the dependency promise above), so a
#     private bucket always needs links signed elsewhere. Easiest is one restore
#     code: `renest presign --nest <id> --out code.json`, then GRANT=code.json.
#     NEST_URL points at the nest directory, which contains manifest.json.
#
# Two ways to find the files:
#   1. By path (default): <bucket>/blobs/sha256/<first 2 chars>/<hash>.
#      Override the root with BLOB_BASE; otherwise it is derived from NEST_URL.
#   2. By list: BLOB_MANIFEST=<url|path> pointing at a JSON map
#      { "<sha256>": "<presigned URL>", ... }. Needed for private buckets,
#      where signed URLs cannot be guessed from a path. A file missing from
#      the list is a hard failure.
#
# No silent fallbacks: if a required tool is missing, or uv cannot be
# installed, this script stops. It never quietly does less than you asked.
#
# When something fails you get one line saying which stage and which kind:
#   S0 precheck -> S1 fetch -> S2 place -> S3 dependencies -> S4 verify
#   (Starting the app and re-running your workflow is done by the Renest
#   agent, not here.)
# The same attribution is written to $TARGET/.renest/restore-failure.json.
#
# Where files land: everything goes under $TARGET, except for two folders in
# your home model cache. A training setup keeps its base model and its
# accelerate config there and will not run if they are anywhere else, so nests
# may name those two — and only those two, with only the shape of path each one
# allows. Nothing else outside $TARGET is ever written.
#
# This script warns but does not refuse when the machine looks like a poor
# match — its job is to try anyway. The one thing it does refuse is a nest
# that tries to write somewhere it was not given, or install from servers
# nobody recognises: that is not a compatibility question, it is someone
# else's code trying to run on your machine.
# =============================================================================
set -euo pipefail

# ── Restore code input: GRANT=<grant.json path or URL> ───────────────────────
# A v2 code is an envelope: curl exchanges it for the v1 payload. A v1 payload
# is used as-is. Only curl and jq are involved. After the exchange MANIFEST_URL
# and BLOB_MANIFEST are filled in for you, so NEST_URL is not needed.
GRANT="${GRANT:-}"
: "${TARGET:=/workspace}"
if [[ -n "$GRANT" ]]; then
  command -v jq >/dev/null 2>&1 || { echo "[renest] jq is not installed" >&2; exit 1; }
  mkdir -p "$TARGET/.renest"
  _GRANT_RAW="$TARGET/.renest/grant-input.json"
  case "$GRANT" in
    http://*|https://*) curl -fsSL "$GRANT" -o "$_GRANT_RAW" || { echo "[renest] could not download the restore code" >&2; exit 1; } ;;
    *) cp "$GRANT" "$_GRANT_RAW" || { echo "[renest] cannot read the restore code file: $GRANT" >&2; exit 1; } ;;
  esac
  _GV="$(jq -r '.grant_version // empty' "$_GRANT_RAW")"
  if [[ "$_GV" == "2" ]]; then
    _EX_URL="$(jq -r '.exchange_url // empty' "$_GRANT_RAW")"
    [[ -n "$_EX_URL" ]] || { echo "[renest] this restore code has no exchange_url" >&2; exit 1; }
    echo "[renest] Redeeming your restore code… (expired or revoked? sign a new one from your drive)"
    # A restore code binds to the first machine that redeems it, so the machine has to
    # say who it is. We send a hash, never the raw values -- the server has no business
    # knowing what this box is called. Only things that survive a reboot go in, because
    # the same hash has to come back when a dropped transfer resumes.
    # No new dependency: sha256sum (or shasum on a stock macOS) is already required.
    _MFP=""
    _MRAW="$(hostname 2>/dev/null)|$(cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null)"
    if command -v sha256sum >/dev/null 2>&1; then
      _MFP="$(printf '%s' "$_MRAW" | sha256sum | cut -d' ' -f1)"
    elif command -v shasum >/dev/null 2>&1; then
      _MFP="$(printf '%s' "$_MRAW" | shasum -a 256 | cut -d' ' -f1)"
    fi
    # Cannot compute one? Send nothing. The code then simply never binds, which is the
    # documented behaviour -- better than locking out someone who legitimately holds it.
    if [[ -n "$_MFP" ]]; then
      curl -fsS -X POST -H "X-Renest-Machine: $_MFP" "$_EX_URL" -o "$TARGET/.renest/grant-exchanged.json"       || { echo "[renest] Redeem failed: expired, revoked, or already used on another machine. Sign a new one — your nest is still in your account." >&2; exit 1; }
    else
      curl -fsS -X POST "$_EX_URL" -o "$TARGET/.renest/grant-exchanged.json"       || { echo "[renest] Redeem failed: the code has expired or been revoked. Sign a new one — your nest is still in your account." >&2; exit 1; }
    fi
    _GRANT_RAW="$TARGET/.renest/grant-exchanged.json"
    _GV="$(jq -r '.grant_version // empty' "$_GRANT_RAW")"
  fi
  [[ "$_GV" == "1" ]] || { echo "[renest] unrecognised grant_version: $_GV" >&2; exit 1; }
  # Keep-time countdown for free accounts: say something only when 30 days or
  # fewer are left. Someone on the free tier may use a restore code on a pod
  # every day and never open the website, and only signing in restarts the
  # clock — without this line their files could be cleared while still in use.
  # Told, never enforced: this line changes nothing that follows it.
  _DAYS_LEFT="$(jq -r '.retention_days_left // empty' "$_GRANT_RAW")"
  # Only say "sign in and it restarts" when the server says it does: an account that
  # cancelled runs to a fixed date, and sending them to sign in would not save a thing.
  _RENEWS="$(jq -r 'if has("retention_renews_on_sign_in") then (.retention_renews_on_sign_in|tostring) else "unknown" end' "$_GRANT_RAW")"
  if [[ "$_DAYS_LEFT" =~ ^[0-9]+$ ]] && [[ "$_DAYS_LEFT" -le 30 ]]; then
    echo "[renest] Heads-up: what you have stored has ${_DAYS_LEFT} days of keep-time left (free accounts keep files for 90 days)."
    case "$_RENEWS" in
      true)  echo "[renest] Signing in on the website once restarts the 90 days, at no cost. This restore is unaffected — carrying on." ;;
      false) echo "[renest] This countdown runs to a fixed date and signing in does not change it — move anything you want to keep before then. This restore is unaffected — carrying on." ;;
      *)     echo "[renest] This restore is unaffected — carrying on." ;;
    esac
  fi
  MANIFEST_URL="$(jq -r '.manifest_url' "$_GRANT_RAW")"
  jq '.blobmap | map_values(.[0])' "$_GRANT_RAW" > "$TARGET/.renest/grant-blobmap.json"
  BLOB_MANIFEST="$TARGET/.renest/grant-blobmap.json"
  NEST_URL="${NEST_URL:-grant:$(jq -r '.grant_id' "$_GRANT_RAW")}"
fi

: "${NEST_URL:?set NEST_URL (or GRANT=<restore code>), e.g. https://pub-xxx.r2.dev/nests/01H...}"
BLOB_BASE="${BLOB_BASE:-${NEST_URL%/nests/*}/blobs/sha256}"
BLOB_MANIFEST="${BLOB_MANIFEST:-}"
RETRIES="${RETRIES:-4}"          # how many times curl retries one file
PARALLEL="${PARALLEL:-4}"        # how many large files move at once
MANIFEST="$TARGET/.renest/manifest.json"
BLOBMAP="$TARGET/.renest/blobmap.json"

STAGE="S0-precheck"      # current stage; failures are attributed to it
FAILFILE="$TARGET/.renest/restore-failure.json"
# The installer writes a lot and only stdout sees it; close the terminal or drop the
# ssh connection and the one thing that explains the failure is gone. Keep a copy.
DEPSLOG="$TARGET/.renest/deps-install.log"
# Reruns must be idempotent: a stale failure file from the last attempt would
# veto a fully successful rerun at the post-parallel check. Real-machine proof
# 2026-07-26: a model downloaded to 100% and the run was still blocked by the
# previous attempt's leftovers. Anyone who fails once will try again.
rm -f "$FAILFILE" 2>/dev/null || true

log()  { printf '\033[1;32m[renest]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[renest] Heads up:\033[0m %s\n' "$*" >&2; }
die()  {
  local code="$1"; shift
  printf '\033[1;31m[renest] Failed [%s / %s]:\033[0m %s\n' "$STAGE" "$code" "$*" >&2
  local _EX=""
  # jq does the escaping here: the message field's sed cannot handle tabs or the
  # control bytes an installer's output is full of, and a broken record is worse
  # than none — support would be reading a file that will not parse.
  if [ -s "${DEPSLOG:-}" ] && command -v jq >/dev/null 2>&1; then
    _EX=",\"install_log\":\"$DEPSLOG\",\"install_log_tail\":$(tail -n 40 "$DEPSLOG" | jq -Rs .)"
  fi
  if mkdir -p "$(dirname "$FAILFILE")" 2>/dev/null; then
    printf '{"stage":"%s","code":"%s","message":%s%s}\n' "$STAGE" "$code" \
      "$(printf '%s' "$*" | tr '\n' ' ' | sed 's/\\/\\\\/g; s/"/\\"/g; s/^/"/; s/$/"/')" "$_EX" > "$FAILFILE"
    printf '\033[1;31m[renest]\033[0m Details written to %s\n' "$FAILFILE" >&2
  fi
  if [ -n "$_EX" ]; then
    printf '\033[1;31m[renest]\033[0m The installer output is kept at %s — that file is the diagnosis, and it is the one to send if you ask us for help.\n' "$DEPSLOG" >&2
  fi
  exit 1
}

hsize() { # human-readable size (integer arithmetic only, one decimal, rounded; works on bash 3.2)
  local b="$1" i=0 d=1 t
  local u=(B KiB MiB GiB TiB)
  while [ $(( b / d )) -ge 1024 ] && [ "$i" -lt 4 ]; do d=$(( d * 1024 )); i=$(( i + 1 )); done
  if [ "$i" -eq 0 ]; then
    printf '%d %s' "$b" "${u[0]}"
  else
    t=$(( (b * 10 + d / 2) / d ))
    printf '%d.%d %s' $(( t / 10 )) $(( t % 10 )) "${u[$i]}"
  fi
}

# ---- Required tools (missing one stops the run) -----------------------------
need() { command -v "$1" >/dev/null 2>&1 || die DEP-MISSING "$1 is not installed. Install it and run this again. This script needs curl, jq, sha256sum (or shasum), tar and uv — nothing else beyond stock Unix text tools."; }
for c in curl jq tar; do need "$c"; done

# sha256: GNU systems call it sha256sum, a stock macOS/BSD only has shasum.
# **This is not an extra dependency** — they are two names for the same thing;
# whichever is present is used, and only having neither counts as missing.
# Why: on a Mac, following the README step by step used to exit straight away
# with DEP-MISSING, and that step is written for users to run.
if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die DEP-MISSING "Neither sha256sum nor shasum is installed, so nothing can be byte-checked. Install one and run this again."
fi
if ! command -v uv >/dev/null 2>&1; then
  log "uv not found — installing it…"
  if ! curl -LsSf https://astral.sh/uv/install.sh | sh; then
    die DEP-UV "Could not install uv. Install it yourself and run this again: https://astral.sh/uv"
  fi
  export PATH="$HOME/.local/bin:$PATH"
  command -v uv >/dev/null 2>&1 || die DEP-UV "uv installed but still is not on PATH. PATH=$PATH"
fi

mkdir -p "$TARGET/.renest" 2>/dev/null || die TARGET-PERM "Cannot write to $TARGET. Machine images differ in who owns what — pick another TARGET, or chown this one first."
[ -w "$TARGET" ] || die TARGET-PERM "Cannot write to $TARGET"

STAGE="S1-fetch"
# ---- 1. Fetch the manifest --------------------------------------------------
# Private buckets have no public URL: pass MANIFEST_URL with a presigned one.
# Without it we build NEST_URL/manifest.json (public bucket / local dir / http.server).
MANIFEST_URL="${MANIFEST_URL:-$NEST_URL/manifest.json}"
log "Fetching the manifest…"
_MANI_HTTP=""
if ! _MANI_HTTP=$(curl -fsSL -w '%{http_code}' "$MANIFEST_URL" -o "$MANIFEST"); then
  case "$_MANI_HTTP" in
    404|410) die FETCH-MISSING "There is no nest manifest at that address: ${MANIFEST_URL%%\?*}
       This is not a network problem. Check the nest id and the bucket you are pointing
       at. If the nest was packed very recently, its upload may not have finished — the
       manifest is written last, on purpose." ;;
  esac
fi
[ -s "$MANIFEST" ] || die FETCH-MANIFEST "Could not download the manifest: ${MANIFEST_URL%%\?*}
       Check: (1) a private bucket cannot be read from a plain URL — it needs signed
                  links. This script cannot make them itself (it has no openssl, on
                  purpose), so sign them where your key lives:
                    renest presign --nest <nest id> --out code.json
                  then run this again with GRANT=code.json
              (2) the signed link may have expired — sign a fresh one
              (3) is NEST_URL right?"
FV=$(jq -r '.format_version' "$MANIFEST")
# 2.x only. Nests in the older 1.x format are not read here: 2.0 made
# code_deps[].role a required field, and guessing it would mean guessing which
# parts of a nest are the app and which are your own code.
#
# 2.1 added entrypoint.success.expect_artifact — "a training run that
# exits 0 but produced no file did not actually run". **That field is meaningless
# here and deliberately unused**: this script rebuilds the environment and checks
# every byte, it never starts the application (see the stages below — the last one
# is the byte check). Judging "did it really run" belongs to the agent layer.
# So 2.1 is a pure addition from the escape hatch's point of view, and refusing it
# would strand a nest whose bytes this script can restore perfectly.
# **Forward-compatibility fuse**: within the same major version, a minor version
# newer than this script knows about is **warned about and let through**, not
# refused — by the spec a new minor version only adds optional fields, which this
# script does not use, and refusing would turn a nest it can restore byte for
# byte into a brick. The 2.1 round was exactly such a pure addition, and this
# gate refused it at the time.
# A different major version is still refused outright: that is what a major
# version number means — breaking changes — and guessing would just be guessing.
# 2.3 (2026-08-08) relaxes two fields from required to optional (the base image
# line and the dependency lockfile) and adds one optional field (the packing
# machine's CPU architecture). Nothing was tightened, so every 2.0/2.1/2.2 nest
# still reads here — and this script now copes with both of those lines being
# absent (see the base-image and lockfile steps below).
# 2.4 (2026-08-11) adds optional machine facts only (how much video memory a run
# was seen to use, whether the machine shares video memory with the system, how
# many cards and whether they reach each other, the C library version and the
# platform tag), plus one reserved field for a feature not yet built. This script
# reads none of them, so every 2.0–2.3 nest still restores here unchanged.
# 2.5 (2026-08-11) adds one optional field only: what carries the traffic between a
# machine's GPUs (a dedicated link, or merely the shared host bus). Recording only
# *whether* they could reach each other hid the difference that decides whether two
# cards can act as one bigger card. This script reads neither field, so nothing here
# changes and every 2.0–2.4 nest still restores unchanged.
# 2.6 (2026-08-12) adds four optional fields, and **this script uses three of them**:
# where the recipe file lived and where the dependency lock lived, so both go back
# where they belong instead of into a staging folder; and which machine libraries the
# successful run needed, checked here before anything is downloaded. The fourth
# (what packing left out of each source archive) is disclosure a reader looks at, not
# something this script acts on. Every 2.0–2.5 nest still restores unchanged: each of
# these is absent there, and absent keeps the old behaviour exactly.
# 2.7 (2026-08-12) changes one thing and only relaxes: the category on each asset
# (files[].kind) is no longer a fixed list of words, it is free text. This script
# never read that field and still does not — where a file lands is decided by its
# path and its root, never by its category. Nothing to do here beyond letting the
# version through, and every 2.0–2.6 nest restores unchanged.
# 2.8 (2026-08-17) adds one optional field, and **this script acts on it**: which
# copy of a module the working run used when several packages in the lock all write
# the same folder (the OpenCV family all write cv2/). The installer decides who
# writes last, and not stably — measured, one lock on one machine gave a different
# survivor on back-to-back installs. So after installing, this script checks the
# recorded file's hash and, if it differs, reinstalls that one package so it writes
# last (section 5b). Still different → it says so and carries on. Every 2.0–2.7 nest
# restores unchanged: the field is absent there, and absent means "do nothing".
case "$FV" in
  2.0|2.1|2.2|2.3|2.4|2.5|2.6|2.7|2.8) ;;
  2.*)
    warn "This nest says format $FV; this script knows up to 2.8. Same major version, so it only adds optional fields this script does not use — carrying on. A newer Renest will make full use of them." ;;
  *)
    # Same three facts the agent side gives, in the same order: how old this nest is,
    # that there is no upgrade path and why, and that the files themselves are fine.
    # Refusing is right; leaving someone wondering whether they just lost their models
    # is not (the manifest still lists every one of them, with fingerprints).
    _WHEN=$(jq -r '.created_at // empty' "$MANIFEST" 2>/dev/null | cut -c1-10)
    _NFILES=$(jq -r '(.files // []) | length' "$MANIFEST" 2>/dev/null)
    die FORMAT-VERSION "Unrecognised nest format version: $FV — this script reads format 2.x (knows 2.0, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7 and 2.8).${_WHEN:+ This nest was packed on ${_WHEN}.} Nests in the older 1.x format cannot be read here, and **there is no upgrade path**: format 2.0 made it compulsory to say which parts of a nest are the application and which are your own code, and nobody can work that out after the fact.${_NFILES:+ **Your files are not lost** — this nest still lists all ${_NFILES} of them with their fingerprints, so they can be fetched one by one even though the environment cannot be rebuilt automatically.} If you still have the environment, pack it again with a current Renest." ;;
esac

# ---- Where the files may land ------------------------------------------------
# Most of a nest lands under $TARGET. Two model-cache folders are the exception:
# a training setup keeps its base model and its accelerate config in your home
# cache, and it will not run if they are somewhere else. Those two folders are
# named here, resolved the same way the Hugging Face tools resolve them, and
# nothing else outside $TARGET is ever written.
if [ -n "${HF_HUB_CACHE:-}" ]; then
  HF_HUB_ROOT="$HF_HUB_CACHE"
elif [ -n "${HF_HOME:-}" ]; then
  HF_HUB_ROOT="$HF_HOME/hub"
else
  HF_HUB_ROOT="${HOME:-}/.cache/huggingface/hub"
fi
if [ -n "${HF_HOME:-}" ]; then
  HF_HOME_ROOT="$HF_HOME"
else
  HF_HOME_ROOT="${HOME:-}/.cache/huggingface"
fi
# root_dir <root> — where files with that root land
root_dir() {
  case "$1" in
    hf_hub)  printf '%s' "$HF_HUB_ROOT" ;;
    hf_home) printf '%s' "$HF_HOME_ROOT" ;;
    *)       printf '%s' "$TARGET" ;;
  esac
}

# ---- Where-it-lands safety check --------------------------------------------
# We warn rather than refuse about compatibility, but not about this: a nest
# handed to you is someone else's bytes, and a path that escapes where it
# belongs means writing files somewhere you did not agree to.
#
# Three checks, and the order matters:
#   1. the named folder has to be one of the three we know;
#   2. the path has to stay inside it — no absolute path, no ~, no ".." —
#      and this one applies to EVERY folder, including the two cache ones.
#      The allow-list below ends in ".+", which happily matches ".." on its own;
#      the allow-list alone would let ".../snapshots/<id>/../../../etc/passwd"
#      straight through. So this check stays, separately, always;
#   3. the two cache folders each allow only their own shape of path, so a
#      nest cannot smuggle your training data into them.
#   4. no file may land somewhere it would be RUN rather than read. Staying
#      inside $TARGET is not enough: a ".pth" dropped into site-packages runs
#      on every interpreter start, and a ".py" dropped into the app's folder
#      gets imported at launch. files[] holds assets — models, LoRAs, inputs —
#      never program code, which travels in code_deps instead. This check is
#      what enforces that, and it looks only at the path: since format 2.7 the
#      category beside it is free text, so trusting it would trust the nest.
BADPATH=$(jq -r '
  [ (.files[]? | (.root // "env") as $r | (.path // "") as $p
      | if ($r != "env" and $r != "hf_hub" and $r != "hf_home")
          then "unknown place to put files: \($r)"
        elif ($p == "") or ($p | test("^(/|~)")) or ($p | test("(^|/)\\.\\.(/|$)"))
          then "a path that writes outside where it belongs: \($p)"
        elif ($r == "hf_hub") and (($p | test("^models--[^/]+/(refs/[^/]+|snapshots/[0-9a-f]{40}/.+)$")) | not)
          then "a path that is not allowed in the model cache: \($p)"
        elif ($r == "hf_home") and (($p | test("^accelerate/[^/]+\\.yaml$")) | not)
          then "a path that is not allowed in the model cache: \($p)"
        elif ($r == "env") and ($p | test("(^|/)(\\.venv|venv|site-packages|bin|Scripts)/"))
          then "a path where files get run as code, not read as data: \($p)"
        elif ($r == "env") and ($p | test("\\.(py|pth|pyc|pyd)$"))
          then "a path that is program code, not an asset: \($p)"
        else empty end),
    (.code_deps[]? | (.install_path // "") as $p
      | if ($p == "") or ($p | test("^(/|~)")) or ($p | test("(^|/)\\.\\.(/|$)"))
          then "a path that writes outside where it belongs: \($p)"
        else empty end),
    # The two paths format 2.6 added get the same check: a nest that names a spot
    # outside the rebuild folder is refused here too, not quietly ignored.
    (((.python_lock.lockfile_path // empty), (.adapters.comfyui.workflow_path // empty))
      | if test("^(/|~)") or test("(^|/)\\.\\.(/|$)")
          then "a path that writes outside where it belongs: \(.)"
        else empty end)
  ] | .[0] // empty' "$MANIFEST")
[ -n "$BADPATH" ] && die MANIFEST-BAD "This nest asks for something we will not do — it names $BADPATH. Refusing to restore it."
# How many files a nest may list. Not a security limit — a sanity one: this script
# starts a couple of processes per file, so a manifest with a million entries would
# keep your machine busy all night without ever moving a byte worth having. A real
# nest is a few dozen files. Keep this number the same as MAX_MANIFEST_FILES in
# the Renest agent (oss/src/renest/roots.py) — two numbers that drift are worse
# than one number that is wrong.
N_FILES=$(jq '(.files // []) | length' "$MANIFEST")
[ "$N_FILES" -gt 50000 ] && die MANIFEST-BAD "This nest lists $N_FILES files; we stop at 50000. A nest that big is nearly always a mistake — ask whoever packed it to split it up."
# A home-cache path can only be used at all if we know where home is.
HOME_FILES=$(jq '[.files[]? | select((.root // "env") != "env")] | length' "$MANIFEST")
if [ "$HOME_FILES" -gt 0 ] && [ -z "${HOME:-}" ] && [ -z "${HF_HOME:-}" ] && [ -z "${HF_HUB_CACHE:-}" ]; then
  die TARGET-PERM "This nest keeps $HOME_FILES files in the model cache, but this machine has no HOME set. Set HF_HOME=/somewhere and run this again."
fi
log "Nest: $(jq -r '.name // .id' "$MANIFEST")"

# ---- 1b. Precheck: disk space (do not waste half an hour downloading) -------
STAGE="S0-precheck"
# Counted per folder, not in one lump: the model cache is often on a different
# disk from the rebuild folder, and one number for both would be a lie in either
# direction — blocking a run that fits, or letting one start that cannot finish.
check_space() { # check_space <folder> <bytes needed>
  local dir="$1" need="$2" need_kb avail_kb
  [ "$need" -gt 0 ] || return 0
  need_kb=$(( (need / 1024) * 115 / 100 + 1 ))     # 15% headroom for unpacking
  mkdir -p "$dir" 2>/dev/null || true
  # POSIX df -P guarantees no line wrapping: one header line + one data line,
  # with available KiB in the 4th column.
  avail_kb=$(df -Pk "$dir" 2>/dev/null | { read -r _ || true; read -r _ _ _ a _ || true; printf '%s' "${a:-}"; } || true)
  if [ -n "${avail_kb:-}" ] && [ "$avail_kb" -lt "$need_kb" ]; then
    die DISK-SPACE "Not enough disk space: this nest needs about $(hsize $((need_kb * 1024))) in $dir including headroom, and it has $(hsize $((avail_kb * 1024))) free. Use a bigger disk or attach a volume."
  fi
}
NEED_ENV=$(jq '[ [.files[] | select((.root // "env") == "env") | .blob.size_bytes] + [.code_deps[].archive.size_bytes] | add // 0 ] | .[0]' "$MANIFEST")
NEED_HUB=$(jq '[ [.files[] | select((.root // "env") == "hf_hub") | .blob.size_bytes] | add // 0 ] | .[0]' "$MANIFEST")
NEED_HFH=$(jq '[ [.files[] | select((.root // "env") == "hf_home") | .blob.size_bytes] | add // 0 ] | .[0]' "$MANIFEST")
check_space "$TARGET" "$NEED_ENV"
check_space "$HF_HUB_ROOT" "$NEED_HUB"
check_space "$HF_HOME_ROOT" "$NEED_HFH"

# ---- 1c. Precheck: what the nest was built on (told, not enforced) ----------
if jq -e '.fingerprint' "$MANIFEST" >/dev/null 2>&1; then
  WANT_PY=$(jq -r '.fingerprint.python.version // empty' "$MANIFEST")
  WANT_TORCH=$(jq -r '.fingerprint.torch.version // empty' "$MANIFEST")
  WANT_CUDA=$(jq -r '.fingerprint.torch.cuda_version // empty' "$MANIFEST")
  log "Packed on: python ${WANT_PY:-?}${WANT_TORCH:+ / torch $WANT_TORCH}${WANT_CUDA:+ / cuda $WANT_CUDA}"
  if command -v python3 >/dev/null 2>&1; then
    HAVE_PY=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "")
    if [ -n "$HAVE_PY" ] && [ -n "$WANT_PY" ] && [ "${WANT_PY%.*}" != "$HAVE_PY" ]; then
      warn "This machine has python $HAVE_PY; the nest wants ${WANT_PY%.*}. A different major version is the number one cause of dependency failures."
      warn "  Carrying on anyway (uv will fetch the right version). If it stalls on dependencies, start from a matching image instead."
    fi
  fi
  if command -v nvidia-smi >/dev/null 2>&1 && [ -n "$WANT_CUDA" ]; then
    HAVE_CUDA=$(nvidia-smi 2>/dev/null | grep -m1 -o 'CUDA Version: [0-9.]*' || true)
    HAVE_CUDA="${HAVE_CUDA#CUDA Version: }"
    [ -n "${HAVE_CUDA:-}" ] && [ "${HAVE_CUDA%%.*}" != "${WANT_CUDA%%.*}" ] && \
      warn "This machine's driver supports CUDA $HAVE_CUDA; the nest was built for CUDA $WANT_CUDA. Different major versions often mean torch will not install or will not run. Carrying on anyway."
  fi
fi

# ---- 1d. Precheck: does this GPU match what torch was built for? ------------
# Warned about loudly, never refused here. The Renest agent can refuse; this
# script's job is to try anyway.
if command -v nvidia-smi >/dev/null 2>&1 && jq -e '.gpu.torch_cuda_arch_list' "$MANIFEST" >/dev/null 2>&1; then
  # The two forms must be counted separately, never flattened into one list:
  #   sm_90      = finished goods: machine code already compiled for that one
  #                class of card and nothing else;
  #   compute_90 = half-finished: an intermediate form is kept (the industry
  #                calls it PTX), so when a newer card appears the graphics
  #                driver can compile it on the spot into something that card
  #                can run.
  # This line used to strip every non-digit character from both, turning each
  # into "90", which hid whether the nest carries the half-finished form at all
  # — and whether a nest older than the card can still run turns entirely on it.
  ARCH_LIST=$(jq -r '(.gpu.torch_cuda_arch_list // []) | map(select(startswith("sm_"))) | map(gsub("[^0-9]";"")) | map(select(. != "")) | join(" ")' "$MANIFEST")
  PTX_LIST=$(jq -r '(.gpu.torch_cuda_arch_list // []) | map(select(startswith("compute_"))) | map(gsub("[^0-9]";"")) | map(select(. != "")) | join(" ")' "$MANIFEST")
  if [ -n "$ARCH_LIST" ]; then
    HAVE_CC=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | head -1 | tr -d ' ')
    HAVE_SM=$(printf '%s' "$HAVE_CC" | tr -d '.')
    if [ -n "$HAVE_SM" ]; then
      GPU_WAS=$(jq -r '.gpu.captured_on.name // "the packing machine"' "$MANIFEST")
      in_list=0; max_sm=0; min_sm=99999
      for a in $ARCH_LIST; do
        [ "$a" = "$HAVE_SM" ] && in_list=1
        [ "$a" -gt "$max_sm" ] 2>/dev/null && max_sm="$a"
        [ "$a" -lt "$min_sm" ] 2>/dev/null && min_sm="$a"
      done
      if [ "$in_list" = 1 ]; then
        log "This GPU (compute $HAVE_CC, sm_$HAVE_SM) is one torch was built for. Good match."
      elif [ "$HAVE_SM" -lt "$min_sm" ] 2>/dev/null; then
        # Forward compatibility only: a card older than the lowest build target
        # cannot be rescued by prebuilt kernels or by PTX.
        warn "This GPU (compute $HAVE_CC, sm_$HAVE_SM) is older than the lowest one torch was built for (sm_$min_sm, packed on $GPU_WAS). Torch has no kernels this old — it will almost certainly fail with 'no kernel image'."
        warn "  Use a card at sm_$min_sm or newer, or pack a fresh nest on this one. Carrying on anyway."
      elif [ "$HAVE_SM" -le "$max_sm" ] 2>/dev/null; then
        log "This GPU (compute $HAVE_CC, sm_$HAVE_SM) is not a prebuilt target but sits between sm_$min_sm and sm_$max_sm, so it should work. Your first image may be slower while the kernels compile."
      else
        if [ -n "$PTX_LIST" ]; then
          # The nest carries the half-finished form, so the driver **may** be
          # able to compile something this card can run. That path has never
          # been measured here, and compiled plugin binaries usually carry no
          # half-finished form at all, so it can still fail part-way through.
          warn "This GPU (compute $HAVE_CC, sm_$HAVE_SM) is newer than the highest one torch was built for (sm_$max_sm, packed on $GPU_WAS). This nest does carry a forward-compatible form (PTX: $PTX_LIST), so the driver may be able to compile for this card — the first image will be slow. We have never measured this, and compiled plugin extensions usually carry no PTX, so it can still fail. Carrying on anyway."
        else
          warn "This GPU (compute $HAVE_CC, sm_$HAVE_SM) is newer than the highest one torch was built for (sm_$max_sm, packed on $GPU_WAS), and this nest carries no forward-compatible form at all (no PTX) — there is nothing here this card can run. Expect 'no kernel image': every file will match byte for byte, and it still will not start."
          warn "  Use a card at sm_$max_sm or older (a 4090 or A4000, say), or pack a fresh nest on a card of this generation. Carrying on anyway."
        fi
      fi
    fi
  fi
fi

STAGE="S1-fetch"
# ---- Presigned file list (optional) -----------------------------------------
if [ -n "$BLOB_MANIFEST" ]; then
  # `%%\?*` drops the query string: a presigned link is a bearer credential, and
  # this output gets pasted into support tickets. Same rule as FETCH-MISSING above.
  log "Using the presigned file list: ${BLOB_MANIFEST%%\?*}"
  if [ -f "$BLOB_MANIFEST" ]; then
    cp "$BLOB_MANIFEST" "$BLOBMAP"
  else
    curl -fsSL "$BLOB_MANIFEST" -o "$BLOBMAP" || die FETCH-BLOBMAP "Could not download the presigned file list: ${BLOB_MANIFEST%%\?*}"
  fi
  jq -e 'type == "object"' "$BLOBMAP" >/dev/null || die BLOBMAP-BAD "The presigned file list is malformed (it should be a {sha256: url} object)"
fi

# blob_url <sha256> — work out where to download this file from
blob_url() {
  local h="$1"
  if [ -n "$BLOB_MANIFEST" ]; then
    local u; u=$(jq -r --arg h "$h" '.[$h] // empty' "$BLOBMAP")
    [ -n "$u" ] || die BLOBMAP-MISS "The presigned list has no entry for ${h:0:12}… — there is nowhere to download that file from"
    printf '%s' "$u"
  else
    printf '%s/%s/%s' "$BLOB_BASE" "${h:0:2}" "$h"
  fi
}

# Where we note which sha256 already landed where, so a second path pointing at the
# same bytes copies instead of downloading again. Under the target so a resumed run
# still has it; failing to create it only costs the saving, never correctness.
SEEN_BLOBS="$TARGET/.renest/landed-blobs"
mkdir -p "$SEEN_BLOBS" 2>/dev/null || SEEN_BLOBS=""

# ---- 2. Download one file and check it --------------------------------------
# fetch_blob <sha256> <destination> [progress prefix]
fetch_blob() {
  local STAGE="S1-fetch"      # anything failing in here is a fetch failure
  local h="$1" dest="$2" prefix="${3:-}" url tmp got
  url=$(blob_url "$h")
  tmp="$dest.part"
  mkdir -p "$(dirname "$dest")"
  if [ -f "$dest" ] && [ "$(sha256_of "$dest")" = "$h" ]; then
    log "  ${prefix}already here and byte-checked, skipping $(basename "$dest")"; return 0
  fi
  # **One sha256, one download.** A manifest may point several paths at the same bytes
  # (one big model referenced from several places is normal); fetching each path
  # separately spends the user's bandwidth once per reference. If these bytes already
  # landed somewhere, copy from there and check the copy the same way -- a bad copy has
  # to fail here, not three stages later reading as "the download was damaged".
  if [ -n "${SEEN_BLOBS:-}" ] && [ -f "$SEEN_BLOBS/$h" ]; then
    local twin; twin=$(cat "$SEEN_BLOBS/$h")
    if [ -f "$twin" ] && [ "$twin" != "$dest" ]; then
      cp "$twin" "$dest" || die FETCH-BLOB "Could not copy $twin to $dest"
      got=$(sha256_of "$dest")
      [ "$got" = "$h" ] || die HASH-MISMATCH "Copying $twin to $dest did not produce the same bytes (expected $h, got $got)."
      log "  ${prefix}same bytes as $(basename "$twin") — copied instead of downloading again"
      return 0
    fi
  fi
  # --speed-limit/--speed-time: stall suicide. A dead TCP connection never
  # triggers --retry on its own; below 10 KiB/s for 30s curl exits 28 (retryable),
  # --retry takes over and -C - resumes. Real-machine proof 2026-07-25: two
  # RunPod 4090 secure hosts froze mid-transfer and hung the full 1800s window.
  # -w '%{http_code}' still prints the status code under -f, so on failure we
  # know what the storage actually said — that is what separates "this object is
  # not in the bucket" from a network fault. The cost of calling everything a
  # network fault: someone holding a 404 goes off debugging their network while
  # the real problem is in the bucket.
  local http=""
  if ! http=$(curl -fSL --progress-bar --retry "$RETRIES" --retry-delay 2 -C - \
       --speed-limit 10240 --speed-time 30 -w '%{http_code}' "$url" -o "$tmp"); then
    case "$http" in
      404|410)
        die FETCH-MISSING "The storage says this file is not there: ${prefix}${h:0:12}…
       URL: ${url%%\?*}
       This is not a network problem — retrying will not make it appear. Usually one of:
         (1) the nest was never finished uploading (the manifest is written last, on
             purpose, so a manifest without its files means the upload was cut short);
         (2) BLOB_BASE or the bucket/folder is wrong;
         (3) this key is not allowed to read it — some providers answer \"not found\"
             instead of \"forbidden\" when the key cannot list the bucket." ;;
      401|403)
        die FETCH-DENIED "The storage refused this file: ${prefix}${h:0:12}… (HTTP $http)
       URL: ${url%%\?*}
       The signed link has probably expired — regenerate BLOB_MANIFEST and run this
       again. If you are using a key directly, check it is allowed to read this bucket." ;;
      *)
        die FETCH-BLOB "Download failed: ${prefix}${h:0:12}… — gave up after $RETRIES retries.
       URL: ${url%%\?*}   (last status: ${http:-none})
       Check: (1) can this machine reach the storage?  (2) has the signed link
              expired (regenerate BLOB_MANIFEST)?  (3) is BLOB_BASE right?" ;;
    esac
  fi
  got=$(sha256_of "$tmp")
  [ "$got" = "$h" ] || die HASH-MISMATCH "$dest does not match what the nest says it should be (expected $h, got $got). The download was damaged, or the source was tampered with."
  mv "$tmp" "$dest"
  # Remember where these bytes landed, so a second path referring to the same sha256
  # copies from here instead of paying for the download twice.
  [ -n "${SEEN_BLOBS:-}" ] && printf '%s' "$dest" > "$SEEN_BLOBS/$h"
  return 0
}

# ---- 3. Which image this nest was built on (told, not enforced) -------------
# base_image is optional from format 2.3 on: a container cannot see its own image
# name, and a nest packed where we could not find it out leaves the whole block
# out rather than writing a placeholder. Print nothing rather than the word
# "null" — a made-up value in a log is worse than a missing line.
# (Same bug class as the lockfile step below, where this script once tried to
#  download blobs/sha256/nu/null on a real machine.)
WANT_REF=$(jq -r '.base_image.ref // empty' "$MANIFEST")
WANT_DIGEST=$(jq -r '.base_image.digest // empty' "$MANIFEST")
if [ -n "$WANT_REF" ]; then
  log "Built on image: $WANT_REF"
  if [ -n "$WANT_DIGEST" ]; then
    log "  digest: $WANT_DIGEST — worth checking this machine uses the same one. We will try either way, but nothing is guaranteed if it differs."
  fi
else
  log "This nest does not say which container image it was built on — that line is optional, and rebuilding never needed it. Carrying on."
fi

# ---- 3b. Libraries this machine has to provide (format 2.6) -----------------
# These belong to the machine's distribution, so no nest can carry them. Checked
# **here**, before anything is downloaded: a machine short of one restores every
# byte, starts, answers — and silently loses whole plugins, which the user only
# finds out when running their own workflow. This script never starts the app, so
# this list is the only chance it has to say so.
# Deliberately not `ldd`: measured, it reported libraries the nest carries itself
# as missing, and got the direction wrong on others. A plain look in the standard
# library folders, under the exact name the program asks for, does not.
# The C library the nest was built against. Same question the agent-side check asks
# (check_system_layer), same verdict, so the two legs do not contradict each other on
# the same machine: warn only when **this** machine is older than the nest's, because
# pre-built packages are chosen against that number and may refuse to install.
# `ldd --version` is used only to read a version string here -- not to resolve which
# libraries a program needs, which is what the note below rejects it for.
# Both readers are optional: no reading, no sentence. Never a refusal (this leg informs).
# BEGIN libc-check -- the parity test runs exactly these lines, so they cannot drift
WANT_LIBC=$(jq -r '.runtime.libc_version // empty' "$MANIFEST")
if [ -n "$WANT_LIBC" ]; then
  HAVE_LIBC=""
  if command -v getconf >/dev/null 2>&1; then
    HAVE_LIBC=$(getconf GNU_LIBC_VERSION 2>/dev/null | tr -dc '0-9.' )
  fi
  if [ -z "$HAVE_LIBC" ] && command -v ldd >/dev/null 2>&1; then
    HAVE_LIBC=$(ldd --version 2>/dev/null | head -1 | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+' | head -1)
  fi
  if [ -n "$HAVE_LIBC" ]; then
    _w_maj=${WANT_LIBC%%.*}; _w_rest=${WANT_LIBC#*.}; _w_min=${_w_rest%%.*}
    _h_maj=${HAVE_LIBC%%.*}; _h_rest=${HAVE_LIBC#*.}; _h_min=${_h_rest%%.*}
    case "$_w_maj$_w_min$_h_maj$_h_min" in *[!0-9]*) _w_maj="" ;; esac
    if [ -n "$_w_maj" ] && { [ "$_h_maj" -lt "$_w_maj" ] || { [ "$_h_maj" -eq "$_w_maj" ] && [ "$_h_min" -lt "$_w_min" ]; }; }; then
      warn "This machine's C library is $HAVE_LIBC and this nest was packed against $WANT_LIBC. Pre-built packages are chosen against that number, so some of them may refuse to install here."
      warn "  Your nest is fine -- this belongs to the machine's operating system. Surest fix: start again from a machine whose C library is $WANT_LIBC or newer."
    fi
  fi
fi
# END libc-check

NL_METHOD=$(jq -r '.runtime.native_libs.method // empty' "$MANIFEST")
if [ -n "$NL_METHOD" ]; then
  NL_MISSING=""
  for _lib in $(jq -r '.runtime.native_libs.names[]?' "$MANIFEST"); do
    _found=0
    for _d in /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu \
              /lib/aarch64-linux-gnu /usr/lib64 /lib64 /usr/lib /lib /usr/local/lib \
              /usr/local/cuda/lib64 /usr/local/cuda/compat; do
      [ -e "$_d/$_lib" ] && { _found=1; break; }
    done
    [ "$_found" = 1 ] || NL_MISSING="$NL_MISSING $_lib"
  done
  if [ -z "$NL_MISSING" ]; then
    log "Every machine library this nest's run needed is here."
  elif [ "$NL_METHOD" = "loaded" ]; then
    # "loaded" means the working run really used these, so a missing one is a real
    # gap. Still only a warning: this script tells you, it does not refuse.
    NL_SHORT="$NL_MISSING"   # kept for the closing lines, which say it once more
    warn "This machine is missing $(printf '%s' "$NL_MISSING" | wc -w | tr -d ' ') library file(s) the working run used:$NL_MISSING"
    warn "  Your nest is fine — every byte will still be restored. These belong to the machine's operating system and no nest can carry them."
    if [ -n "$WANT_REF" ]; then
      warn "  Surest fix: start again from the image this was packed on ($WANT_REF). A machine short of one of these is usually short of several, and the right image brings them all at once."
    else
      warn "  A machine short of one of these is usually short of several, so installing them one at a time tends to take several rounds. On Debian or Ubuntu, apt-file search <name> tells you which package holds one."
    fi
  else
    # "declared" is the fallback list: it covers only part of what is really used and
    # also names libraries that are never loaded at all. Measured, one machine was
    # missing four of them while producing images perfectly well — so this one stays
    # a mild note and must never grow into a refusal.
    log "Note: $(printf '%s' "$NL_MISSING" | wc -w | tr -d ' ') library file(s) named by this nest are not on this machine:$NL_MISSING"
    log "  This list was read off the installed packages rather than off the working run, so it names libraries that may never be used. Carrying on; come back to this only if something fails to load later."
  fi
fi

# ---- 4. Put the source code back --------------------------------------------
STAGE="S2-place"
log "Restoring source code…"
while read -r dep; do
  name=$(jq -r '.name' <<<"$dep")
  path="$TARGET/$(jq -r '.install_path' <<<"$dep")"
  h=$(jq -r '.archive.sha256' <<<"$dep")
  commit=$(jq -r '.commit' <<<"$dep")
  log "  $name @ ${commit:0:8}"
  fetch_blob "$h" "$TARGET/.renest/archives/$name.tar.gz"
  mkdir -p "$path"
  tar -xzf "$TARGET/.renest/archives/$name.tar.gz" -C "$path" --strip-components=1
  post=$(jq -r '.post_install // empty' <<<"$dep")
  # The escape hatch tells you, it does not stop you (that is the whole promise).
  # But "does not stop you" is not "does not tell you": this is a plain command
  # line the packer wrote into the nest, and it runs as you, here. You get to see
  # it. The Renest agent asks first; this script only shows.
  if [ -n "$post" ]; then
    warn "$name brought setup commands. Running them now — they run as you, on this machine:"
    printf '    %s\n' "$post" >&2
    ( cd "$path" && bash -c "$post" )
  fi
done < <(jq -c '.code_deps[]' "$MANIFEST")

# ---- 5. Rebuild the Python environment from the lockfile --------------------
STAGE="S3-deps"
log "Rebuilding the Python environment…"
# python_lock is optional in the schema (a target-only pack can legally omit it).
# When absent, say so and skip — never treat jq's literal null as a hash.
# (Real-machine proof 2026-07-26: this script once tried to download
#  blobs/sha256/nu/null. The escape hatch informs, it never refuses.)
LOCK_H=$(jq -r '.python_lock.lockfile.sha256 // empty' "$MANIFEST")
T_DEPS_START=$(date +%s)
if [ -z "$LOCK_H" ]; then
  warn "This nest carries no python_lock (no dependency lockfile was captured at pack time) — skipping the environment rebuild; dependencies are up to the current machine."
else
fetch_blob "$LOCK_H" "$TARGET/.renest/requirements.lock"
# Where the lock belongs. From format 2.6 the nest records where it sat; before that
# it did not, so it landed at $TARGET/requirements.lock by fixed convention — which is
# still what an older nest gets, and what an absent field means. The fine-tuning
# frameworks keep theirs in a sub-directory, and that convention moved the file
# somewhere the framework does not look. One copy is for uv to read; this one is so
# the byte check covers it too.
LOCK_LANDING=$(jq -r '.python_lock.lockfile_path // "requirements.lock"' "$MANIFEST")
mkdir -p "$(dirname "$TARGET/$LOCK_LANDING")"
cp "$TARGET/.renest/requirements.lock" "$TARGET/$LOCK_LANDING"
# ---- Which servers may we install from? -------------------------------------
# Whoever packed this nest wrote the lockfile, and uv installs whatever it points
# at — which means running their code on this machine, with access to everything
# on it. So this one we refuse rather than warn about. Two ways through: name your
# own private index in RENEST_TRUSTED_HOSTS, or, if you trust where this nest came
# from, re-run with TRUST_UNSAFE_URLS=1.
#
# Note this list is a snapshot baked into the script. The Renest agent refreshes
# its copy automatically; this script deliberately does not phone home, so a newly
# popular source is recognised there before it is recognised here. That is the
# price of not depending on us — use one of the two ways through above.
TRUST_UNSAFE_URLS="${TRUST_UNSAFE_URLS:-}"
EXTRA_HOSTS=$(printf '%s' "${RENEST_TRUSTED_HOSTS:-}" | tr ';,' '\n\n' | tr -d ' ' | tr 'A-Z' 'a-z')
# RENEST-TRUSTED-HOSTS-SNAPSHOT-BEGIN
# ↓ Kept identical to the hosts list in oss/src/renest/data/trusted-hosts.json.
#   A consistency test (oss/tests/consistency/test_trusted_hosts_snapshot.py)
#   fails the moment one side is edited without the other.
TRUSTED_HOSTS_SNAPSHOT="
pypi.org files.pythonhosted.org download.pytorch.org download-r2.pytorch.org download-r2.pytorch.org
pypi.nvidia.com pypi.ngc.nvidia.com data.pyg.org
developer.download.nvidia.com developer.download.nvidia.cn developer.nvidia.cn
github.com codeload.github.com objects.githubusercontent.com
release-assets.githubusercontent.com raw.githubusercontent.com gitlab.com
huggingface.co hf-mirror.com
pypi.tuna.tsinghua.edu.cn mirrors.tuna.tsinghua.edu.cn mirrors.bfsu.edu.cn
mirrors.aliyun.com mirrors.aliyuncs.com mirrors.cloud.aliyuncs.com
mirrors.cloud.tencent.com mirrors.tencent.com mirrors.tencentyun.com mirror.ccs.tencentyun.com
repo.huaweicloud.com mirrors.huaweicloud.com mirror.baidu.com mirrors.163.com
pypi.mirrors.ustc.edu.cn mirrors.ustc.edu.cn mirrors.pku.edu.cn
mirror.nju.edu.cn mirrors.nju.edu.cn
mirror.sjtu.edu.cn mirrors.sjtu.edu.cn mirrors.sjtug.sjtu.edu.cn
mirrors.zju.edu.cn mirrors.hit.edu.cn mirrors.bupt.edu.cn mirrors.cernet.edu.cn
pypi.douban.com pypi.doubanio.com
"
# RENEST-TRUSTED-HOSTS-SNAPSHOT-END
# Skip whole-line comments, matching the agent's own check exactly — the two
# must never disagree about the same lockfile.
UNSAFE_URLS=$(grep -v '^[[:space:]]*#' "$TARGET/.renest/requirements.lock" 2>/dev/null \
  | grep -oE '[A-Za-z][A-Za-z0-9+.-]*://[^[:space:]'"'"'"#]+' \
  | sort -u \
  | while IFS= read -r url; do
      # case arms are written with balanced parentheses (pattern): an old bash
      # (3.2, the one macOS ships) trips over the lone closing parenthesis when
      # it parses a case inside $( ), and the balanced form is read correctly by
      # both generations of bash.
      # Strip a version-control prefix before judging. `pip`/`uv` write
      # `git+https://github.com/org/repo@commit` for a dependency taken straight
      # from a repository, and that string does **not** start with `https://`, so
      # without this line it fell into the catch-all below and was refused
      # **without its host ever being looked at** -- even though github.com is on
      # the list right here. 2026-08-12, on a real machine: a nest holding one of
      # the five most-installed ComfyUI extensions could not be rebuilt at all.
      # The agent side has stripped this prefix since 2026-08-02; this leg had
      # not, and the consistency test between the two legs compares the host
      # **list** only, so the divergence in *logic* went unnoticed.
      # Only `something+https://` is stripped: a bare `git://` or `http://` still
      # falls through to the refusal below, as it should.
      case "$url" in
        (*+https://*) vcsurl="${url#*+}" ;;
        (*) vcsurl="$url" ;;
      esac
      # `file://` pointing **inside the directory being rebuilt** is not an outside
      # server: it is code this nest brought with it. Editable installs of the
      # fine-tuning frameworks leave exactly such a line, so refusing it made those
      # nests impossible to rebuild by this route at all -- and rule 5 promises this
      # script alone can rebuild any nest. Resolved with `cd`+`pwd -P` (shell
      # builtins, no new dependency) so a symlink or `..` cannot lead outside.
      # `file://host/path` is another machine and stays refused.
      case "$vcsurl" in
        (file://*)
          fpath="${vcsurl#file://}"
          case "$fpath" in (/*) ;; (*) printf '%s\n' "$url"; continue ;; esac
          freal=$(cd "$fpath" 2>/dev/null && pwd -P) || { printf '%s\n' "$url"; continue; }
          troot=$(cd "$TARGET" 2>/dev/null && pwd -P) || troot=""
          if [ -n "$troot" ]; then
            case "$freal/" in ("$troot"/*) continue ;; esac
          fi
          printf '%s\n' "$url"; continue ;;
      esac
      case "$vcsurl" in
        (https://*) ;;
        (*) printf '%s\n' "$url"; continue ;;  # plain http can be tampered with in transit
      esac
      host="${vcsurl#https://}"; host="${host%%/*}"; host="${host##*@}"; host="${host%%:*}"
      host=$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')
      [ -n "$host" ] || { printf '%s\n' "$url"; continue; }
      case " ${TRUSTED_HOSTS_SNAPSHOT//$'\n'/ } ${EXTRA_HOSTS//$'\n'/ } " in
        (*" $host "*) ;;                       # on the list (EXTRA comes from RENEST_TRUSTED_HOSTS)
        (*) printf '%s\n' "$url" ;;
      esac
    done || true)
if [ -n "$UNSAFE_URLS" ]; then
  if [ -n "$TRUST_UNSAFE_URLS" ]; then
    warn "Allowing these unrecognised sources because you set TRUST_UNSAFE_URLS=1:"
    # Strip the query string before showing a URL: model hosts put the user's own
    # API token in it, and this output ends up in tickets and forum posts.
    printf '%s\n' "$UNSAFE_URLS" | head -5 | sed -e 's/?.*//' -e 's/^/    /' >&2
  else
    UNSAFE_HOSTS=$(printf '%s\n' "$UNSAFE_URLS" | while IFS= read -r u2; do
        h="${u2#*://}"; h="${h%%/*}"; h="${h##*@}"; h="${h%%:*}"
        [ -n "$h" ] && printf '%s\n' "$h" || true
      done | tr '[:upper:]' '[:lower:]' | sort -u | head -3 | paste -sd, -)
    die DEPS-UNTRUSTED-URL "This nest wants to install from servers nobody recognises. Stopped — nothing was installed:
$(printf '%s\n' "$UNSAFE_URLS" | head -5 | sed -e 's/?.*//' -e 's/^/       /')

       Installing dependencies runs code those servers hand you, on this machine.
       That code can read everything here: the models you just restored, your
       storage credentials, whatever else lives on this box.

       > First answer one question: did you pack this nest, or did someone give it to you?

         - You packed it (a private index at work, say) — name the host and re-run:
             RENEST_TRUSTED_HOSTS=$UNSAFE_HOSTS bash restore.sh

         - Someone gave it to you — stop and think: do you trust them?
           Do you recognise that domain? If not, do not allow it. Go ask them
           why their setup installs from there. A nest built to attack you uses
           exactly this step, and the restore looks normal the whole time."
  fi
fi
PYVER=$(jq -r '.runtime.python_version' "$MANIFEST")
# Re-running has to be safe: anyone who hits a failure will try again. uv fails
# hard when the directory exists but is not a venv, and --clear does not save it,
# so remove it first. Only the .venv this script created — nothing else.
rm -rf "$TARGET/.venv"
uv venv --python "$PYVER" "$TARGET/.venv" || die DEPS-VENV "uv could not create the environment (it needs python $PYVER). A machine that cannot provide that version is the most common failure at this stage."
# Where packages come from. PACKAGE_SOURCE lets you point at a closer mirror when the
# default one is slow for you — on one real machine the difference was 37x (5.9 vs 216
# Mbps for the same 30 MB). This is safe to offer because the nest records a fingerprint
# for every package: wrong bytes stop the rebuild instead of quietly landing.
# No new dependency — it is just an environment variable uv already reads.
if [ -n "${PACKAGE_SOURCE:-}" ]; then
  log "Installing dependencies from $PACKAGE_SOURCE instead of the default. Every package is still checked against the fingerprint recorded in this nest."
  export UV_DEFAULT_INDEX="$PACKAGE_SOURCE"
fi
VIRTUAL_ENV="$TARGET/.venv" uv pip sync "$TARGET/.renest/requirements.lock" 2>&1 | tee "$DEPSLOG" || die DEPS-SYNC "Installing dependencies failed. uv's own output above is the real diagnosis — read it, and it is also saved to $DEPSLOG. The three usual causes:
       (1) torch/CUDA will not install on this machine (wrong base image)
       (2) a package needs compiling here and there is no compiler
       (3) a pinned wheel link returns 404 because that build was removed upstream.
           The Renest agent falls back to the generic version automatically; this
           script does not. Edit that line to name==version and run it again."

# ---- 5b. Several packages wrote the same folder: make the survivor the one that worked (format 2.8)
# The OpenCV family (opencv-python / -contrib / -headless) all write cv2/, and the
# installer decides who writes last — not stably: measured 2026-08-17, one lock on
# one machine gave a different survivor on back-to-back installs, and the survivor
# decides which machine libraries the module needs. The nest records which copy the
# working run used, as the hash of the installed file. Differ → reinstall that one
# package alone (its own line from the lock, no dependencies) so it writes last,
# then check again. Still different → say so. **This script tells you, it never refuses.**
_N_CM=$(jq -r '(.runtime.contested_modules // []) | length' "$MANIFEST")
_i=0
while [ "$_i" -lt "$_N_CM" ]; do
  _MOD=$(jq -r ".runtime.contested_modules[$_i].module" "$MANIFEST")
  _WIN=$(jq -r ".runtime.contested_modules[$_i].winner" "$MANIFEST")
  _REL=$(jq -r ".runtime.contested_modules[$_i].winner_evidence.file" "$MANIFEST")
  _WANT=$(jq -r ".runtime.contested_modules[$_i].winner_evidence.sha256" "$MANIFEST")
  _i=$((_i + 1))
  _F=$(ls "$TARGET"/.venv/lib/python3*/site-packages/"$_REL" 2>/dev/null | head -1 || true)
  _GOT=""; [ -n "$_F" ] && [ -f "$_F" ] && _GOT=$(sha256_of "$_F")
  if [ "$_GOT" = "$_WANT" ]; then
    log "The installed copy of $_MOD is the one your working setup used."
    continue
  fi
  # The winner's own line from the lock (name==version or name @ url), hash options
  # dropped; spelling of the name is matched loosely (- _ . are interchangeable).
  _REQ=$(grep -iE "^${_WIN//[-_.]/[-_.]}[[:space:]]*(==|@)" "$TARGET/.renest/requirements.lock" 2>/dev/null | head -1 | sed -E 's/[[:space:]]+--hash=.*//; s/[[:space:]]+#.*//; s/[[:space:]]*\\$//' || true)
  if [ -z "$_REQ" ]; then
    warn "The copy of $_MOD installed here is not the one your working setup used, and $_WIN is not pinned in this nest's dependency list, so it could not be reinstalled. Carrying on: anything that imports $_MOD may behave differently from the run that worked."
    continue
  fi
  if ! VIRTUAL_ENV="$TARGET/.venv" uv pip install --reinstall --no-deps "$_REQ" 2>&1 | tee -a "$DEPSLOG"; then
    warn "The copy of $_MOD installed here is not the one your working setup used, and reinstalling $_WIN failed (uv's output above says why). Carrying on: anything that imports $_MOD may behave differently from the run that worked."
    continue
  fi
  _F=$(ls "$TARGET"/.venv/lib/python3*/site-packages/"$_REL" 2>/dev/null | head -1 || true)
  _GOT=""; [ -n "$_F" ] && [ -f "$_F" ] && _GOT=$(sha256_of "$_F")
  if [ "$_GOT" = "$_WANT" ]; then
    warn "The copy of $_MOD that ended up installed was not the one your working setup used; reinstalled $_WIN so it is."
  else
    warn "The copy of $_MOD installed here is not the one your working setup used; $_WIN was reinstalled and now writes last, but its $_REL is a different build from the one your working setup had. Carrying on: anything that imports $_MOD may behave differently from the run that worked."
  fi
done
fi
T_DEPS_END=$(date +%s)

# ---- 6. Move the big files, several at a time -------------------------------
# Only this section counts toward the transfer speed we report. Dependency
# installs take minutes; folding them in would invent a bandwidth number.
STAGE="S2-place"
N=$(jq '.files | length' "$MANIFEST")
TOTAL=$(jq '[.files[].blob.size_bytes] | add // 0' "$MANIFEST")
log "Moving $N files, $(hsize "$TOTAL") in total…"
T_XFER_START=$(date +%s)
i=0
while read -r f; do
  i=$((i+1))
  relpath=$(jq -r '.path' <<<"$f")
  froot=$(jq -r '.root // "env"' <<<"$f")
  # Every file lands as a real file, with the name and extension the nest gives
  # it (fetch_blob downloads to <dest>.part, checks the bytes, then renames).
  # Never a symlink, and never a second copy under a hashed name: tools resolve
  # symlinks and then decide what a file is from its extension alone, so a link
  # with the extension stripped off gets read as the wrong format, and the error
  # you get points nowhere near the real cause.
  path="$(root_dir "$froot")/$relpath"
  h=$(jq -r '.blob.sha256' <<<"$f")
  sz=$(jq -r '.blob.size_bytes' <<<"$f")
  (
    fetch_blob "$h" "$path" "[$i/$N] "
    printf '\033[1;32m[renest]\033[0m   [✓ %d/%d] %s (%s)\n' "$i" "$N" "$relpath" "$(hsize "$sz")"
  ) &
  # cap how many run at once
  while [ "$(jobs -rp | wc -l)" -ge "$PARALLEL" ]; do wait -n; done
done < <(jq -c '.files[]' "$MANIFEST")
wait
# A failure inside a background job only exits that job. If one of them already
# recorded a failure, stop now and keep its attribution — otherwise the script
# runs on and dies again at the verify stage, reporting the wrong cause.
if [ -f "$FAILFILE" ]; then
  log "One of the downloads failed (details in $FAILFILE) — stopping"
  exit 1
fi
T_XFER_END=$(date +%s)

# Count the bytes actually on disk, not what the manifest claims. Counting files
# that never arrived would invent a bandwidth number out of a failed run.
XFER_BYTES=0
while read -r f; do
  p="$(root_dir "$(jq -r '.root // "env"' <<<"$f")")/$(jq -r '.path' <<<"$f")"
  [ -f "$p" ] && XFER_BYTES=$((XFER_BYTES + $(wc -c < "$p")))
done < <(jq -c '.files[]' "$MANIFEST")

# ---- 6b. Put the recipe back where it lived (format 2.6) --------------------
# Until now this script never fetched the recipe at all: the bytes sat in the nest
# and no restore ever asked for them. Iron rule 5 says the escape hatch alone must
# rebuild a nest **completely**, and the recipe is part of the nest, so leaving it
# behind was leaving the job unfinished. Putting a file down is not starting the
# app — that stays out of scope, and this does not change it.
WF_H=$(jq -r '.adapters.comfyui.workflow.sha256 // empty' "$MANIFEST")
if [ -n "$WF_H" ]; then
  WF_STAGED="$TARGET/.renest/staging/workflow.json"
  fetch_blob "$WF_H" "$WF_STAGED"
  WF_PATH=$(jq -r '.adapters.comfyui.workflow_path // empty' "$MANIFEST")
  if [ -z "$WF_PATH" ]; then
    # Older than 2.6: the nest never recorded where it lived. Say so and stop there —
    # **never invent a path.** A guess either overwrites something of the user's or
    # points somewhere the app never looks, and nothing would tell them either way.
    log "This nest doesn't record where its comfyui recipe used to live, so it is here instead: $WF_STAGED. Copy it wherever you keep your workflows."
  elif { [ -e "$TARGET/$WF_PATH" ] && [ ! -f "$TARGET/$WF_PATH" ]; } || \
       { [ -f "$TARGET/$WF_PATH" ] && [ "$(sha256_of "$TARGET/$WF_PATH")" != "$WF_H" ]; }; then
    # The first half is a directory sitting on that name: `cp` would put the file
    # inside it, which is not what the nest asked for and not what the agent does.
    warn "There is already a different $WF_PATH here, so we left yours alone. The recipe from this nest is here instead: $WF_STAGED."
  else
    mkdir -p "$(dirname "$TARGET/$WF_PATH")"
    cp "$WF_STAGED" "$TARGET/$WF_PATH"
    log "Recipe is back where it lived: $TARGET/$WF_PATH"
  fi

  # A workflow built elsewhere often names its files the long way
  # (/workspace/ComfyUI/models/x.safetensors). On a machine whose root is somewhere
  # else every one of those goes nowhere, and the app's own error says nothing about
  # why. Two components minimum: a one-word value like /upscale is a label, not a path.
  # **Nothing new is stored to make this possible** — the paths are in the recipe
  # itself. We name them; we do not create the link, which would mean writing outside
  # the folder you gave us.
  _STRAY=$(jq -r '[.. | strings | select(test("^(/[^/]+/[^/]|[A-Za-z]:[\\\\/])"))] | unique | .[]' \
             "$WF_STAGED" 2>/dev/null | while IFS= read -r _p; do
             [ -e "$_p" ] || printf '%s, ' "$_p"; done | sed 's/, $//')
  if [ -n "$_STRAY" ]; then
    warn "This recipe still names full paths from the machine it was built on, and they do not exist here: $_STRAY. Nothing is broken in the rebuild — the files it needs are in place under this folder — but those nodes will not find them until you point each one at its file by name, or make the old path lead here yourself."
  fi
fi

# ---- 7. Whatever else this nest needs run ----------------------------------
POST=$(jq -r '.post_install // empty' "$MANIFEST")
if [ -n "$POST" ]; then
  warn "This nest brought setup commands. Running them now — they run as you, on this machine:"
  printf '    %s\n' "$POST" >&2
  bash -c "$POST"
fi

# ---- 8. Check every file, byte for byte -------------------------------------
STAGE="S4-verify"
log "Checking every file…"
T_VERIFY_START=$(date +%s)
FAIL=0
while read -r f; do
  path="$(root_dir "$(jq -r '.root // "env"' <<<"$f")")/$(jq -r '.path' <<<"$f")"
  h=$(jq -r '.blob.sha256' <<<"$f")
  [ "$(sha256_of "$path")" = "$h" ] || { echo "  ✗ $path"; FAIL=1; }
done < <(jq -c '.files[]' "$MANIFEST")
# The lockfile is checked too — it has to land correctly, not just be read.
# Nests without a lock skip this: never rely on ""=="" passing by accident
# (found by the oss real-machine gate, 2026-07-26).
if [ -n "$LOCK_H" ]; then
  [ "$(sha256_of "$TARGET/$LOCK_LANDING")" = "$LOCK_H" ] || { echo "  ✗ $TARGET/$LOCK_LANDING"; FAIL=1; }
fi
[ "$FAIL" = 0 ] || die VERIFY-HASH "The files listed above are not what this nest says they should be."
T_VERIFY_END=$(date +%s)

# ---- 9. Record the timings --------------------------------------------------
XFER_SECS=$((T_XFER_END - T_XFER_START)); [ "$XFER_SECS" -lt 1 ] && XFER_SECS=1
cat > "$TARGET/.renest/restore-metrics.json" <<JSON
{
  "transfer_seconds": $XFER_SECS,
  "transfer_bytes": $XFER_BYTES,
  "deps_seconds": $((T_DEPS_END - T_DEPS_START)),
  "verify_seconds": $((T_VERIFY_END - T_VERIFY_START)),
  "_note": "transfer_* covers the large-file section only; speed = transfer_bytes / transfer_seconds. Dependency installs are excluded on purpose."
}
JSON

rm -f "$FAILFILE"
log "✅ Done. Every file checked, byte for byte. Your setup is back."
log "   Moving files ${XFER_SECS}s / dependencies $((T_DEPS_END - T_DEPS_START))s / checking $((T_VERIFY_END - T_VERIFY_START))s"
if [ "$HOME_FILES" -gt 0 ]; then
  log "   Everything is under $TARGET, apart from $HOME_FILES model-cache files in $HF_HOME_ROOT"
else
  log "   Everything is under $TARGET"
fi
log "   Python environment: $TARGET/.venv"
# Said once already, before the download -- and by now that is a big nest, half an
# hour and a thousand progress lines ago, with a clean "Done" as the last thing on
# screen. Measured 2026-08-12: three restores on a machine short of one library came
# back byte-perfect and started fine, and not one of them could run its own recipe --
# the extensions load as nothing, silently. So say it last as well. Telling, not
# refusing: this script never blocks (2026-07-15 ruling).
if [ -n "${NL_SHORT:-}" ]; then
  warn "Read this before you call it done: every byte is back, but this machine is missing the library file(s) the working run used:$NL_SHORT"
  warn "   Until they are here, parts of this environment load as nothing. It will start and answer, and your own workflow is what will fail."
  [ -n "$WANT_REF" ] && warn "   Surest fix: start again from the image this was packed on ($WANT_REF) -- it brings all of them at once."
fi
