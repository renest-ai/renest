"""CLI side of cloud-delivered rules (``renest update-rules``).

[SECURITY-REVIEW] the whole delivery chain:
- root of trust = the ed25519 public key ring baked into the package
  (data/rules-signing-keys.json); an empty ring **shuts cloud updates off** (fail-closed)
  and only the built-in baseline is used -- never a quiet degrade to skipping signatures;
- every rules file is signature-checked first (against the raw content bytes the server
  returned), then put through the same structure check as rules.py, and only lands in
  ``~/.renest/rules/`` when both pass (atomic write via os.replace); failing either one
  means that file does not land at all;
- what lands is consumed by rules.py as a "user override", and anything broken falls back
  to the built-in baseline -- so even a poisoned channel can at worst put you back on the
  built-in rules; the engine is never led astray;
- the escape hatch is untouched: restore.sh reads no rules and never runs this command.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

from . import rules as _rules
from .errors import ExitCode
from .events import EventEmitter
from .rules import DOCTOR_RULES, FINGERPRINT_MATRIX, SOURCE_PLAYBOOK, TRUSTED_HOSTS, WORLD_RULES

__all__ = ["RULE_NAMES", "trusted_keys", "verify_and_install", "update_all",
           "staleness_warning", "warn_if_stale", "in_effect"]

#: Which rules files this channel refreshes.
#:
#: **License texts (data/licenses/) are deliberately kept out**: they are bytes that
#: travel with a nest, so they belong to content addressing, not to a mutable file
#: about the world -- hot-swapping legal text would change what past nests mean.
RULE_NAMES: tuple[str, ...] = (
    DOCTOR_RULES,
    FINGERPRINT_MATRIX,
    SOURCE_PLAYBOOK,
    TRUSTED_HOSTS,
    WORLD_RULES,
)
# Default service address. **The API domain, not the web domain**: the console is static
# hosting, where any /api/v1/* is swallowed by the catch-all page and comes back as a 200
# with HTML, which the CLI then misreports as a network fault.
DEFAULT_ORIGIN = "https://api.renest.ai"

#: Public repository holding nothing but rules -- a source that stays reachable whatever
#: happens to us, needs no login, and cannot leak anything (the rules hold no secret, and
#: the public key baked into every install is what proves they came from us).
#: Overridable by `RENEST_RULES_MIRROR` so users on an old version can rescue themselves
#: without waiting for a release, which is the whole reason this channel exists.
_GITHUB_ORIGIN_DEFAULT = "https://raw.githubusercontent.com/renest-ai/renest-rules/main"
GITHUB_ORIGIN = os.environ.get("RENEST_RULES_MIRROR", _GITHUB_ORIGIN_DEFAULT)

#: Main source: the same signed bytes on a CDN, whose edge nodes can absorb being scanned
#: and hammered. Down -> the public repository -> our own API -> the built-in baseline.
#: Not on the brand domain on purpose: that would tie the brand's DNS and certificates to
#: one piece of plumbing. Which domain serves it does not affect security, because the root
#: of trust is the public key in the install, not a domain.
CDN_ORIGIN = os.environ.get("RENEST_RULES_CDN", "https://rules.nesthandoff.com")

#: The host the rules now come from, tried first since 2026-08-11. It was added a release
#: earlier as a second choice, on purpose: an unconfigured host in first place costs every
#: refresh a dead request and reads as though the move had landed. The order was flipped
#: only after fetching from it for real -- same bundle, byte for byte identical to what the
#: old host served (both sha256 eb365fcf04495dc0...).
#: The move happens because the other domain exists to be sacrificed -- it carries hand-off
#: links strangers forward, so it is the one that gets blocked, and the tool's own refresh
#: channel must not sit on an expendable host.
NEXT_CDN_ORIGIN = os.environ.get("RENEST_RULES_CDN_NEXT", "https://rules.emptylatent.com")

#: Past this many days without a refresh, the rules are treated as possibly out of date.
#: They describe what the outside world looks like right now, and a batch of new things
#: from upstream every month is normal.
STALE_AFTER_DAYS = 30
_KEYS_FILE = Path(__file__).resolve().parent / "data" / "rules-signing-keys.json"


def trusted_keys() -> dict[str, bytes]:
    """The public key ring baked into the package, as {key_id: 32 raw bytes}.

    Unreadable or malformed means an empty ring, which shuts cloud updates off.
    """
    try:
        data = json.loads(_KEYS_FILE.read_text(encoding="utf-8"))
        return {
            str(kid): bytes.fromhex(hexkey)
            for kid, hexkey in (data.get("keys") or {}).items()
            if isinstance(hexkey, str) and len(hexkey) == 64
        }
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def _verify_sig(content: bytes, sig_hex: str, key_id: str, keys: dict[str, bytes]) -> str | None:
    """Check a signature; None means it passed, otherwise a description of the problem.

    An unknown key_id and a bad signature are both refused.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    raw = keys.get(str(key_id))
    if raw is None:
        return f"key_id={key_id} is not in the trusted key ring"
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(bytes.fromhex(sig_hex), content)
    except (InvalidSignature, ValueError):
        return "signature check failed"
    return None


def _install_dir() -> Path:
    env = os.environ.get("RENEST_RULES_DIR")
    return Path(env) if env else Path.home() / ".renest" / "rules"


def verify_and_install(
    name: str, content: bytes, sig_hex: str, key_id: str,
    keys: dict[str, bytes] | None = None,
) -> str | None:
    """One rules file: signature check -> structure check -> atomic install.

    Returns None once it is installed, otherwise the reason it was refused.
    """
    if name not in RULE_NAMES:
        return f"unknown rules file {name}"
    keys = keys if keys is not None else trusted_keys()
    if not keys:
        return "the trusted key ring is empty, so cloud updates are shut off (fail-closed)"
    problem = _verify_sig(content, sig_hex, key_id, keys)
    if problem is not None:
        return problem
    try:
        data = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "the content is not valid JSON"
    problem = _rules._validate(name, data)
    if problem is not None:
        return f"structure check failed: {problem}"
    # **Anti-downgrade: accept only something newer than what is already here.** A
    # signature proves "we issued this", not "this is the latest", so an old but validly
    # signed file (stale cache, or fed to you deliberately) could otherwise pin someone to
    # an outdated view of the world. Not strictly newer -> it does not land.
    older = _older_than_local(name, data)
    if older is not None:
        return older
    dest_dir = _install_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp = dest_dir / f".{name}.tmp"
    tmp.write_bytes(content)
    os.replace(tmp, dest_dir / name)
    _rules.clear_cache()
    return None


def issued_at(data: dict) -> str:
    """When this rules file was issued. **Stamped by the signing tool, never hand-written**
    -- a hand-written date lies (content edited, date forgotten), and the whole "speak up
    when it goes stale" behaviour rests on it."""
    return str(data.get("issued_at") or "")


#: Same stamp on both sides: nothing to do, and **not a failure**.
SAME_AS_LOCAL = "same"


def _older_than_local(name: str, incoming: dict) -> str | None:
    """Why the incoming copy must not replace the local one, or ``None``.

    Returns ``SAME_AS_LOCAL`` when both carry the same stamp -- the caller must
    report that as "already up to date" and succeed. Anything else returned is a
    real refusal: a validly signed but older file trying to push the machine back
    to an earlier view of the world.

    Nothing local yet (a first update), or neither side stamped a time -> let it
    through: **never hard-block when there is no timestamp**, or the very first
    update could not install at all.
    """
    new_at = issued_at(incoming)
    if not new_at:
        return None
    local = _install_dir() / name
    if not local.is_file():
        return None
    try:
        old_at = issued_at(json.loads(local.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return None
    if not old_at:
        return None
    # Equal is not a downgrade. Reporting it as one made a healthy machine print a
    # failure and exit non-zero, with a line that contradicted itself ("keeping the
    # newer one" about two copies of the same age). Measured 2026-08-11 while
    # checking a second delivery host: same file, both stamps identical.
    if new_at == old_at:
        return SAME_AS_LOCAL
    if new_at < old_at:
        return (
            f"this copy was issued {new_at}, and the one already here is {old_at} — "
            f"keeping the newer one. (A validly signed but stale file must never be "
            f"able to push you back to an older view of the world.)"
        )
    return None


def stale_days(name: str, *, now=None) -> int | None:
    """How many days ago the local rules file was issued.

    No timestamp, or unreadable -> ``None`` (meaning: unknown, and do not guess).
    """
    import datetime as _dt

    local = _install_dir() / name
    try:
        at = issued_at(json.loads(local.read_text(encoding="utf-8")))
        when = _dt.datetime.fromisoformat(at.replace("Z", "+00:00"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    now = now or _dt.datetime.now(_dt.UTC)
    return max(0, (now - when).days)


def staleness_note(name: str, *, now=None) -> str | None:
    """One plain-language line when it has gone stale; ``None`` when it has not, or when
    nothing is known.

    **Saying nothing is the same as not having this channel at all** -- nobody wonders on
    their own how old the rules on their machine are.
    """
    days = stale_days(name, now=now)
    if days is None or not _is_stale(days):
        return None
    return _stale_text(days)


def _is_stale(days: int) -> bool:
    """Past thirty days, not "on the thirtieth" -- one boundary, written once, so the
    warning and the tests cannot drift apart on the day it fires."""
    return days > STALE_AFTER_DAYS


def _stale_text(days: int) -> str:
    return (
        f"The compatibility facts on this machine are {days} days old. They go out of "
        f"date as the world moves on, and out-of-date facts are how a perfectly good "
        f"machine gets turned away. Refresh them with: renest update-rules"
    )


def staleness_warning(*, now=None) -> str | None:
    """One line for the whole set -- the five files land together, so five copies of the
    same sentence would just be noise. The oldest of them decides.

    **Nothing downloaded yet falls back to the age of what the install shipped with**,
    which is the case this whole warning exists for: installed once, left for six months,
    then turned away by facts that were already old on the day they arrived.
    """
    ages = [d for d in (stale_days(n, now=now) for n in RULE_NAMES) if d is not None]
    days = max(ages) if ages else _builtin_age_days(now=now)
    if days is None or not _is_stale(days):
        return None
    return _stale_text(days)


def _builtin_age_days(*, now=None) -> int | None:
    """How long ago the newest of the shipped rules files was last touched."""
    import datetime as _dt

    stamps = [s for s in (_rules.builtin_stamp(n) for n in RULE_NAMES) if s]
    if not stamps:
        return None
    try:  # dates are YYYY-MM-DD, which sorts correctly as text
        when = _dt.datetime.fromisoformat(max(stamps)).replace(tzinfo=_dt.UTC)
    except ValueError:
        return None
    return max(0, ((now or _dt.datetime.now(_dt.UTC)) - when).days)


def warn_if_stale(stream=None, *, now=None) -> None:
    """Print the staleness line where a user will see it, and never get in the way.

    A warning, not a wall: nothing is blocked, and any failure while checking is
    swallowed -- an unreadable date must not take down a restore.
    """
    try:
        note = staleness_warning(now=now)
    except Exception:  # noqa: BLE001 - a side note must never break the real work
        return
    if note:
        print(f"⚠ {note}", file=stream if stream is not None else sys.stderr)


#: Name of the file once everything is bundled together. **What is combined is transport,
#: not storage** -- once the client has it, it still lands as five separate files, each
#: passing its own structure check.
BUNDLE_NAME = "renest-rules.signed.json"


def install_bundle(body: dict, *, keys: dict[str, bytes] | None = None) -> list[dict]:
    """Install the bundled rules: **check the signature once, then land five files
    separately**.

    **Atomicity**: if any one of them fails the structure check, **none of them lands**.
    A half-updated view of the world (three new, two old) is worse than a fully old one --
    the old one is at least self-consistent.
    """
    keys = keys if keys is not None else trusted_keys()
    content = body.get("content", "")
    problem = _verify_sig(content.encode("utf-8"), body.get("sig", ""), body.get("key_id", ""), keys)
    if problem is not None:
        return [{"name": BUNDLE_NAME, "ok": False, "detail": problem}]
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return [{"name": BUNDLE_NAME, "ok": False, "detail": "the bundle is not valid JSON"}]

    files = payload.get("files")
    if not isinstance(files, dict):
        return [{"name": BUNDLE_NAME, "ok": False, "detail": "the bundle has no files section"}]

    # **Validate all of them first; one failure keeps the whole bundle out** -- never
    # install half of it
    for name in RULE_NAMES:
        data = files.get(name)
        if data is None:
            return [{"name": BUNDLE_NAME, "ok": False, "detail": f"the bundle is missing {name}"}]
        why = _rules._validate(name, data)
        if why is not None:
            return [{"name": BUNDLE_NAME, "ok": False,
                     "detail": f"{name} failed the structure check: {why}"}]

    # The anti-downgrade check applies to the bundle as a whole: not newer, not installed
    stale = _older_than_local(RULE_NAMES[0], payload)
    if stale == SAME_AS_LOCAL:
        return [{"name": BUNDLE_NAME, "ok": True,
                 "detail": f"already up to date (issued {issued_at(payload)})"}]
    if stale is not None:
        return [{"name": BUNDLE_NAME, "ok": False, "detail": stale}]

    dest = _install_dir()
    dest.mkdir(parents=True, exist_ok=True)
    out = []
    for name in RULE_NAMES:
        one = dict(files[name])
        one.setdefault("issued_at", payload.get("issued_at"))
        tmp = dest / f".{name}.tmp"
        tmp.write_text(json.dumps(one, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, dest / name)
        out.append({"name": name, "ok": True, "detail": "updated"})
    _rules.clear_cache()
    return out


def _fetch_bundle() -> dict | None:
    """Fetch the bundled rules. **Every place is tried**: the two CDN hosts and the
    public repository.

    All of them down returns ``None`` -- the baseline shipped inside the install is used
    then, and it **never degrades into skipping the signature check**.
    """
    mirror = os.environ.get("RENEST_RULES_MIRROR", "").rstrip("/")
    # **Tried in this order**, all static hosting rather than our own API, which absorbs
    # being hammered with anonymous pulls. All of them are verified against **the same
    # key**, so an extra location only adds another way out and lowers nothing.
    # Our own API used to sit at the end as a cold standby. It never once served this
    # file (checked live 2026-08-14: 404), because publishing writes to the CDN and the
    # public repository and has not touched the server since. A fallback nobody has
    # exercised is not safety, it is the look of safety, so it is gone.
    candidates = [
        f"{mirror}/{BUNDLE_NAME}" if mirror else None,   # set by env var (emergency/own)
        f"{NEXT_CDN_ORIGIN}/{BUNDLE_NAME}",              # main: CDN (fast, absorbs abuse)
        f"{CDN_ORIGIN}/{BUNDLE_NAME}",                   # the host being retired, now the fallback
        f"{_GITHUB_ORIGIN_DEFAULT}/{BUNDLE_NAME}",       # backup: raw file in public repo
    ]
    for url in [c for c in candidates if c]:
        try:
            r = httpx.get(url, timeout=20)
            r.raise_for_status()
            return r.json()
        except Exception:  # noqa: BLE001 - one source down, try the next one
            continue
    return None


def update_all(fetch=None) -> list[dict]:
    """Fetch the bundle -> check the signature -> land five files.

    Returns one result per file, [{name, ok, detail}].

    **There is exactly one path: the single bundle.** A per-file fallback would hide
    problems -- it would look like the update succeeded while delivering neither the
    atomicity nor the single signature check.

    ``fetch`` is the seam for tests: when given, it is used to fetch the bundle (it takes
    no arguments).
    """
    keys = trusted_keys()
    if not keys:
        return [{"name": "-", "ok": False,
                 "detail": "The trusted key ring is empty (no public key baked into "
                           "rules-signing-keys.json), so cloud rules updates are not "
                           "switched on. You are running the rules built into the "
                           "install, which work fine."}]
    body = fetch() if fetch is not None else _fetch_bundle()
    if body is None:
        return [{"name": BUNDLE_NAME, "ok": False,
                 "detail": "couldn't reach any of the places that serve the rules — the ones "
                           "built into this install still apply, so nothing is broken. "
                           "Try again when you have a connection."}]
    return install_bundle(body, keys=keys)


def in_effect() -> dict:
    """Which copy of the rules this machine will use from now on, and how old it is.

    ``{"source": "downloaded"|"built-in"|"mixed", "issued": "YYYY-MM-DD", "version": …}``.
    A downloaded set is dated by the day it was issued; the built-in set has no such day,
    so what identifies it is the version it shipped with. "mixed" means the five files
    disagree, which is worth showing rather than hiding behind whichever was read first.
    """
    from . import __version__

    sources = {_rules.active_copy(name) for name in RULE_NAMES}
    source = sources.pop() if len(sources) == 1 else "mixed"
    stamps = [s for s in (_local_issued_at(n) for n in RULE_NAMES) if s]
    return {
        "source": source,
        "issued": min(stamps)[:10] if source == "downloaded" and stamps else "",
        "version": __version__,
    }


def _local_issued_at(name: str) -> str:
    try:
        return issued_at(json.loads((_install_dir() / name).read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return ""


def in_effect_line(state: dict) -> str:
    """The one line printed after a refresh: **is what I just ran now in use?**
    Without it the only way to tell was to open the file in python.
    """
    if state["source"] == "downloaded":
        when = f"issued {state['issued']}" if state["issued"] else "with no date on it"
        return f"Now in use: the compatibility facts downloaded from us, {when}."
    if state["source"] == "built-in":
        return (
            f"Now in use: the compatibility facts built into this install "
            f"(renest {state['version']}) — nothing downloaded has replaced them."
        )
    # A mix is a normal state, not a fault: some files came down from us, and for the
    # rest the copy inside this install is the newer one, so that one wins. Saying
    # "run it again" here would send people chasing something that is already right.
    return (
        "Now in use: a mix — some facts came from us, and for the rest the copy built "
        "into this install is newer, so that one is used. Nothing is broken."
    )


# ---------------------------------------------------------------- CLI ----
def add_arguments(parser) -> None:
    """No options: the rules come from fixed public addresses, not from a service
    address anyone points at."""


def run_from_args(args, emitter: EventEmitter) -> int:
    results = update_all()
    ok = all(r["ok"] for r in results)
    _rules.clear_cache()  # read what has just landed, not what was cached before it
    try:
        state = in_effect()
    except Exception:  # noqa: BLE001 - the refresh result matters more than this line
        state = None
    if args.json:
        print(json.dumps({"ok": ok, "results": results, "in_effect": state},
                         ensure_ascii=False))
    else:
        for r in results:
            mark = "✓" if r["ok"] else "✗"
            print(f"{mark} {r['name']}: {r['detail']}", file=sys.stderr)
        if state is not None:
            print(in_effect_line(state), file=sys.stderr)
    return int(ExitCode.OK) if ok else 1


# --------------------------------------------------------------------------
# Keeping the rules fresh: ask once on the first run
# --------------------------------------------------------------------------
def should_ask_refresh(config, *, stdin, stderr, json_mode: bool, command: str, env=None) -> bool:
    """Whether to ask at all. **The default is not to ask**, and every veto has a name --
    the same rules as the anonymous-data prompt; no second scheme is invented.

    Asking once is the design: the question itself is the consent, so going online stays
    the user's choice, and one answer keeps working from then on.
    """
    import os as _os

    from .telemetry import _is_interactive, is_pod_environment

    env = _os.environ if env is None else env
    if json_mode or command in {"serve", "update-rules"}:
        return False
    if getattr(config, "rules_refresh_asked", False):
        return False
    if "RENEST_RULES_REFRESH" in env:  # an env var is an answer already given
        return False
    if env.get("CI"):
        return False
    if is_pod_environment(env):
        # Never ask on a pod: the user is waiting for a restore on a machine billed by the
        # hour, and a prompt interrupts them; besides, that machine is destroyed after use,
        # so a stored answer vanishes with it and every new machine would ask again.
        return False
    return _is_interactive(stdin, stderr)


def refresh_disclosure() -> str:
    """Say the whole thing before asking -- **short enough to read right there**, never a
    'details on our website' link.
    """
    return (
        "\nWe keep a small set of compatibility facts on your machine — things like\n"
        "'CUDA 12.4 needs driver 550.54 or newer', which package sources are known-good,\n"
        "and which GPUs we have actually tested. They go out of date as the world moves on,\n"
        "and out-of-date facts are how a perfectly good machine gets turned away.\n"
        "\n"
        "Refreshing them downloads one small signed file from us. Nothing about you or your\n"
        "files is sent — it is a plain download, and the file is rejected unless it is signed\n"
        "with a key that shipped inside this program.\n"
    )


def _patched_rules_toml(original: str | None, *, enabled: bool) -> str:
    """Touch only the two boolean keys inside ``[rules]``, and nothing else at all.

    Patching TOML by hand is usually a bad idea; it is controllable here because **the
    blast radius is pinned down to two booleans**: either the ``[rules]`` section does not
    exist (then it is appended at the end), or those two lines are replaced in place.
    The same approach as the anonymous-data prompt -- no second scheme is invented.
    """
    block = f"[rules]\nrefresh = {str(enabled).lower()}\nrefresh_asked = true\n"
    if not original:
        return block
    if "[rules]" not in original:
        sep = "" if original.endswith("\n") else "\n"
        return f"{original}{sep}\n{block}"
    out, in_section, wrote = [], False, False
    for line in original.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            if in_section and not wrote:
                out.append(f"refresh = {str(enabled).lower()}")
                out.append("refresh_asked = true")
                wrote = True
            in_section = stripped == "[rules]"
        if in_section and stripped.split("=")[0].strip() in {"refresh", "refresh_asked"}:
            continue  # drop the old values; the new ones are written below
        out.append(line)
    if in_section and not wrote:
        out.append(f"refresh = {str(enabled).lower()}")
        out.append("refresh_asked = true")
    return "\n".join(out) + "\n"


def record_refresh_answer(enabled: bool, *, path=None):
    """Write the answer into the user config file. **If the write goes wrong, put the
    original back and give up** -- returning ``None``.

    Why so timid: that file may be holding the user's own bucket key, and mangling it for
    the sake of an "auto-refresh?" switch would gamble real work on a side feature.
    """
    import os as _os

    from .config import user_config_path

    target = Path(path) if path else user_config_path()
    original: str | None = None
    try:
        original = target.read_text(encoding="utf-8") if target.exists() else None
        patched = _patched_rules_toml(original, enabled=enabled)
        target.parent.mkdir(parents=True, exist_ok=True)
        if original is None:
            # created 0600 from the start -- this file will hold a bucket key later, so
            # never leave a window at the default permissions
            fd = _os.open(target, _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o600)
            with _os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(patched)
        else:
            target.write_text(patched, encoding="utf-8")
        return target
    except OSError:
        try:
            if original is None:
                target.unlink(missing_ok=True)
            else:
                target.write_text(original, encoding="utf-8")
        except OSError:
            pass
        return None


def ask_refresh_once(config, *, stdin, stderr, json_mode: bool, command: str,
                     config_path=None, env=None) -> bool | None:
    """Ask once and record the answer. Returns the answer; ``None`` when nothing was asked.

    **The default is no**: a bare Enter means off. Someone hitting Enter in a hurry has not
    expressed consent -- reading Enter as yes would be stealing (the same rules as the
    anonymous-data prompt).
    """
    if not should_ask_refresh(
        config, stdin=stdin, stderr=stderr, json_mode=json_mode, command=command, env=env
    ):
        return None
    print(refresh_disclosure(), file=stderr)
    try:
        answer = input("Keep these compatibility facts up to date automatically? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        # Interrupted means unanswered. **Nothing is written to disk**, and it asks again
        # next time -- recording an interruption as a refusal would take away the only way
        # anyone ever turns it on.
        print("", file=stderr)
        return None
    enabled = answer.strip().lower() in {"y", "yes"}
    record_refresh_answer(enabled, path=config_path)
    print(
        "Thanks — we'll keep them current. You can turn it off in your config file."
        if enabled
        else "Left off. Run `renest update-rules` yourself whenever you want them refreshed.",
        file=stderr,
    )
    return enabled
