"""Configuration and credential resolution.

:class:`Config` (non-secret knobs) and :class:`Credentials` are separate types so
the second cannot leak into the first — :meth:`Config.to_toml_dict` cannot emit a
secret by construction. Config precedence, low to high: built-in defaults <
system file < user file < ``RENEST_*`` env < CLI overrides; ``--config PATH``
replaces the *user* layer.

Credential rule: the server never stores a user's cloud key, an execution machine
only ever holds a scope-limited signed grant, the desktop app uses the OS
keychain. This CLI may keep the user's own bucket key in a 0600 config file under
``[storage]`` — we refuse looser permissions, warn when the file sits in a git
repo or a cloud-synced folder, and tell the user plainly that it is plain text.
Any other credential-shaped key still fails loading with exit code 3.
"""

from __future__ import annotations

import dataclasses

import json
import os
import re
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import httpx
import platformdirs

from . import s3sig as _s3sig
from .errors import ExitCode

__all__ = [
    "APP_NAME",
    "ENV_PREFIX",
    "JSON_SOURCE_MAX_BYTES",
    "JSON_SOURCE_TIMEOUT",
    "STORAGE_SECRET_MAX_MODE",
    "TOKEN_ENV",
    "BucketKey",
    "Config",
    "ConfigError",
    "CredentialSource",
    "Credentials",
    "Grant",
    "SourceError",
    "SourceErrorKind",
    "StorageConfigFile",
    "assert_no_secret_keys",
    "assert_storage_secret_permissions",
    "bucket_key_from_config",
    "find_storage_config",
    "is_pod_environment",
    "load_config",
    "load_grant",
    "parse_iso8601",
    "read_json_source",
    "resolve_credentials",
    "resolve_token",
    "storage_config_has_secret",
    "storage_secret_exposure_warnings",
    "system_config_path",
    "user_config_path",
]

#: platformdirs appname. Everything the tool needs at runtime lives under the
#: tool's own name: tokens and config land in ~/.config/renest (Linux) or
#: %APPDATA%\renest (Windows), which keeps this cross-platform.
APP_NAME = "renest"

#: Environment-variable prefix for every config key and credential.
ENV_PREFIX = "RENEST_"


# --------------------------------------------------------------------------
# Config error (pre-gate exit code 3; not a staged NestFailure)
# --------------------------------------------------------------------------
class ConfigError(Exception):
    """Config / credential problem — maps to exit code 3.

    Distinct from :class:`~renest.errors.NestFailure`: 3 is a *pre-gate* code
    (died before entering any stage), so it is outside the staged error canon.
    """

    exit_code: int = int(ExitCode.CONFIG_OR_CREDENTIAL)

    def __init__(self, human: str, *, hint: str = "") -> None:
        self.human = human
        self.hint = hint
        super().__init__(f"{human}{('  → ' + hint) if hint else ''}")


# --------------------------------------------------------------------------
# One entry point for JSON input (dict / local path / URL): two parsers drift
# apart, so everything is funnelled through :func:`read_json_source`. Failures
# carry a :class:`SourceErrorKind` for callers to classify in their own words.
# --------------------------------------------------------------------------
#: Timeout for one URL fetch, in seconds. Applies only when this module creates
#: its own httpx client; a caller-supplied client keeps its own settings.
JSON_SOURCE_TIMEOUT = 30.0

#: Size ceiling on a URL fetch. Grants and manifests are small text, so anything
#: larger is refused; bytes are counted as they arrive, never swallowed whole.
JSON_SOURCE_MAX_BYTES = 32 * 1024 * 1024


class SourceErrorKind(StrEnum):
    """Why reading a JSON input failed. Callers translate this into their own
    wording for the user."""

    NETWORK = "network"  # cannot connect, or the connection dropped
    DENIED = "denied"  # HTTP 401/403 (an expired signed link is the usual cause)
    STATUS = "status"  # any other non-200
    READ = "read"  # the local file cannot be read
    TOO_LARGE = "too_large"  # over the size ceiling
    NOT_JSON = "not_json"  # not valid JSON


class SourceError(ConfigError):
    """Reading a JSON input failed. Still part of the exit-code-3 family, with
    the raw detail needed to classify the failure attached."""

    def __init__(
        self,
        kind: SourceErrorKind,
        human: str,
        *,
        hint: str = "",
        status: int | None = None,
        detail: str = "",
        exc_type: str = "",
    ) -> None:
        self.kind = kind
        self.status = status
        self.detail = detail
        self.exc_type = exc_type
        super().__init__(human, hint=hint)


def _fetch_text(
    url: str,
    *,
    client: httpx.Client | None,
    max_bytes: int,
    timeout: float,
) -> str:
    """Fetch a piece of JSON text with a size ceiling. Bytes are counted as they
    arrive and the connection is dropped the moment the ceiling is crossed."""
    own = client is None
    c = client if client is not None else httpx.Client(follow_redirects=True, timeout=timeout)
    try:
        try:
            with c.stream("GET", url) as r:
                if r.status_code in (401, 403):
                    raise SourceError(
                        SourceErrorKind.DENIED,
                        f"Input refused (HTTP {r.status_code}); the signed link has likely expired",
                        status=r.status_code,
                        hint="Get a fresh grant issued and try again.",
                    )
                if r.status_code != 200:
                    raise SourceError(
                        SourceErrorKind.STATUS,
                        f"Could not fetch input: HTTP {r.status_code}",
                        status=r.status_code,
                    )
                chunks: list[bytes] = []
                total = 0
                for chunk in r.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise SourceError(
                            SourceErrorKind.TOO_LARGE,
                            f"Input is over the {max_bytes}-byte limit; refusing to load it",
                            detail=url,
                        )
                    chunks.append(chunk)
        except httpx.HTTPError as exc:
            raise SourceError(
                SourceErrorKind.NETWORK,
                f"Could not fetch input: {type(exc).__name__}",
                detail=str(exc),
                exc_type=type(exc).__name__,
            ) from exc
    finally:
        if own:
            c.close()
    return b"".join(chunks).decode("utf-8", errors="replace")


def read_json_source(
    source: Any,
    *,
    client: httpx.Client | None = None,
    max_bytes: int = JSON_SOURCE_MAX_BYTES,
    timeout: float = JSON_SOURCE_TIMEOUT,
) -> Any:
    """dict / local path / URL to parsed JSON. All three shapes come through here.

    A URL is fetched over httpx with the size and timeout guard rails; every
    failure raises :class:`SourceError`, which carries its kind.
    """
    if isinstance(source, Mapping):
        return dict(source)
    s = str(source)
    if s.startswith(("http://", "https://")):
        text = _fetch_text(s, client=client, max_bytes=max_bytes, timeout=timeout)
    else:
        try:
            # A local file goes through the same ceiling, and the size is checked
            # *before* the read: read_text swallows the file whole, so judging
            # afterwards means the oversized file is already in memory.
            size = Path(s).stat().st_size
            if size > max_bytes:
                raise SourceError(
                    SourceErrorKind.TOO_LARGE,
                    f"That file is too big to be a nest manifest: {size} bytes "
                    f"(we stop at {max_bytes}).",
                )
            text = Path(s).read_text(encoding="utf-8")
        except OSError as exc:
            raise SourceError(
                SourceErrorKind.READ, f"Cannot read input: {s}", detail=str(exc)
            ) from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SourceError(
            SourceErrorKind.NOT_JSON, f"Input is not valid JSON: {exc}", detail=str(exc)
        ) from exc


# --------------------------------------------------------------------------
# Secret guard (the credential rule)
# --------------------------------------------------------------------------
#: A key in a config file is credential-shaped if its name matches this.
#: ``endpoint`` / ``token_file`` / ``target`` are deliberately unmatched, and so is
#: ``token``: ``auth.token`` is the designed home of the revocable personal access
#: token, not a bucket or cloud master key. Read by :func:`resolve_token` only.
_SECRET_KEY_RE = re.compile(
    r"secret|password|passphrase|private[_-]?key|credential"
    r"|access[_-]?key|secret[_-]?key|aws_access|aws_secret"
    r"|(^|[_-])(ak|sk)$",
    re.IGNORECASE,
)


def _is_secret_key(key: str) -> bool:
    return bool(_SECRET_KEY_RE.search(key))


#: The controlled opening in the credential rule: on this CLI the user's own
#: bucket key may live in a user config file whose permissions are 0600. This is
#: an **exhaustive allowlist**, not an opened-up prefix — every other
#: credential-shaped key is still refused, and adding a third path takes another
#: explicit decision.
#: **Execution machines such as rented pods are not covered**: there only a
#: temporary environment variable or a signed link is allowed.
_SECRET_ALLOWED_PATHS = frozenset({"storage.access_key", "storage.secret_key"})


def assert_no_secret_keys(data: Mapping[str, Any], *, source: str) -> None:
    """Reject a parsed config that carries a credential-shaped key.

    Walks nested tables. Raises :class:`ConfigError` (exit 3) on the first
    offending key, naming the correct place to put the secret instead.

    The only exception is :data:`_SECRET_ALLOWED_PATHS` (the user's own bucket
    key in the ``[storage]`` table). It matches on the **full dotted path** only,
    so ``[storage] aws_secret_access_key`` and ``[other] access_key`` are still
    refused.
    """

    def walk(node: Mapping[str, Any], path: str) -> None:
        for key, value in node.items():
            here = f"{path}.{key}" if path else key
            if _is_secret_key(str(key)) and here not in _SECRET_ALLOWED_PATHS:
                raise ConfigError(
                    f"Config file {source} contains a credential field “{here}”. "
                    "Keys never belong in a config file.",
                    hint=(
                        "The only exception is your own bucket key under [storage] "
                        "(access_key / secret_key). Everything else belongs in the "
                        "environment (RENEST_S3_ACCESS_KEY / RENEST_S3_SECRET_KEY) or in "
                        "a signed grant file (renest restore --grant …)."
                    ),
                )
            if isinstance(value, Mapping):
                walk(value, here)

    walk(data, "")


# --------------------------------------------------------------------------
# Config (non-secret knobs only)
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Config:
    """Effective, non-secret configuration.

    Every field maps to a TOML key and a ``RENEST_*`` env var. Secrets
    are *structurally* absent — there is no field to hold one, so serializing a
    Config can never emit a credential.
    """

    region: str = "auto"  # cn | us | auto
    telemetry_enabled: bool = False
    #: **The third state.** `enabled` is only true or false, which cannot tell
    #: "switched off" apart from "never asked". Without this bit, "ask once"
    #: turns into "ask on every start".
    telemetry_asked: bool = False
    telemetry_endpoint: str | None = None
    #: Keeping the built-in rules fresh: whether automatic refresh is on, and
    #: whether we have asked (a third state again, for the same reason as above).
    #: We ask rather than defaulting to on: refreshing automatically would reach
    #: the network without the user agreeing, and going online has to be explicit.
    rules_refresh_enabled: bool = False
    rules_refresh_asked: bool = False
    telemetry_install_id: str | None = None
    serve_port: int = 7799
    verify_ssim_threshold: float = 0.98
    pack_dir: str | None = None
    pack_exclude: tuple[str, ...] = ()

    def to_toml_dict(self) -> dict[str, Any]:
        """Nested dict mirroring the TOML layout (round-trippable, secret-free)."""
        return {
            "region": self.region,
            "telemetry": {
                "enabled": self.telemetry_enabled,
                "asked": self.telemetry_asked,
                "endpoint": self.telemetry_endpoint,
                "install_id": self.telemetry_install_id,
            },
            "rules": {
                "refresh": self.rules_refresh_enabled,
                "refresh_asked": self.rules_refresh_asked,
            },
            "serve": {"port": self.serve_port},
            "verify": {"ssim_threshold": self.verify_ssim_threshold},
            "pack": {"dir": self.pack_dir, "exclude": list(self.pack_exclude)},
        }


#: TOML path (as a dotted key) -> Config field name. Drives file extraction.
_TOML_TO_FIELD: dict[str, str] = {
    "region": "region",
    "telemetry.enabled": "telemetry_enabled",
    "telemetry.asked": "telemetry_asked",
    "telemetry.endpoint": "telemetry_endpoint",
    "telemetry.install_id": "telemetry_install_id",
    "rules.refresh": "rules_refresh_enabled",
    "rules.refresh_asked": "rules_refresh_asked",
    "serve.port": "serve_port",
    "verify.ssim_threshold": "verify_ssim_threshold",
    "pack.dir": "pack_dir",
    "pack.exclude": "pack_exclude",
}

#: RENEST_* env var -> Config field name (prefix RENEST_, e.g. RENEST_TELEMETRY).
_ENV_TO_FIELD: dict[str, str] = {
    "RENEST_REGION": "region",
    "RENEST_TELEMETRY": "telemetry_enabled",
    "RENEST_TELEMETRY_ENDPOINT": "telemetry_endpoint",
    "RENEST_TELEMETRY_INSTALL_ID": "telemetry_install_id",
    "RENEST_SERVE_PORT": "serve_port",
    "RENEST_VERIFY_SSIM_THRESHOLD": "verify_ssim_threshold",
    "RENEST_PACK_DIR": "pack_dir",
    "RENEST_PACK_EXCLUDE": "pack_exclude",  # comma-separated
}

_FIELD_TYPES = {f.name: f.type for f in fields(Config)}
_BOOL_TRUE = {"1", "true", "yes", "on"}
_BOOL_FALSE = {"0", "false", "no", "off"}


#: Field name to the **name** of the type it declares, read from Config's own
#: annotations and never hand-copied: a hand-copied table drifts the moment a
#: field is added, and once did — two new booleans arrived as the string 'True'.
#: Deferred annotation evaluation makes ``f.type`` a string, so compare it as a
#: string; ``is bool`` would never hold.
_FIELD_TYPES: dict[str, str] = {
    f.name: str(f.type) for f in dataclasses.fields(Config)
}


def _coerce(field_name: str, value: Any) -> Any:
    """Coerce a raw (env string / TOML scalar) value to the field's type."""
    if field_name == "pack_exclude":
        if isinstance(value, str):
            return tuple(p for p in (s.strip() for s in value.split(",")) if p)
        return tuple(value)
    # Decide by the type the field declares, never by a hard-coded list of field
    # names: the list was missed when new boolean fields were added, and their
    # values reached the program as the string 'True'.
    if _FIELD_TYPES.get(field_name) == "bool":
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in _BOOL_TRUE:
            return True
        if text in _BOOL_FALSE:
            return False
        raise ConfigError(f"Config option {field_name} takes true or false, got {value!r}.")
    if field_name == "serve_port":
        return int(value)
    if field_name == "verify_ssim_threshold":
        return float(value)
    # str | None fields
    return None if value is None else str(value)


def _get_toml_path(data: Mapping[str, Any], dotted: str) -> Any:
    node: Any = data
    for part in dotted.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return _MISSING
        node = node[part]
    return node


_MISSING = object()


def _overrides_from_toml(data: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for dotted, field_name in _TOML_TO_FIELD.items():
        value = _get_toml_path(data, dotted)
        if value is not _MISSING:
            out[field_name] = _coerce(field_name, value)
    return out


def _overrides_from_env(env: Mapping[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for env_key, field_name in _ENV_TO_FIELD.items():
        if env_key in env:
            out[field_name] = _coerce(field_name, env[env_key])
    return out


def _load_toml_file(path: Path) -> dict[str, Any]:
    """Parse one config file and reject any credential-shaped key."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return {}
    except OSError as exc:  # pragma: no cover - unreadable file
        raise ConfigError(f"Cannot read config file {path}: {exc}") from exc
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"Config file {path} is not valid TOML (UTF-8): {exc}") from exc
    assert_no_secret_keys(data, source=str(path))
    return data


# --------------------------------------------------------------------------
# Directory semantics (cross-platform, via platformdirs)
# --------------------------------------------------------------------------
def user_config_path() -> Path:
    """User config file: ~/.config/renest/config.toml (Linux) / %APPDATA%\\renest (Win)."""
    return Path(platformdirs.user_config_dir(APP_NAME)) / "config.toml"


def system_config_path() -> Path:
    """System config file. POSIX machines use /etc/renest/config.toml;
    Windows falls back to platformdirs site config."""
    if os.name == "nt":  # pragma: no cover - exercised on Windows CI
        return Path(platformdirs.site_config_dir(APP_NAME)) / "config.toml"
    return Path("/etc/renest/config.toml")


def load_config(
    *,
    cli_overrides: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
    config_path: str | os.PathLike[str] | None = None,
    user_config: str | os.PathLike[str] | None = None,
    system_config: str | os.PathLike[str] | None = None,
) -> Config:
    """Resolve the effective config with four-layer precedence.

    Low → high: built-in defaults < system file < user file < ``RENEST_*`` env <
    ``cli_overrides``. ``config_path`` (the ``--config`` flag) *replaces* the
    user-file layer; the system layer still applies.

    ``user_config`` / ``system_config`` exist for tests; production defaults to
    :func:`user_config_path` / :func:`system_config_path`.
    """
    env = os.environ if env is None else env

    system_file = Path(system_config) if system_config is not None else system_config_path()
    if config_path is not None:
        user_file: Path = Path(config_path)
    elif user_config is not None:
        user_file = Path(user_config)
    else:
        user_file = user_config_path()

    merged: dict[str, Any] = {}
    merged.update(_overrides_from_toml(_load_toml_file(system_file)))
    merged.update(_overrides_from_toml(_load_toml_file(user_file)))
    merged.update(_overrides_from_env(env))
    if cli_overrides:
        for key, value in cli_overrides.items():
            if value is None:
                continue
            if key not in _FIELD_TYPES:
                raise ConfigError(f"Unknown config option: {key}")
            merged[key] = _coerce(key, value)

    return replace(Config(), **merged)


# --------------------------------------------------------------------------
# Credentials — resolved from env / grant file ONLY, never from config
# --------------------------------------------------------------------------
class CredentialSource(StrEnum):
    """Where the effective credential came from."""

    GRANT = "grant"  # presigned restore manifest; no long-lived secret on box
    BUCKET_KEY = "bucket_key"  # S3 AK/SK, env-only
    NONE = "none"  # nothing available (e.g. --dry-run / lint)


@dataclass(frozen=True)
class Grant:
    """Parsed presigned restore-grant.

    Carries no long-lived secret: the URLs are time-limited signatures and the
    file itself declares its own ``expires_at``. Safe to sit on disk.
    """

    grant_version: str
    grant_id: str | None
    nest_id: str | None
    issued_at: str | None
    expires_at: str | None
    manifest_url: str | None
    manifest_sha256: str | None
    blobmap: dict[str, list[str]]
    meta4: dict[str, str]
    #: Who handed this nest to you (a display name); None means you packed it
    #: yourself. Stated by the issuing server, never by the nest itself — the thing
    #: being checked does not supply the rules for checking it.
    handed_off_from: str | None = None
    #: True = whoever handed you this nest was passing it on rather than packing
    #: it. Blocks laundering through an unwitting middle person whose name you
    #: trust.
    handed_off_relayed: bool | None = None
    #: Days of free-tier retention left, as calculated by the issuer; None means
    #: this has nothing to do with the account. Used for a notice only and
    #: **changes no restore behaviour** — the escape hatch informs, never blocks.
    retention_days_left: int | None = None
    #: Whether signing in restarts that countdown. None = the grant did not say
    #: (older servers), and then we say nothing about renewal rather than guess.
    retention_renews_on_sign_in: bool | None = None
    path: Path | None = None

    def is_expired(self, *, now: datetime | None = None) -> bool:
        """True if ``expires_at`` is in the past. Unparseable/missing → True
        (fail safe: an expiry we cannot read is treated as expired)."""
        if not self.expires_at:
            return True
        parsed = parse_iso8601(self.expires_at)
        if parsed is None:
            return True
        now = now or datetime.now(UTC)
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        return parsed <= now


@dataclass(frozen=True)
class BucketKey:
    """Credentials for an S3-compatible bucket, plus the dialect values needed to
    address it.

    Normally resolved from the environment; on this CLI it may also sit in the
    ``[storage]`` table of a 0600 config file (the single opening in the
    credential rule, see :data:`_SECRET_ALLOWED_PATHS`).

    ``provider`` / ``region`` / ``addressing`` are the **entire** set of dialect
    differences between providers and produce no code branches; ``provider`` only
    derives defaults and words error messages.
    """

    access_key: str
    secret_key: str
    endpoint: str | None = None
    bucket: str | None = None
    #: The region used when signing. When absent it is derived from the provider
    #: (R2 uses the literal ``auto``; AWS and B2 are read out of the endpoint).
    region: str | None = None
    #: ``r2`` | ``aws`` | ``b2`` | ``other``; defaults to ``other``.
    provider: str | None = None
    #: ``auto`` | ``path`` | ``virtual``; defaults per provider.
    addressing: str | None = None

    def effective_region(self) -> str | None:
        """An explicit value wins, otherwise derive it from provider/endpoint.
        None means it could not be derived, and the caller refuses up front."""
        return self.region or _s3sig.infer_region(self.endpoint, self.provider)

    def effective_addressing(self) -> str:
        return _s3sig.resolve_addressing(self.provider, self.addressing)

    def __repr__(self) -> str:  # never leak the secret in logs/tracebacks
        return (
            f"BucketKey(access_key={_redact(self.access_key)!r}, "
            f"secret_key='***', endpoint={self.endpoint!r}, bucket={self.bucket!r}, "
            f"region={self.region!r}, provider={self.provider!r}, "
            f"addressing={self.addressing!r})"
        )


@dataclass(frozen=True)
class Credentials:
    """Resolved credential + provenance. Config never contains this object."""

    source: CredentialSource
    grant: Grant | None = None
    bucket_key: BucketKey | None = None
    on_pod: bool = False
    #: human warning when a long-lived secret sits on an ephemeral machine
    warning: str | None = None
    #: ``"env"`` | ``"config_file"`` | None — where the bucket key came from.
    #: `doctor` says this out loud rather than glossing over the fact that it is a
    #: plain-text file; on a rented machine "from a file" earns a heavier warning
    #: than "from an environment variable", because a file outlives the shell.
    bucket_key_origin: str | None = None
    #: Path of the config file holding the key (set only when
    #: ``bucket_key_origin == "config_file"``).
    config_path: Path | None = None
    #: Exposure warnings for that file (inside a git repository, or inside a
    #: cloud-synced folder). See :func:`storage_secret_exposure_warnings`.
    exposure_warnings: tuple[str, ...] = ()


def _redact(value: str) -> str:
    if len(value) <= 4:
        return "***"
    return value[:2] + "***" + value[-2:]


def parse_iso8601(text: str) -> datetime | None:
    """ISO-8601 to a timezone-aware datetime (a bare time is read as UTC);
    returns None when it cannot be parsed.

    Every place that judges whether a grant has expired measures with this one
    ruler."""
    candidate = text.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def is_pod_environment(env: Mapping[str, str] | None = None, *, workspace: Path | None = None) -> bool:
    """Best-effort ephemeral-machine detection. Detection failure is
    treated as 'on a pod' by the caller (fail-safe warnings)."""
    env = os.environ if env is None else env
    if any(k in env for k in ("RUNPOD_POD_ID", "VAST_CONTAINERLABEL", "PAPERSPACE_METRIC_WORKLOAD_ID")):
        return True
    probe = workspace if workspace is not None else Path("/workspace")
    return probe.exists()


def load_grant(
    source: str | os.PathLike[str] | Mapping[str, Any],
    *,
    client: httpx.Client | None = None,
) -> Grant:
    """Load and shape a restore-grant. **One entry point** taking all three
    shapes: a dict, a local path, or a URL (a URL goes through the guard-railed
    fetch in :func:`read_json_source`). Raises :class:`ConfigError` (exit 3) on a
    missing file, bad JSON, or an unknown major grant_version."""
    p: Path | None = None
    where = ""
    if not isinstance(source, Mapping):
        where = f":{source}"
        if not str(source).startswith(("http://", "https://")):
            # .path records a local file source only; a URL or a dict has no
            # path on disk.
            p = Path(source)
    try:
        data = read_json_source(source, client=client)
    except SourceError as exc:
        if exc.kind is SourceErrorKind.READ and isinstance(
            exc.__cause__, FileNotFoundError
        ):
            raise ConfigError(f"No grant file here: {p}") from exc
        if exc.kind in (SourceErrorKind.READ, SourceErrorKind.NOT_JSON):
            raise ConfigError(
                f"Cannot read the grant, or it is not valid JSON{where} ({exc.detail})"
            ) from exc
        raise
    if not isinstance(data, Mapping):
        raise ConfigError(f"The grant must be a JSON object at the top level{where}")

    version = str(data.get("grant_version", ""))
    if not version:
        raise ConfigError(f"The grant is missing grant_version{where}")
    if version.split(".", 1)[0] != "1":
        raise ConfigError(
            f"Unknown grant version {version!r}; this tool reads 1.x{where}",
            hint="Update renest, or ask whoever sent it to issue a v1 grant.",
        )

    blobmap_raw = data.get("blobmap", {})
    blobmap = {
        str(h): [str(u) for u in (urls if isinstance(urls, Iterable) and not isinstance(urls, str) else [urls])]
        for h, urls in (blobmap_raw.items() if isinstance(blobmap_raw, Mapping) else [])
    }
    meta4_raw = data.get("meta4", {})
    meta4 = {str(k): str(v) for k, v in (meta4_raw.items() if isinstance(meta4_raw, Mapping) else [])}

    return Grant(
        grant_version=version,
        grant_id=_opt_str(data.get("grant_id")),
        nest_id=_opt_str(data.get("nest_id")),
        issued_at=_opt_str(data.get("issued_at")),
        expires_at=_opt_str(data.get("expires_at")),
        manifest_url=_opt_str(data.get("manifest_url")),
        manifest_sha256=_opt_str(data.get("manifest_sha256")),
        blobmap=blobmap,
        meta4=meta4,
        handed_off_from=_opt_str(data.get("handed_off_from")),
        handed_off_relayed=(
            None if data.get("handed_off_relayed") is None else bool(data["handed_off_relayed"])
        ),
        retention_days_left=_opt_int(data.get("retention_days_left")),
        retention_renews_on_sign_in=(data.get("retention_renews_on_sign_in")
                                     if isinstance(data.get("retention_renews_on_sign_in"), bool)
                                     else None),
        path=p,
    )


def _opt_int(value: Any) -> int | None:
    """An optional integer field: absent, None, or non-numeric all become None —
    an older issuer that never sends it must not be able to break a restore."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)


# --------------------------------------------------------------------------
# Keeping a bring-your-own-storage bucket key on the local machine. The three
# safeguards that make it acceptable live here: a permission check, a
# git-repository warning, and a cloud-sync warning.
# --------------------------------------------------------------------------
#: The loosest permissions allowed on a config file holding a bucket key (POSIX
#: only). 0600 = owner-only, so no other account on the machine can read the key.
STORAGE_SECRET_MAX_MODE = 0o600

#: Its own name so a test can inject it: monkeypatching ``os.name`` would also
#: change which implementation :class:`pathlib.Path` picks, turning the path under
#: test into a WindowsPath and invalidating the test itself.
_IS_WINDOWS = os.name == "nt"

#: Safeguard: path fragments of common cloud-sync and backup folders. A match
#: warns, because a plain-text key being synced away by iCloud / OneDrive /
#: Dropbox is the most realistic way this storage choice goes wrong. Path
#: fragments only; no private state of any sync application is read.
#: Matched against a lower-cased path, so entries must be ASCII. A client
#: installed in another language may create a folder this list misses.
_SYNC_DIR_MARKERS: tuple[str, ...] = (
    "library/mobile documents",  # the real path of iCloud Drive on macOS
    "icloud",
    "onedrive",
    "dropbox",
    "google drive",
    "googledrive",
    "nutstore",  # Nutstore, a cloud drive widely used in China
    "jianguoyun",  # Nutstore's own domain, which shows up in some paths
    # The same client installed in Chinese names its folder in Chinese, and that is
    # the spelling most of its users actually have on disk. Written as an escape so
    # this file stays ASCII; dropping it would quietly stop warning those users that
    # their key file is being synced to someone else's servers.
    "\u575a\u679c\u4e91",
    "yandexdisk",
    "pcloud",
    "sync.com",
)


def _storage_table(data: Mapping[str, Any]) -> Mapping[str, Any]:
    table = data.get("storage")
    return table if isinstance(table, Mapping) else {}


def storage_config_has_secret(data: Mapping[str, Any]) -> bool:
    """Whether this parsed config actually carries a bucket key, which decides
    whether the permission check has to run."""
    table = _storage_table(data)
    return bool(table.get("access_key")) or bool(table.get("secret_key"))


def assert_storage_secret_permissions(path: Path, data: Mapping[str, Any]) -> None:
    """Safeguard: a config file holding a key must be no looser than 0600, or the
    run **fails before it starts**.

    A refusal, not a warning: at 0644 any account on the machine can walk off with
    the key, and carrying on would accept that exposure on the user's behalf. The
    error carries a fix command they can paste straight in.

    Skipped on Windows, where access control is ACLs rather than st_mode and
    claiming to have checked would be misleading.
    """
    if _IS_WINDOWS or not storage_config_has_secret(data):
        return
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:  # pragma: no cover - the file was just read successfully
        return
    if mode & ~STORAGE_SECRET_MAX_MODE:
        raise ConfigError(
            f"Config file {path} holds your bucket key but is readable by others "
            f"(permissions {mode:04o}). Refusing to use it.",
            hint=f"Fix it with:  chmod 600 {path}",
        )


def storage_secret_exposure_warnings(path: Path) -> list[str]:
    """Two safeguards: could the key file be committed by git, or synced by a
    cloud drive?

    Both are exposure paths a user would never think of. Returns warnings in plain
    words (empty = both clean). This reads only the shape of the file system,
    never the contents of any file.
    """
    warnings: list[str] = []
    try:
        resolved = path.resolve()
    except OSError:  # pragma: no cover
        resolved = path

    # Inside a git repository: a single `git add -A` would push the key online.
    for parent in [resolved, *resolved.parents]:
        if (parent / ".git").exists():
            warnings.append(
                f"This file sits inside the git repository at {parent}. One "
                f"“git add -A” would commit your bucket key. Add this to .gitignore:\n"
                f"    {path.name}"
            )
            break

    # Inside a cloud-synced folder: the plain-text key gets uploaded somewhere.
    low = str(resolved).lower()
    for marker in _SYNC_DIR_MARKERS:
        if marker in low:
            warnings.append(
                f"This file looks like it sits in a folder that syncs to the cloud "
                f"(matched “{marker}”). Your bucket key would be uploaded in plain text. "
                f"Move it out, or keep the key in environment variables instead."
            )
            break
    return warnings


def bucket_key_from_config(data: Mapping[str, Any]) -> BucketKey | None:
    """``[storage]`` table to a :class:`BucketKey`. Returns None unless a
    complete key pair is present.

    Only a complete pair counts as "a bucket is configured": half-configured
    should read as "not configured" rather than sign with an empty key and fail
    afterwards.
    """
    table = _storage_table(data)
    access = table.get("access_key")
    secret = table.get("secret_key")
    if not access or not secret:
        return None

    def _s(key: str) -> str | None:
        value = table.get(key)
        return None if value is None else str(value)

    return BucketKey(
        access_key=str(access),
        secret_key=str(secret),
        endpoint=_s("endpoint"),
        bucket=_s("bucket"),
        region=_s("region"),
        provider=_s("provider"),
        addressing=_s("addressing"),
    )


@dataclass(frozen=True)
class StorageConfigFile:
    """A config file that holds a bucket key: where it is, the credential inside
    it, and its exposure warnings."""

    path: Path
    bucket_key: BucketKey
    warnings: tuple[str, ...] = ()


def find_storage_config(
    *,
    config_path: str | os.PathLike[str] | None = None,
    user_config: str | os.PathLike[str] | None = None,
    system_config: str | os.PathLike[str] | None = None,
) -> StorageConfigFile | None:
    """Find the config file that **holds a bucket key**, using the same layer
    order as load_config (the user layer beats the system layer).

    Permissions that do not pass raise :class:`ConfigError` on the spot, with no
    silent fallback. Exposure warnings ride on the returned object; the caller
    decides how to show them.
    """
    if config_path is not None:
        candidates = [Path(config_path)]
    else:
        candidates = [
            Path(user_config) if user_config is not None else user_config_path(),
            Path(system_config) if system_config is not None else system_config_path(),
        ]
    for path in candidates:
        data = _load_toml_file(path)
        if not storage_config_has_secret(data):
            continue
        assert_storage_secret_permissions(path, data)
        key = bucket_key_from_config(data)
        if key is None:
            # Only half a key pair: treated as not configured, deliberately —
            # permissions were already checked above.
            continue
        return StorageConfigFile(
            path=path, bucket_key=key, warnings=tuple(storage_secret_exposure_warnings(path))
        )
    return None


def resolve_credentials(
    *,
    env: Mapping[str, str] | None = None,
    grant_path: str | os.PathLike[str] | None = None,
    on_pod: bool | None = None,
    config_path: str | os.PathLike[str] | None = None,
    user_config: str | os.PathLike[str] | None = None,
    system_config: str | os.PathLike[str] | None = None,
) -> Credentials:
    """Decide which credential the run uses and where it came from.

    Precedence: an explicit grant (file path or ``RENEST_GRANT_FILE``) wins over a
    bucket key — pods should prefer the presigned, secret-free path. Bucket keys
    themselves come from the environment first, then from a ``[storage]`` section
    in the config file (same direction as :func:`load_config`: env beats file).
    Nothing present → :attr:`CredentialSource.NONE`.
    """
    env = os.environ if env is None else env
    pod = is_pod_environment(env) if on_pod is None else on_pod

    grant_ref = grant_path if grant_path is not None else env.get("RENEST_GRANT_FILE")
    if grant_ref:
        grant = load_grant(grant_ref)
        return Credentials(source=CredentialSource.GRANT, grant=grant, on_pod=pod)

    access = env.get("RENEST_S3_ACCESS_KEY")
    secret = env.get("RENEST_S3_SECRET_KEY")
    if access and secret:
        bucket = BucketKey(
            access_key=access,
            secret_key=secret,
            endpoint=env.get("RENEST_S3_ENDPOINT"),
            bucket=env.get("RENEST_S3_BUCKET"),
            region=env.get("RENEST_S3_REGION"),
            provider=env.get("RENEST_S3_PROVIDER"),
            addressing=env.get("RENEST_S3_ADDRESSING"),
        )
        warning = None
        if pod:
            warning = (
                "Your bucket key is sitting in the environment of a machine that can "
                "disappear. Destroy this pod when you are done. For restores, prefer a "
                "signed grant (--grant)."
            )
        return Credentials(
            source=CredentialSource.BUCKET_KEY,
            bucket_key=bucket,
            on_pod=pod,
            warning=warning,
            bucket_key_origin="env",
            config_path=None,
        )

    found = find_storage_config(
        config_path=config_path, user_config=user_config, system_config=system_config
    )
    if found is not None:
        warning = None
        if pod:
            # The file opening covers this CLI only. A key in a file on a rented
            # machine is worse than one in an environment variable: the variable
            # goes with the shell, the file stays in the image and the volume.
            warning = (
                "Your bucket key is in a file on a machine you rent, not on your own "
                "computer. A file outlives the shell that started this run — it stays in "
                "the image and the volume. Keep long-lived keys on your own machine and "
                "give this one a time-limited signed link instead (renest presign)."
            )
        return Credentials(
            source=CredentialSource.BUCKET_KEY,
            bucket_key=found.bucket_key,
            on_pod=pod,
            warning=warning,
            bucket_key_origin="config_file",
            config_path=found.path,
            exposure_warnings=found.warnings,
        )

    return Credentials(source=CredentialSource.NONE, on_pod=pod)


# --------------------------------------------------------------------------
# Personal access token (rnt_) — how an account authenticates to the service
# --------------------------------------------------------------------------
#: env var carrying the personal access token (distinct from RENEST_TOKEN_FILE,
#: which is the *local serve loopback* token path — frozen contract, unrelated).
TOKEN_ENV = "RENEST_TOKEN"


def resolve_token(
    *,
    env: Mapping[str, str] | None = None,
    config_path: str | os.PathLike[str] | None = None,
    user_config: str | os.PathLike[str] | None = None,
    system_config: str | os.PathLike[str] | None = None,
) -> str | None:
    """Resolve the SaaS personal access token (``rnt_…``), or None.

    Same layer order as :func:`load_config`: env beats the user file, which beats
    the system file. There is deliberately **no** ``--token`` flag — a credential
    on argv leaks into shell history and ``ps``; use ``--config PATH``.

    The token lives under ``[auth] token``. Callers must never log or echo it.
    """
    env = os.environ if env is None else env

    raw = env.get(TOKEN_ENV, "").strip()
    if raw:
        return raw

    system_file = Path(system_config) if system_config is not None else system_config_path()
    if config_path is not None:
        user_file: Path = Path(config_path)
    elif user_config is not None:
        user_file = Path(user_config)
    else:
        user_file = user_config_path()

    for candidate in (user_file, system_file):
        data = _load_toml_file(candidate)
        auth = data.get("auth")
        if isinstance(auth, Mapping):
            token = str(auth.get("token") or "").strip()
            if token:
                return token
    return None
