"""Talking to the Renest service about signing a machine in and approving one upload.

[SECURITY-REVIEW] Two credentials pass through here and neither may be written down
anywhere but its one home:

* the **machine sign-in token** comes back from the device sign-in (``renest login``)
  and is stored by the caller as ``auth.token`` in the 0600 config file. It can only
  ask for an upload to be approved and read that request back;
* the **upload-once token** comes back once, after the person approved one upload in
  their own browser. It lives in the caller's memory for the length of that one
  upload and is revoked with :func:`finish_upload`;
* the **take-back-once token** (2026-10-19, the panel's "Take back") comes back once,
  after the person approved one take-back in their browser. It can list this
  account's nests and fetch the download links of **one** version, lives in the
  caller's memory, and is revoked with :func:`finish_takeback`.

Neither token ever goes into an exception message, a return value meant for display,
or a log line. Errors here carry an HTTP status and a plain sentence, nothing else.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field

import httpx

__all__ = [
    "ApprovalError",
    "DeviceLogin",
    "UploadApproval",
    "cancel_takeback_approval",
    "cancel_upload_approval",
    "finish_takeback",
    "finish_upload",
    "list_takeback_nests",
    "poll_device_login",
    "poll_takeback_approval",
    "poll_upload_approval",
    "request_takeback_approval",
    "request_upload_approval",
    "server_refusal",
    "start_device_login",
    "takeback_links",
]

#: What an approval id may look like before it is put into a request path.
_ID_SHAPE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_TIMEOUT = httpx.Timeout(connect=15.0, read=30.0, write=30.0, pool=15.0)


class ApprovalError(Exception):
    """A refusal or an unreachable service, as one sentence a person can act on.

    ``status`` is the HTTP status (0 when the service could not be reached at all).
    ``code`` is the service's own machine code for the refusal (``PLAN_CANNOT_PACK``,
    ``QUOTA_EXCEEDED``, ...) when it named one, and ``actions`` the ways forward it
    offered (``[{"label", "url"}]``, web pages only) -- both passed on to the panel.
    """

    def __init__(self, human: str, *, status: int = 0, code: str = "",
                 actions: list[dict] | None = None) -> None:
        super().__init__(human)
        self.human = human
        self.status = status
        self.code = code
        self.actions = list(actions or [])


@dataclass
class DeviceLogin:
    device_code: str = field(repr=False)
    user_code: str
    verify_url: str
    expires_in: int
    interval: float


@dataclass
class UploadApproval:
    approval_id: str
    user_code: str
    verify_url: str
    expires_in: int
    interval: float


def _api(origin: str) -> str:
    return origin.rstrip("/") + "/api/v1"


_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_CODE_SHAPE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
#: How many ways forward one refusal may carry, and how long each part may be.
_MAX_ACTIONS = 4
_MAX_LABEL = 80
_MAX_URL = 500


def _actions(raw: object) -> list[dict]:
    """The ways forward the service offered, kept only when each is a plain web page.

    A link is the one place a stray value could do something in the person's browser,
    so anything that is not ``http(s)://host/...`` (no user name or password in it) is
    dropped here rather than trusted further down.
    """
    out: list[dict] = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        if len(out) >= _MAX_ACTIONS:
            break
        if not isinstance(item, dict):
            continue
        label, url = item.get("label"), item.get("url")
        if not (isinstance(label, str) and isinstance(url, str)):
            continue
        label = _CTRL.sub("", label).strip()[:_MAX_LABEL]
        url = url.strip()
        if not label or len(url) > _MAX_URL or _CTRL.search(url):
            continue
        try:
            parts = urllib.parse.urlsplit(url)
        except ValueError:
            continue
        if parts.scheme not in ("https", "http") or not parts.hostname or "@" in parts.netloc:
            continue
        out.append({"label": label, "url": url})
    return out


def server_refusal(resp: httpx.Response) -> tuple[str, str, list[dict]]:
    """``(code, message, actions)`` from the service's error envelope.

    The envelope is ``{"error": {"code", "message", "actions"?}}``; ``actions`` is also
    read beside ``error`` at the top level. Anything missing comes back empty, so a
    caller can tell "the service named this refusal" (``code`` set) from a bare status.
    """
    try:
        body = resp.json()
    except ValueError:
        return "", "", []
    if not isinstance(body, dict):
        return "", "", []
    err = body.get("error")
    code = message = ""
    actions: list[dict] = []
    if isinstance(err, dict):
        raw_code, raw_message = err.get("code"), err.get("message")
        if isinstance(raw_code, str) and _CODE_SHAPE.match(raw_code):
            code = raw_code
        if isinstance(raw_message, str):
            message = _CTRL.sub(" ", raw_message).strip()[:600]
        actions = _actions(err.get("actions"))
    if not actions:
        actions = _actions(body.get("actions"))
    return code, message, actions


def _server_error(resp: httpx.Response) -> str:
    """The server's own short reason, without echoing anything we sent."""
    code, message, _actions_ = server_refusal(resp)
    if message or code:
        return message or code
    try:
        body = resp.json()
    except ValueError:
        return f"HTTP {resp.status_code}"
    if isinstance(body, dict):
        for key in ("error", "detail"):
            value = body.get(key)
            if isinstance(value, str) and value:
                return value[:300]
    return f"HTTP {resp.status_code}"


def _refused(resp: httpx.Response, prefix: str) -> ApprovalError:
    """The service said no. When it named the refusal, its own sentence goes to the
    person word for word, with its code and ways forward; otherwise ours, with its reason."""
    code, message, actions = server_refusal(resp)
    human = message if (code and message) else f"{prefix}: {_server_error(resp)}"
    return ApprovalError(human, status=resp.status_code, code=code, actions=actions)


def _call(client: httpx.Client, method: str, url: str, *, json: dict | None = None,
          token: str | None = None) -> httpx.Response:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        return client.request(method, url, json=json, headers=headers, timeout=_TIMEOUT)
    except httpx.HTTPError as exc:
        # The exception text can carry the address; it never carries headers, but
        # the class name is all a person needs here.
        raise ApprovalError(
            f"Cannot reach the Renest service ({type(exc).__name__}). Check this machine's "
            "network and try again."
        ) from None


def _interval(body: dict) -> float:
    try:
        return max(float(body.get("interval", 3)), 0.0)
    except (TypeError, ValueError):
        return 3.0


def _expires_in(body: dict) -> int:
    try:
        return max(int(body.get("expires_in", 600)), 0)
    except (TypeError, ValueError):
        return 600


# -- device sign-in -----------------------------------------------------------
def start_device_login(client: httpx.Client, origin: str, machine_label: str) -> DeviceLogin:
    resp = _call(client, "POST", f"{_api(origin)}/device-logins",
                 json={"machine_label": machine_label})
    if resp.status_code not in (200, 201):
        raise ApprovalError(f"The Renest service refused to start a sign-in: {_server_error(resp)}",
                            status=resp.status_code)
    body = resp.json()
    try:
        return DeviceLogin(
            device_code=str(body["device_code"]),
            user_code=str(body["user_code"]),
            verify_url=str(body["verify_url"]),
            expires_in=_expires_in(body),
            interval=_interval(body),
        )
    except (KeyError, TypeError):
        raise ApprovalError("The Renest service answered the sign-in request in a shape this "
                            "version does not understand.") from None


def poll_device_login(client: httpx.Client, origin: str, device_code: str) -> dict:
    """One poll. Returns the body: ``status`` plus, once, ``token`` and ``account_email``."""
    resp = _call(client, "POST", f"{_api(origin)}/device-logins/poll",
                 json={"device_code": device_code})
    if resp.status_code != 200:
        raise ApprovalError(f"The Renest service refused the sign-in check: {_server_error(resp)}",
                            status=resp.status_code)
    body = resp.json()
    return body if isinstance(body, dict) else {}


# -- one upload, approved in the browser ----------------------------------------
def request_upload_approval(client: httpx.Client, origin: str, signin_token: str, *,
                            nest_name: str, size_bytes: int, machine_label: str) -> UploadApproval:
    resp = _call(client, "POST", f"{_api(origin)}/upload-approvals", token=signin_token,
                 json={"nest_name": nest_name, "size_bytes": int(size_bytes),
                       "machine_label": machine_label})
    if resp.status_code == 401:
        raise ApprovalError(
            "This machine's Renest sign-in has expired or was revoked. In its terminal, run: "
            "renest login", status=401)
    if resp.status_code not in (200, 201):
        raise _refused(resp, "The Renest service refused to ask for approval")
    body = resp.json()
    try:
        approval_id = str(body["approval_id"])
        # It goes into the path of every later call, so it must be an id and nothing else.
        if not _ID_SHAPE.match(approval_id):
            raise TypeError
        return UploadApproval(
            approval_id=approval_id,
            user_code=str(body["user_code"]),
            verify_url=str(body["verify_url"]),
            expires_in=_expires_in(body),
            interval=_interval(body),
        )
    except (KeyError, TypeError):
        raise ApprovalError("The Renest service answered the approval request in a shape this "
                            "version does not understand.") from None


def poll_upload_approval(client: httpx.Client, origin: str, signin_token: str,
                         approval_id: str) -> dict:
    """One poll. Returns the body: ``status`` plus, once, ``upload_token``."""
    resp = _call(client, "GET", f"{_api(origin)}/upload-approvals/{approval_id}",
                 token=signin_token)
    if resp.status_code == 401:
        raise ApprovalError(
            "This machine's Renest sign-in has expired or was revoked. In its terminal, run: "
            "renest login", status=401)
    if resp.status_code != 200:
        raise _refused(resp, "The Renest service refused the approval check")
    body = resp.json()
    return body if isinstance(body, dict) else {}


def cancel_upload_approval(client: httpx.Client, origin: str, signin_token: str,
                           approval_id: str) -> bool:
    """Withdraw an approval request this machine no longer needs (cancelled, or the job
    failed before the upload started). The service revokes an upload-once token that
    was issued but not yet collected. Idempotent on the service side; never raises.
    """
    try:
        resp = _call(client, "POST", f"{_api(origin)}/upload-approvals/{approval_id}/cancel",
                     token=signin_token)
    except ApprovalError:
        return False
    return resp.status_code in (200, 204)


def finish_upload(client: httpx.Client, origin: str, upload_token: str, approval_id: str,
                  outcome: str) -> bool:
    """Tell the service this upload is over, which revokes the upload-once token.

    Returns whether the service acknowledged it. Never raises: the upload's own outcome
    is what the person needs to hear about, and the token dies at its hard cap anyway.
    """
    if outcome not in ("succeeded", "failed", "cancelled"):
        outcome = "failed"
    try:
        resp = _call(client, "POST", f"{_api(origin)}/upload-approvals/{approval_id}/finish",
                     token=upload_token, json={"outcome": outcome})
    except ApprovalError:
        return False
    return resp.status_code in (200, 204)


# -- one take-back, approved in the browser (the panel's "Take back", 2026-10-19) ---------
def request_takeback_approval(client: httpx.Client, origin: str, signin_token: str, *,
                              machine_label: str) -> UploadApproval:
    """Ask the service for permission to list this account's nests and take one back
    here. Same shape as an upload approval: a short code the person checks in their
    browser, and an id the machine polls."""
    resp = _call(client, "POST", f"{_api(origin)}/takeback-approvals", token=signin_token,
                 json={"machine_label": machine_label})
    if resp.status_code == 401:
        raise ApprovalError(
            "This machine's Renest sign-in has expired or was revoked. In its terminal, run: "
            "renest login", status=401)
    if resp.status_code not in (200, 201):
        raise _refused(resp, "The Renest service refused to ask for a take-back approval")
    body = resp.json()
    try:
        approval_id = str(body["approval_id"])
        if not _ID_SHAPE.match(approval_id):
            raise TypeError
        return UploadApproval(
            approval_id=approval_id,
            user_code=str(body["user_code"]),
            verify_url=str(body["verify_url"]),
            expires_in=_expires_in(body),
            interval=_interval(body),
        )
    except (KeyError, TypeError):
        raise ApprovalError("The Renest service answered the take-back request in a shape this "
                            "version does not understand.") from None


def poll_takeback_approval(client: httpx.Client, origin: str, signin_token: str,
                           approval_id: str) -> dict:
    """One poll. Returns the body: ``status`` plus, once, ``takeback_token``."""
    resp = _call(client, "GET", f"{_api(origin)}/takeback-approvals/{approval_id}",
                 token=signin_token)
    if resp.status_code == 401:
        raise ApprovalError(
            "This machine's Renest sign-in has expired or was revoked. In its terminal, run: "
            "renest login", status=401)
    if resp.status_code != 200:
        raise _refused(resp, "The Renest service refused the take-back approval check")
    body = resp.json()
    return body if isinstance(body, dict) else {}


def cancel_takeback_approval(client: httpx.Client, origin: str, signin_token: str,
                             approval_id: str) -> bool:
    """Withdraw a take-back request this machine no longer needs. Never raises."""
    try:
        resp = _call(client, "POST", f"{_api(origin)}/takeback-approvals/{approval_id}/cancel",
                     token=signin_token)
    except ApprovalError:
        return False
    return resp.status_code in (200, 204)


def finish_takeback(client: httpx.Client, origin: str, takeback_token: str, approval_id: str,
                    outcome: str) -> bool:
    """Tell the service this take-back is over, which revokes the take-back-once token.
    Never raises."""
    if outcome not in ("succeeded", "failed", "cancelled"):
        outcome = "failed"
    try:
        resp = _call(client, "POST", f"{_api(origin)}/takeback-approvals/{approval_id}/finish",
                     token=takeback_token, json={"outcome": outcome})
    except ApprovalError:
        return False
    return resp.status_code in (200, 204)


def list_takeback_nests(client: httpx.Client, origin: str, takeback_token: str) -> list[dict]:
    """This account's nests that can be taken back, as the service lists them."""
    resp = _call(client, "GET", f"{_api(origin)}/takeback/nests", token=takeback_token)
    if resp.status_code == 401:
        raise ApprovalError("This take-back approval is no longer valid. Press \"Take back\" "
                            "again to ask once more.", status=401)
    if resp.status_code != 200:
        raise _refused(resp, "The Renest service refused to list your nests")
    body = resp.json()
    return [row for row in body if isinstance(row, dict)] if isinstance(body, list) else []


def takeback_links(client: httpx.Client, origin: str, takeback_token: str,
                   nest_version_id: str) -> dict:
    """The short-lived download links for one version (the same payload a restore
    code redeems to). The service binds the approval to this one version."""
    if not _ID_SHAPE.match(nest_version_id or ""):
        raise ApprovalError("That nest version id is not one this version understands.")
    resp = _call(client, "POST",
                 f"{_api(origin)}/takeback/nest-versions/{nest_version_id}/links",
                 token=takeback_token)
    if resp.status_code == 401:
        raise ApprovalError("This take-back approval is no longer valid. Press \"Take back\" "
                            "again to ask once more.", status=401)
    if resp.status_code != 200:
        raise _refused(resp, "The Renest service refused to hand out the download links")
    body = resp.json()
    return body if isinstance(body, dict) else {}
