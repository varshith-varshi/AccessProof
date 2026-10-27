"""Microsoft Entra test-employee login for AccessProof's SharePoint RAG.

Alice/Bob tiles are OIDC login hints, not impersonation controls. The
authenticated tenant, immutable object ID and signed username are verified
before issuing an HttpOnly browser session. Guard independently validates
the JWT again for each protected question.
"""
from __future__ import annotations

import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from packages.auth.oidc import OidcError, OidcProviderClient

STATE_COOKIE = "ap_demo_entra_state"
SESSION_COOKIE = "ap_demo_entra_session"
_STATE_TTL, _SESSION_TTL, _MAX_SESSIONS = 300, 3600, 256
router = APIRouter(prefix="/v1/auth/entra", tags=["Demo Entra Employee Login"])
_lock = threading.RLock()


@dataclass(frozen=True)
class Pending:
    nonce: str
    verifier: str
    email: str
    expires_at: float


@dataclass(frozen=True)
class Session:
    id_token: str
    object_id: str
    email: str
    expires_at: float


_pending: dict[str, Pending] = {}
_sessions: dict[str, Session] = {}


def _config() -> tuple[str, str, str, str, dict[str, str], bool]:
    raw_tenant = os.getenv("ACCESSPROOF_DEMO_ENTRA_TENANT_ID", "").strip()
    client_id = os.getenv("ACCESSPROOF_DEMO_ENTRA_CLIENT_ID", "").strip()
    secret = os.getenv("ACCESSPROOF_DEMO_ENTRA_CLIENT_SECRET", "").strip()
    callback = os.getenv("ACCESSPROOF_DEMO_ENTRA_REDIRECT_URI", "").strip()
    try:
        tenant = str(UUID(raw_tenant))
        url = urlsplit(callback)
    except (ValueError, TypeError):
        raise HTTPException(503, "ENTRA_DEMO_LOGIN_NOT_CONFIGURED") from None
    if (tenant == "00000000-0000-0000-0000-000000000000"
            or not client_id or not secret
            or not url.hostname or url.username or url.password or url.query or url.fragment
            or url.path != "/v1/auth/entra/callback"
            or not (url.scheme == "https"
                    or (url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1"}))):
        raise HTTPException(503, "ENTRA_DEMO_LOGIN_NOT_CONFIGURED")
    domain = os.getenv("ACCESSPROOF_DEMO_ENTRA_DOMAIN", "").strip().lower()
    if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", domain):
        raise HTTPException(503, "ENTRA_DEMO_LOGIN_NOT_CONFIGURED")
    employees: dict[str, str] = {}
    for role in ("alice", "bob"):
        email = os.getenv(f"ACCESSPROOF_DEMO_ENTRA_{role.upper()}_EMAIL", "").strip().lower()
        if (not email.endswith("@" + domain) or not email or len(email) > 320
                or any(c in email for c in "<> \r\n")):
            raise HTTPException(503, "ENTRA_DEMO_LOGIN_NOT_CONFIGURED")
        employees[role] = email
    if employees["alice"] == employees["bob"]:
        raise HTTPException(503, "ENTRA_DEMO_LOGIN_NOT_CONFIGURED")
    return tenant, client_id, secret, callback, employees, url.scheme == "https"


def _provider(tenant: str) -> OidcProviderClient:
    return OidcProviderClient(f"https://login.microsoftonline.com/{tenant}/v2.0")


def _prune() -> None:
    now = time.time()
    for state, pending in list(_pending.items()):
        if pending.expires_at <= now:
            _pending.pop(state, None)
    for sid, session in list(_sessions.items()):
        if session.expires_at <= now:
            _sessions.pop(sid, None)


def session_token_from_request(request: Request) -> str | None:
    sid = request.cookies.get(SESSION_COOKIE, "")
    with _lock:
        _prune()
        session = _sessions.get(sid)
    return session.id_token if session else None


@router.get("/start")
def start(request: Request, as_user: str = "") -> RedirectResponse:
    tenant, client_id, _secret, callback, employees, secure = _config()
    if as_user not in employees:
        raise HTTPException(400, "UNKNOWN_DEMO_EMPLOYEE")
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier, challenge = OidcProviderClient.new_pkce()
    try:
        provider = _provider(tenant)
        try:
            discovery = provider.discovery()
        finally:
            provider.close()
        url = OidcProviderClient.authorization_url(
            discovery, client_id=client_id, redirect_uri=callback,
            state=state, nonce=nonce, code_challenge=challenge,
        )
    except (OidcError, ValueError) as exc:
        raise HTTPException(503, "ENTRA_OIDC_UNAVAILABLE") from exc
    with _lock:
        _prune()
        if len(_pending) >= _MAX_SESSIONS:
            raise HTTPException(503, "ENTRA_LOGIN_BUSY")
        _pending[state] = Pending(
            nonce=nonce, verifier=verifier, email=employees[as_user],
            expires_at=time.time() + _STATE_TTL,
        )
        _sessions.pop(request.cookies.get(SESSION_COOKIE, ""), None)
    response = RedirectResponse(
        url + "&" + urlencode({
            "login_hint": employees[as_user], "prompt": "select_account",
        }),
        status_code=302,
    )
    response.set_cookie(
        STATE_COOKIE, state, httponly=True, secure=secure,
        samesite="lax", max_age=_STATE_TTL, path="/v1/auth/entra",
    )
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/callback")
def callback(request: Request, state: str = "", code: str = "", error: str = "") -> RedirectResponse:
    tenant, client_id, secret, redirect_uri, _users, secure = _config()
    browser_state = request.cookies.get(STATE_COOKIE, "")
    if (error or not code or not state or not browser_state or len(state) > 256
            or not secrets.compare_digest(state, browser_state)):
        raise HTTPException(401, "ENTRA_LOGIN_STATE_INVALID")
    with _lock:
        _prune()
        flow = _pending.pop(state, None)
    if flow is None or flow.expires_at <= time.time():
        raise HTTPException(401, "ENTRA_LOGIN_STATE_EXPIRED_OR_USED")
    try:
        provider = _provider(tenant)
        try:
            discovery = provider.discovery()
            tokens = provider.exchange_code(
                discovery, client_id=client_id, client_secret=secret,
                code=code, redirect_uri=redirect_uri, code_verifier=flow.verifier,
            )
            id_token = tokens["id_token"]
            claims = provider.validate_id_token(
                discovery, id_token=id_token, client_id=client_id, nonce=flow.nonce,
            )
        finally:
            provider.close()
    except (OidcError, ValueError, KeyError, TypeError) as exc:
        raise HTTPException(401, "ENTRA_EMPLOYEE_TOKEN_REJECTED") from exc

    object_id = claims.get("oid")
    principal = claims.get("preferred_username") or claims.get("upn")
    expires = claims.get("exp")
    try:
        object_id = str(UUID(object_id))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(403, "ENTRA_EMPLOYEE_OBJECT_ID_REQUIRED") from None
    if (claims.get("tid") != tenant or not isinstance(principal, str)
            or principal.lower() != flow.email or not isinstance(expires, int)
            or expires <= time.time() or not isinstance(id_token, str)):
        raise HTTPException(403, "ENTRA_EMPLOYEE_IDENTITY_MISMATCH")
    with _lock:
        _prune()
        if len(_sessions) >= _MAX_SESSIONS:
            raise HTTPException(503, "ENTRA_LOGIN_BUSY")
        sid = secrets.token_urlsafe(32)
        lifetime = min(expires - time.time(), _SESSION_TTL)
        _sessions[sid] = Session(
            id_token=id_token, object_id=object_id, email=flow.email,
            expires_at=time.time() + lifetime,
        )
    response = RedirectResponse("/demo/entra", status_code=303)
    response.set_cookie(
        SESSION_COOKIE, sid, httponly=True, secure=secure, samesite="lax",
        max_age=max(1, int(lifetime)), path="/",
    )
    response.delete_cookie(STATE_COOKIE, path="/v1/auth/entra")
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/me")
def me(request: Request) -> JSONResponse:
    sid = request.cookies.get(SESSION_COOKIE, "")
    with _lock:
        _prune()
        session = _sessions.get(sid)
    if session is None:
        raise HTTPException(401, "ENTRA_EMPLOYEE_LOGIN_REQUIRED")
    return JSONResponse({
        "email": session.email,
        "object_id": session.object_id,
        "issuer": "microsoft-entra",
    }, headers={"Cache-Control": "no-store"})


@router.post("/logout")
def logout(request: Request) -> JSONResponse:
    with _lock:
        _sessions.pop(request.cookies.get(SESSION_COOKIE, ""), None)
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.headers["Cache-Control"] = "no-store"
    return response
