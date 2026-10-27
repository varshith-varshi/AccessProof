"""Optional Google employee sign-in for the controlled Google Drive RAG demo.

This is a single-process demo session store, NOT a production SSO/session system.
The RAG Guard independently verifies Google's ID token before each decision.
Never use this module to authenticate the AccessProof control plane.
"""
from __future__ import annotations

import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from packages.auth.oidc import OidcError, OidcProviderClient

GOOGLE_ISSUER = "https://accounts.google.com"
STATE_COOKIE = "ap_demo_google_state"
SESSION_COOKIE = "ap_demo_google_session"
_STATE_TTL = 300
_SESSION_TTL = 3600
_MAX_SESSIONS = 512

router = APIRouter(prefix="/v1/auth/google", tags=["Demo Google Employee Login"])
_lock = threading.RLock()


@dataclass(frozen=True)
class Pending:
    state: str
    nonce: str
    verifier: str
    expires_at: float


@dataclass(frozen=True)
class Session:
    id_token: str
    subject: str
    email: str
    expires_at: float


_pending: dict[str, Pending] = {}
_sessions: dict[str, Session] = {}


def _provider() -> OidcProviderClient:
    return OidcProviderClient(GOOGLE_ISSUER)


def _config() -> tuple[str, str, str, str, bool]:
    client_id = os.getenv("ACCESSPROOF_DEMO_GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.getenv("ACCESSPROOF_DEMO_GOOGLE_CLIENT_SECRET", "").strip()
    hosted_domain = os.getenv("ACCESSPROOF_DEMO_GOOGLE_HOSTED_DOMAIN", "").strip().lower()
    redirect_uri = os.getenv("ACCESSPROOF_DEMO_GOOGLE_REDIRECT_URI", "").strip()
    uri = urlsplit(redirect_uri)
    # A domain requirement prevents a personal Gmail account from pretending
    # to be a Google Workspace / Cloud Identity managed employee.
    if (not client_id or not client_secret or
            not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", hosted_domain) or
            not uri.hostname or uri.username or uri.password or uri.query or uri.fragment or
            uri.path != "/v1/auth/google/callback" or
            not (uri.scheme == "https" or (
                uri.scheme == "http" and uri.hostname in {"localhost", "127.0.0.1"}))):
        raise HTTPException(503, "GOOGLE_EMPLOYEE_LOGIN_NOT_CONFIGURED")
    return client_id, client_secret, hosted_domain, redirect_uri, uri.scheme == "https"


def _evict_expired() -> None:
    now = time.time()
    for key, item in list(_pending.items()):
        if item.expires_at <= now:
            _pending.pop(key, None)
    for key, item in list(_sessions.items()):
        if item.expires_at <= now:
            _sessions.pop(key, None)


def session_token_from_request(request: Request) -> str | None:
    sid = request.cookies.get(SESSION_COOKIE, "")
    if not sid:
        return None
    with _lock:
        _evict_expired()
        session = _sessions.get(sid)
        return session.id_token if session is not None else None


@router.get("/start")
def login_start() -> RedirectResponse:
    client_id, _secret, domain, redirect_uri, secure = _config()
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier, challenge = OidcProviderClient.new_pkce()
    try:
        provider = _provider()
        try:
            discovery = provider.discovery()
        finally:
            provider.close()
        url = OidcProviderClient.authorization_url(
            discovery, client_id=client_id, redirect_uri=redirect_uri,
            state=state, nonce=nonce, code_challenge=challenge,
        )
    except (OidcError, ValueError) as exc:
        raise HTTPException(503, "GOOGLE_OIDC_UNAVAILABLE") from exc
    with _lock:
        _evict_expired()
        if len(_pending) >= _MAX_SESSIONS:
            raise HTTPException(503, "GOOGLE_LOGIN_BUSY")
        _pending[state] = Pending(
            state=state, nonce=nonce, verifier=verifier,
            expires_at=time.time() + _STATE_TTL,
        )
    # hd is only a provider UI hint; the signed hd claim is checked on callback.
    from urllib.parse import urlencode
    response = RedirectResponse(url + "&" + urlencode({"hd": domain}), status_code=302)
    response.set_cookie(
        STATE_COOKIE, state, httponly=True, secure=secure, samesite="lax",
        max_age=_STATE_TTL, path="/v1/auth/google",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/callback")
def login_callback(
    request: Request, state: str = "", code: str = "", error: str = "",
) -> RedirectResponse:
    client_id, client_secret, domain, redirect_uri, secure = _config()
    browser_state = request.cookies.get(STATE_COOKIE, "")
    if (error or not code or not state or not browser_state or
            len(state) > 256 or not secrets.compare_digest(state, browser_state)):
        raise HTTPException(401, "GOOGLE_LOGIN_STATE_INVALID")
    with _lock:
        _evict_expired()
        flow = _pending.pop(state, None)
    if flow is None or flow.expires_at <= time.time():
        raise HTTPException(401, "GOOGLE_LOGIN_STATE_EXPIRED_OR_USED")

    try:
        provider = _provider()
        try:
            discovery = provider.discovery()
            tokens = provider.exchange_code(
                discovery, client_id=client_id, client_secret=client_secret,
                code=code, redirect_uri=redirect_uri, code_verifier=flow.verifier,
            )
            token = str(tokens["id_token"])
            claims = provider.validate_id_token(
                discovery, id_token=token, client_id=client_id, nonce=flow.nonce,
            )
        finally:
            provider.close()
    except (OidcError, KeyError, ValueError) as exc:
        raise HTTPException(401, "GOOGLE_EMPLOYEE_TOKEN_REJECTED") from exc

    email = claims.get("email")
    sub = claims.get("sub")
    exp = claims.get("exp")
    if (not isinstance(claims.get("hd"), str) or
            claims["hd"].lower() != domain or
            claims.get("email_verified") is not True or
            not isinstance(email, str) or
            not email.lower().endswith("@" + domain) or
            not isinstance(sub, str) or not sub or
            not isinstance(exp, int) or exp <= time.time()):
        raise HTTPException(403, "NOT_MANAGED_GOOGLE_EMPLOYEE")
    with _lock:
        _evict_expired()
        if len(_sessions) >= _MAX_SESSIONS:
            raise HTTPException(503, "GOOGLE_LOGIN_BUSY")
        sid = secrets.token_urlsafe(32)
        lifetime = min(float(exp) - time.time(), _SESSION_TTL)
        _sessions[sid] = Session(
            id_token=token, subject=sub, email=email.lower(),
            expires_at=time.time() + lifetime,
        )
    response = RedirectResponse("/demo", status_code=303)
    response.set_cookie(
        SESSION_COOKIE, sid, httponly=True, secure=secure, samesite="strict",
        max_age=max(1, int(lifetime)), path="/",
    )
    response.delete_cookie(STATE_COOKIE, path="/v1/auth/google")
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/me")
def current_employee(request: Request) -> JSONResponse:
    sid = request.cookies.get(SESSION_COOKIE, "")
    with _lock:
        _evict_expired()
        session = _sessions.get(sid)
    if session is None:
        raise HTTPException(401, "GOOGLE_EMPLOYEE_LOGIN_REQUIRED")
    return JSONResponse(
        {"email": session.email, "subject": session.subject, "issuer": GOOGLE_ISSUER},
        headers={"Cache-Control": "no-store"},
    )


@router.post("/logout")
def logout(request: Request) -> JSONResponse:
    sid = request.cookies.get(SESSION_COOKIE, "")
    with _lock:
        _sessions.pop(sid, None)
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.headers["Cache-Control"] = "no-store"
    return response
