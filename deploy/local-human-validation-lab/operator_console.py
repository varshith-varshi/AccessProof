"""Loopback-only human validation console for REAL Microsoft Entra sessions.

Never stores employee passwords, browser tokens, access tokens, refresh tokens,
or impersonated credentials. The backend reads the existing 0600 Unix
sockets maintained by verified Microsoft login agents. Tokens are only used
in server-to-server requests to the AccessProof-protected RAG.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import stat
import time
from pathlib import Path
from typing import Literal

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

HOST = "127.0.0.1"
PORT = 28290
ORIGIN = f"http://{HOST}:{PORT}"
RAG = "http://127.0.0.1:28189"
IDENTITIES = Path.home() / ".ap-id"
ACTORS = {"alice": IDENTITIES / "alice.sock", "bob": IDENTITIES / "bob.sock"}
BOOTSTRAP_FILE = IDENTITIES / "validation-console-bootstrap"
COOKIE = "ap_human_validation_operator"
BOOTSTRAP = secrets.token_urlsafe(48)
SESSION = secrets.token_urlsafe(48)
SESSION_START = time.monotonic()
VALID_SECONDS = 6 * 3600
ALLOWED_DOCUMENTS = {
    "finance_alice.txt", "engineering_bob.txt", "shared_control.txt",
    "group_finance_alice.txt", "inherited_finance_alice.txt",
}
EXPECTED = {
    "alice": {"finance_alice.txt": "ALLOW", "engineering_bob.txt": "DENY",
              "shared_control.txt": "ALLOW", "group_finance_alice.txt": "ALLOW",
              "inherited_finance_alice.txt": "ALLOW"},
    "bob": {"finance_alice.txt": "DENY", "engineering_bob.txt": "ALLOW",
            "shared_control.txt": "ALLOW", "group_finance_alice.txt": "DENY",
            "inherited_finance_alice.txt": "DENY"},
}
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.state.bootstrap_available = True
app.state.last_request = 0.0


def _create_bootstrap() -> None:
    if IDENTITIES.is_symlink() or not IDENTITIES.is_dir():
        raise RuntimeError("PRIVATE_IDENTITY_DIRECTORY_REQUIRED")
    if stat.S_IMODE(IDENTITIES.stat().st_mode) != 0o700:
        raise RuntimeError("PRIVATE_IDENTITY_DIRECTORY_MUST_BE_0700")
    if BOOTSTRAP_FILE.is_symlink():
        raise RuntimeError("REFUSE_SYMLINK_BOOTSTRAP_FILE")
    fd = os.open(BOOTSTRAP_FILE, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, BOOTSTRAP.encode())
    finally:
        os.close(fd)


_create_bootstrap()


def _session_started(actor: str) -> bool:
    """The socket is created BEFORE login; don't block on a pending login."""
    logfile = IDENTITIES / f"{actor}.log"
    pidfile = IDENTITIES / f"{actor}.pid"
    try:
        pid = int(pidfile.read_text().strip())
        os.kill(pid, 0)
        if logfile.is_symlink() or stat.S_IMODE(logfile.stat().st_mode) & 0o077:
            return False
        return f"SERVING {actor} tokens" in logfile.read_text()
    except (OSError, ValueError):
        return False


def _socket_get(actor: str, what: str) -> str:
    path = ACTORS.get(actor)
    if path is None or what not in {"claims", "api_token"}:
        raise ValueError("INVALID_ACTOR_OR_QUERY")
    if not _session_started(actor):
        raise RuntimeError("EMPLOYEE_SIGN_IN_STILL_PENDING")
    if path.is_symlink() or not path.exists() or not stat.S_ISSOCK(path.stat().st_mode):
        raise RuntimeError("EMPLOYEE_NOT_SIGNED_IN")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(str(path))
        connection.sendall((what + "\n").encode("ascii"))
        data = b""
        while b"\n" not in data:
            chunk = connection.recv(8192)
            if not chunk or len(data) + len(chunk) > 40_000:
                raise RuntimeError("IDENTITY_AGENT_UNAVAILABLE")
            data += chunk
    value = data.split(b"\n", 1)[0].decode("utf-8")
    if value.startswith("ERROR ") or not value:
        raise RuntimeError("MICROSOFT_SESSION_NOT_READY")
    return value


def _verified_claims(actor: str) -> dict:
    obj = json.loads(_socket_get(actor, "claims"))
    claims = obj.get("id_token_claims") or {}
    if (obj.get("actor") != actor or obj.get("graph_me_oid_match") is not True
            or not claims.get("oid") or not claims.get("tid")
            or claims.get("iss") !=
            f"https://login.microsoftonline.com/{claims.get('tid')}/v2.0"
            or int(claims.get("exp") or 0) < int(time.time()) + 10):
        raise RuntimeError("MICROSOFT_SIGN_IN_NOT_VERIFIED")
    return {
        "state": "SIGNED_IN", "actor": actor, "user": obj.get("upn", ""),
        "verified_at": obj.get("verified_at"),
        "expires_in_seconds": max(0, int(claims["exp"]) - int(time.time())),
    }


def _signin_url(actor: str) -> str | None:
    logfile = IDENTITIES / f"{actor}.log"
    pidfile = IDENTITIES / f"{actor}.pid"
    try:
        pid = int(pidfile.read_text().strip())
        os.kill(pid, 0)
        if logfile.is_symlink() or stat.S_IMODE(logfile.stat().st_mode) & 0o077:
            return None
        links = [s.strip() for s in logfile.read_text().splitlines()
                 if s.strip().startswith("https://login.microsoftonline.com/")]
        if not links:
            return None
        from urllib.parse import urlsplit
        candidate = links[-1]
        parsed = urlsplit(candidate)
        if (parsed.scheme != "https" or parsed.hostname != "login.microsoftonline.com"
                or not parsed.path.endswith("/oauth2/v2.0/authorize")):
            return None
        return candidate
    except (OSError, ValueError):
        return None


def _deny_if_not_authenticated(request: Request) -> None:
    if time.monotonic() - SESSION_START >= VALID_SECONDS:
        raise HTTPException(401, "OPERATOR_SESSION_EXPIRED")
    if request.url.hostname != HOST:
        raise HTTPException(403, "LOOPBACK_HOST_REQUIRED")
    value = request.cookies.get(COOKIE, "")
    if not secrets.compare_digest(value, SESSION):
        raise HTTPException(401, "OPERATOR_AUTHENTICATION_REQUIRED")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    return response


@app.get("/")
def home(request: Request, bootstrap: str | None = None):
    if bootstrap is not None:
        if (not app.state.bootstrap_available
                or not secrets.compare_digest(bootstrap, BOOTSTRAP)):
            raise HTTPException(401, "BOOTSTRAP_INVALID_OR_ALREADY_USED")
        app.state.bootstrap_available = False
        redirect = RedirectResponse("/", status_code=303)
        redirect.set_cookie(
            COOKIE, SESSION, httponly=True, samesite="strict", max_age=VALID_SECONDS,
            path="/",
        )
        return redirect
    _deny_if_not_authenticated(request)
    return HTMLResponse((Path(__file__).parent / "operator_console.html").read_text())


@app.get("/operator-console.js")
def javascript(request: Request):
    _deny_if_not_authenticated(request)
    from fastapi.responses import Response
    return Response((Path(__file__).parent / "operator_console.js").read_text(),
                    media_type="text/javascript")


@app.get("/operator-console.css")
def css(request: Request):
    _deny_if_not_authenticated(request)
    from fastapi.responses import Response
    return Response((Path(__file__).parent / "operator_console.css").read_text(),
                    media_type="text/css")


@app.get("/api/identities")
def identities(request: Request):
    _deny_if_not_authenticated(request)
    result = {}
    for actor in ACTORS:
        try:
            result[actor] = _verified_claims(actor)
        except (RuntimeError, ValueError, OSError, json.JSONDecodeError, TimeoutError):
            result[actor] = {
                "state": "SIGN_IN_REQUIRED", "actor": actor,
                "sign_in_url": _signin_url(actor),
            }
    return {"actors": result, "documents": sorted(ALLOWED_DOCUMENTS),
            "expected": EXPECTED, "token_storage": "SERVER_MEMORY_ONLY"}


def _runtime_readiness() -> dict:
    """Live service health, never simulated or an independent certificate."""
    out = {"gateway_ready": False, "guard_ready": False,
           "rag_protected_route": False, "rag_signed_index_ready": False,
           "signed_index_reason": "SIGNED_INDEX_UNAVAILABLE", "indexed_documents": 0,
           "identity_ready": False, "authorization_revisions_ready": False,
           "guard_policy_version": None, "live_provider_verified": False,
           "independently_certified": False}
    try:
        with httpx.Client(timeout=4, trust_env=False, follow_redirects=False) as client:
            gw = client.get("http://127.0.0.1:18090/health/ready")
            guard = client.get("http://127.0.0.1:18080/health",
                               params={"application_id": "accessproof-human-validation-rag"})
            status = client.get(RAG + "/status")
            signed = client.get(RAG + "/health/ready")
            source = client.get(RAG + "/health")
        out["gateway_ready"] = gw.status_code == 200 and gw.json().get("status") == "ok"
        gj = guard.json() if guard.status_code == 200 else {}
        out["guard_ready"] = bool(gj.get("ready") is True and gj.get("status") == "ok")
        out["identity_ready"] = gj.get("identity_ready") is True
        out["authorization_revisions_ready"] = gj.get("authorization_revisions_ready") is True
        out["guard_policy_version"] = gj.get("policy_version")
        sj = status.json() if status.status_code == 200 else {}
        out["rag_protected_route"] = sj.get("protected_route") is True
        out["indexed_documents"] = int(sj.get("documents") or 0)
        out["rag_signed_index_ready"] = signed.status_code == 200 and signed.json().get("signed_index_ready") is True
        out["signed_index_reason"] = (signed.json().get("reason_code") or "SIGNED_INDEX_UNAVAILABLE")
        out["live_provider_verified"] = bool(source.status_code == 200 and
                                              source.json().get("live_provider_verified") is True)
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        pass
    out["ready_to_test"] = bool(
        out["gateway_ready"] and out["guard_ready"] and out["identity_ready"]
        and out["authorization_revisions_ready"] and out["rag_protected_route"]
        and out["rag_signed_index_ready"] and out["indexed_documents"] > 0
    )
    return out


@app.get("/api/readiness")
def readiness(request: Request):
    _deny_if_not_authenticated(request)
    return _runtime_readiness()


class Prompt(BaseModel):
    actor: Literal["alice", "bob"]
    question: str = Field(min_length=2, max_length=1000)
    # Optional ONLY for an explicit canary diagnostic. Ordinary questions
    # retrieve signed candidates automatically from the SharePoint index.
    document_name: str | None = Field(default=None, min_length=3, max_length=120)


@app.post("/api/chat")
def chat(request: Request, prompt: Prompt):
    _deny_if_not_authenticated(request)
    if request.headers.get("origin") != ORIGIN:
        raise HTTPException(403, "SAME_ORIGIN_REQUIRED")
    if request.headers.get("x-accessproof-human-test") != "1":
        raise HTTPException(403, "OPERATOR_TEST_HEADER_REQUIRED")
    if prompt.document_name is not None and prompt.document_name not in ALLOWED_DOCUMENTS:
        raise HTTPException(400, "ONLY_APPROVED_SYNTHETIC_CANARIES_SUPPORTED")
    # For question-first chat, an expected allow/deny result cannot be
    # precomputed. AccessProof's live Gateway decision is authoritative.
    expected = (EXPECTED[prompt.actor][prompt.document_name]
                if prompt.document_name is not None else "NOT_PREDETERMINED")
    retrieval_mode = "diagnostic" if prompt.document_name else "automatic"
    if not _runtime_readiness()["ready_to_test"]:
        raise HTTPException(503, "ACCESSPROOF_ENFORCEMENT_NOT_READY")
    if time.monotonic() - app.state.last_request < 1:
        raise HTTPException(429, "TEST_RATE_LIMIT")
    app.state.last_request = time.monotonic()
    try:
        _verified_claims(prompt.actor)
        token = _socket_get(prompt.actor, "api_token")
    except (RuntimeError, ValueError, OSError, TimeoutError, json.JSONDecodeError) as exc:
        raise HTTPException(409, "MICROSOFT_SIGN_IN_REQUIRED") from exc
    # Employee token NEVER leaves this process for browser/JS. The RAG uses
    # the protected route, which is hard-bound to the dedicated Gateway.
    try:
        with httpx.Client(timeout=100, trust_env=False, follow_redirects=False) as client:
            upstream = client.post(
                RAG + "/chat/protected",
                json=({"question": prompt.question, "document_name": prompt.document_name}
                      if prompt.document_name is not None else {"question": prompt.question}),
                headers={"Authorization": "Bearer " + token, "Cache-Control": "no-store"},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(503, "PROTECTED_RAG_UNAVAILABLE") from exc
    data = upstream.json() if "application/json" in upstream.headers.get("content-type", "") else {}
    if upstream.status_code == 403:
        return JSONResponse(status_code=200, content={
            "actor": prompt.actor, "retrieval_mode": retrieval_mode,
            "outcome": "DENIED", "http_status": 403,
            "expected": expected,
            "guard_audit_confirmation": "NOT_CHECKED",
            "answer": None,
        })
    if upstream.status_code != 200:
        return JSONResponse(status_code=503, content={
            "actor": prompt.actor, "retrieval_mode": retrieval_mode,
            "outcome": "INCONCLUSIVE", "http_status": upstream.status_code,
            "expected": expected,
            "reason": str(data.get("detail") or "PROTECTED_REQUEST_FAILED")[:120],
        })
    gate = data.get("accessproof") or {}
    if (data.get("mode") != "protected" or data.get("security") != "GATEWAY_ALLOWED"
            or gate.get("decision") != "allow" or not gate.get("decision_id")
            or not isinstance(data.get("answer"), str)):
        raise HTTPException(502, "UNVERIFIED_GATEWAY_RESPONSE")
    return {
        "actor": prompt.actor, "retrieval_mode": retrieval_mode,
        "outcome": "ALLOWED", "expected": expected,
        "guard_audit_confirmation": "NOT_CHECKED",
        "decision_id": str(gate["decision_id"])[:130],
        "cache_hit": data.get("cache_hit") is True,
        "cache_authorization": (
            "CURRENT_EMPLOYEE_RECHECKED_BY_GATEWAY"
            if data.get("cache_authorization") == "CURRENT_EMPLOYEE_RECHECKED_BY_GATEWAY"
            else "NOT_VERIFIED"
        ),
        "answer": data["answer"],
    }


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT, access_log=False, log_level="warning")
