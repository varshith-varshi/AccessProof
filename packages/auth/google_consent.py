"""Google source OAuth 2.0 authorization-code flow with server-side PKCE.

This is only for explicitly approved enterprise source connections. No raw
OAuth code, refresh token, client secret or verifier reaches the browser UI.
"""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlsplit

import httpx

GOOGLE_SCOPES = (
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
)


class GoogleConsentError(ValueError):
    pass


def _validate_redirect(value: str) -> None:
    parsed = urlsplit(value)
    if (not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query or
        not (parsed.scheme == "https" or
             (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}))):
        raise GoogleConsentError("GOOGLE_REDIRECT_URI_INVALID")


def authorization_url(*, client_id: str, redirect_uri: str, state: str, verifier: str) -> str:
    _validate_redirect(redirect_uri)
    if not client_id or not state or not 43 <= len(verifier) <= 128:
        raise GoogleConsentError("GOOGLE_OAUTH_CONFIGURATION_INVALID")
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state,
        "scope": " ".join(GOOGLE_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    })


def exchange_code(*, code: str, client_id: str, client_secret: str,
                  redirect_uri: str, verifier: str,
                  client: httpx.Client | None = None) -> dict[str, str]:
    _validate_redirect(redirect_uri)
    if not code or len(code) > 4096 or not client_id or not client_secret or not verifier:
        raise GoogleConsentError("GOOGLE_CODE_EXCHANGE_INPUT_INVALID")
    own = client is None
    http = client or httpx.Client(timeout=15, follow_redirects=False, trust_env=False)
    try:
        try:
            response = http.post("https://oauth2.googleapis.com/token", data={
                "code": code, "client_id": client_id, "client_secret": client_secret,
                "redirect_uri": redirect_uri, "code_verifier": verifier,
                "grant_type": "authorization_code",
            })
        except httpx.HTTPError as exc:
            raise GoogleConsentError("GOOGLE_TOKEN_ENDPOINT_UNAVAILABLE") from exc
        if response.status_code >= 400:
            raise GoogleConsentError("GOOGLE_CONSENT_OR_TOKEN_EXCHANGE_FAILED")
        try:
            payload = response.json()
            access = payload["access_token"]
            lifetime = int(payload["expires_in"])
            refresh = payload.get("refresh_token")
            scopes = str(payload["scope"]).split()
            if (not isinstance(access, str) or not access or
                    not 60 <= lifetime <= 86400 or
                    not isinstance(refresh, str) or not refresh or
                    str(payload.get("token_type") or "Bearer").lower() != "bearer" or
                    not set(GOOGLE_SCOPES).issubset(scopes)):
                raise ValueError("Incomplete Google offline authorization")
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise GoogleConsentError("GOOGLE_OAUTH_SCOPES_OR_OFFLINE_ACCESS_MISSING") from exc
        return {
            "access_token": access, "refresh_token": refresh,
            "client_id": client_id,
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=lifetime)).isoformat(),
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "scope": " ".join(scopes),
        }
    finally:
        if own:
            http.close()
