"""Microsoft Entra admin-consent and app-only Graph token acquisition.

This is separate from employee OIDC authentication. An authenticated
AccessProof administrator starts a one-time consent state, a Microsoft tenant
administrator consents, then the backend gets a *Graph-audience* app token.
No customer employee token is accepted as a substitute for source consent.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from uuid import UUID

import httpx


class MicrosoftConsentError(RuntimeError):
    pass


def tenant_uuid(value: object) -> str:
    try:
        tenant = str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise MicrosoftConsentError("MICROSOFT_TENANT_INVALID") from exc
    if tenant == "00000000-0000-0000-0000-000000000000":
        raise MicrosoftConsentError("MICROSOFT_TENANT_INVALID")
    return tenant


def authorization_url(
    *, tenant_id: str, client_id: str, redirect_uri: str, state: str,
) -> str:
    tenant = tenant_uuid(tenant_id)
    from urllib.parse import urlsplit
    parsed = urlsplit(redirect_uri)
    allowed = parsed.scheme == "https" and bool(parsed.hostname)
    allowed = allowed or (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"})
    if not client_id or not state or not allowed or parsed.username or parsed.password:
        raise MicrosoftConsentError("MICROSOFT_CONSENT_CONFIGURATION_INVALID")
    return (
        f"https://login.microsoftonline.com/{tenant}/v2.0/adminconsent?"
        + urlencode({
            "client_id": client_id,
            # The v2 admin-consent endpoint requires scope. Application
            # permissions are granted from the app registration via .default;
            # do not embed a broader hard-coded Graph permissions list here.
            "scope": "https://graph.microsoft.com/.default",
            "redirect_uri": redirect_uri,
            "state": state,
        })
    )


def graph_app_token(
    *, tenant_id: str, client_id: str, client_secret: str,
    client: httpx.Client | None = None,
) -> tuple[str, datetime]:
    tenant = tenant_uuid(tenant_id)
    if not client_id or not client_secret:
        raise MicrosoftConsentError("MICROSOFT_APPLICATION_CREDENTIALS_MISSING")
    own_client = client is None
    http = client or httpx.Client(timeout=15, follow_redirects=False, trust_env=False)
    try:
        try:
            response = http.post(
                f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
                data={
                    "client_id": client_id, "client_secret": client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
        except httpx.HTTPError as exc:
            raise MicrosoftConsentError("MICROSOFT_TOKEN_ENDPOINT_UNAVAILABLE") from exc
        if response.status_code >= 400:
            raise MicrosoftConsentError(
                "MICROSOFT_CONSENT_OR_CREDENTIALS_REQUIRED"
                if response.status_code in {400, 401, 403}
                else "MICROSOFT_TOKEN_ENDPOINT_UNAVAILABLE"
            )
        try:
            payload = response.json()
            token = payload["access_token"]
            lifetime = int(payload["expires_in"])
            if (not isinstance(token, str) or len(token) < 5
                    or not 60 <= lifetime <= 86400
                    or payload.get("token_type", "Bearer").lower() != "bearer"):
                raise ValueError("Invalid Graph credential")
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise MicrosoftConsentError("MICROSOFT_TOKEN_RESPONSE_INVALID") from exc
        return token, datetime.now(timezone.utc) + timedelta(seconds=lifetime)
    finally:
        if own_client:
            http.close()
