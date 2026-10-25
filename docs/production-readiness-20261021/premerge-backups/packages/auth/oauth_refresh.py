"""Provider-neutral OAuth refresh lifecycle.

The caller owns persistence and supplies an atomic save callback.  This keeps
refresh tokens inside the existing encrypted source credential envelope and
prevents a provider response that omits ``refresh_token`` from erasing the
last usable credential.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

import httpx


@dataclass(frozen=True)
class OAuthCredentials:
    access_token: str
    refresh_token: str | None = None
    expires_at: datetime | None = None
    token_type: str = "Bearer"
    scopes: tuple[str, ...] = ()

    def needs_refresh(self, skew_seconds: int = 300) -> bool:
        return self.expires_at is not None and self.expires_at <= datetime.now(timezone.utc) + timedelta(seconds=skew_seconds)


class OAuthRefreshError(RuntimeError):
    def __init__(self, code: str, *, retry_after: float | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.retry_after = retry_after


def refresh_credentials(
    credentials: OAuthCredentials,
    *,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    save: Callable[[OAuthCredentials], None],
    client: httpx.Client | None = None,
    attempts: int = 3,
) -> OAuthCredentials:
    """Refresh once and atomically persist the resulting credential state."""
    if not credentials.refresh_token:
        raise OAuthRefreshError("REAUTHORIZATION_REQUIRED")
    owns_client = client is None
    http = client or httpx.Client(timeout=15, follow_redirects=False, trust_env=False)
    try:
        response: httpx.Response | None = None
        for attempt in range(max(1, attempts)):
            try:
                response = http.post(token_endpoint, data={
                    "grant_type": "refresh_token",
                    "refresh_token": credentials.refresh_token,
                    "client_id": client_id,
                    "client_secret": client_secret,
                })
            except httpx.HTTPError as exc:
                if attempt + 1 >= attempts:
                    raise OAuthRefreshError("DEGRADED") from exc
                continue
            if response.status_code not in {429, 500, 502, 503, 504}:
                break
            if attempt + 1 < attempts:
                delay = min(30.0, (2**attempt) + random.random())
                retry_after = response.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    delay = min(30.0, float(retry_after))
                # The caller can schedule the next retry; this small bounded
                # delay prevents a tight storm when called by a worker.
                import time
                time.sleep(delay)
        assert response is not None
        if response.status_code in {401, 400}:
            error = str(response.json().get("error") or "") if response.headers.get("content-type", "").startswith("application/json") else ""
            raise OAuthRefreshError("REAUTHORIZATION_REQUIRED" if error in {"invalid_grant", "invalid_client"} or response.status_code == 400 else "DEGRADED")
        if response.status_code == 403:
            raise OAuthRefreshError("INSUFFICIENT_PERMISSION")
        if response.status_code >= 400:
            raise OAuthRefreshError("DEGRADED")
        try:
            payload = response.json()
            access_token = str(payload["access_token"])
        except (ValueError, KeyError, TypeError) as exc:
            raise OAuthRefreshError("DEGRADED") from exc
        rotated = payload.get("refresh_token") or credentials.refresh_token
        expires_in = payload.get("expires_in")
        refreshed = OAuthCredentials(
            access_token=access_token,
            refresh_token=str(rotated) if rotated else None,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=int(expires_in)) if expires_in else credentials.expires_at,
            token_type=str(payload.get("token_type") or credentials.token_type),
            scopes=tuple(str(payload.get("scope") or "").split()) or credentials.scopes,
        )
        save(refreshed)
        return refreshed
    finally:
        if owns_client:
            http.close()
