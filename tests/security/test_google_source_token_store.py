"""Customer-side Google OAuth token renewal never escapes ingester secret store."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from packages.auth.google_source_token import GoogleSourceTokenStore, TokenStoreError


def _store(tmp_path, *, expires_in: int):
    secret = tmp_path / "oauth.json"
    secret.write_text(json.dumps({
        "access_token": "initial-access", "refresh_token": "initial-refresh",
        "client_id": "approved-client", "client_secret": "approved-secret",
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat(),
        "scope": "https://www.googleapis.com/auth/drive.readonly",
    }))
    secret.chmod(0o600)
    return GoogleSourceTokenStore(secret), secret


def test_google_source_token_uses_existing_unexpired_token(tmp_path):
    store, secret = _store(tmp_path, expires_in=3600)
    assert store.access_token() == "initial-access"
    assert json.loads(secret.read_text())["refresh_token"] == "initial-refresh"


def test_google_source_token_refreshes_and_persists_rotated_token(tmp_path):
    store, secret = _store(tmp_path, expires_in=30)
    observed = []
    def handler(request: httpx.Request):
        assert str(request.url) == "https://oauth2.googleapis.com/token"
        assert request.method == "POST"
        observed.append(request.content)
        return httpx.Response(200, json={
            "access_token": "rotated-access", "refresh_token": "rotated-refresh",
            "expires_in": 3600, "token_type": "Bearer",
        })
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert store.access_token(client=client) == "rotated-access"
    saved = json.loads(secret.read_text())
    assert saved["refresh_token"] == "rotated-refresh"
    assert saved["client_secret"] == "approved-secret"
    assert secret.stat().st_mode & 0o777 == 0o600
    assert observed and b"initial-refresh" in observed[0]
    assert store.access_token() == "rotated-access"


def test_google_source_token_rejects_unsafe_secret_permissions(tmp_path):
    store, secret = _store(tmp_path, expires_in=60)
    secret.chmod(0o644)
    with pytest.raises(TokenStoreError):
        store.access_token()


def test_google_source_token_rejects_invalid_refresh_without_overwriting_secret(tmp_path):
    store, secret = _store(tmp_path, expires_in=30)
    original = secret.read_bytes()
    with httpx.Client(transport=httpx.MockTransport(
        lambda _: httpx.Response(400, json={"error": "invalid_grant"})
    )) as client:
        with pytest.raises(Exception):
            store.access_token(client=client)
    assert secret.read_bytes() == original
