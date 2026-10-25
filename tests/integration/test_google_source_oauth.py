"""Source-scoped Google OAuth: secure state, PKCE, permissions and replay."""
from __future__ import annotations

from urllib.parse import parse_qs, urlparse
from datetime import datetime, timedelta, timezone

import httpx
from fastapi.testclient import TestClient

from apps.api.accessproof_api import app as api_module
from apps.api.accessproof_api.db import (
    Base, GoogleSourceOAuthState, SessionLocal, SourceConnection, engine,
)
from connectors.google_drive.adapter import ConnectionIdentity
from packages.auth.google_consent import GOOGLE_SCOPES, authorization_url, exchange_code, GoogleConsentError


class FakeDrive:
    def __init__(self, **kwargs):
        self.root = kwargs["test_root_folder_id"]
        self._client = self

    async def validate_connection(self):
        return ConnectionIdentity(provider="google-drive", tenant="drive-a", account=None,
                                  boundary=self.root, metadata={"validated": True})

    async def aclose(self):
        pass


def test_google_oauth_state_is_one_time_and_root_bound(monkeypatch):
    monkeypatch.setenv("ACCESSPROOF_GOOGLE_OAUTH_CLIENT_ID", "test-client")
    monkeypatch.setenv("ACCESSPROOF_GOOGLE_OAUTH_CLIENT_SECRET", "test-secret")
    monkeypatch.setattr(api_module, "GoogleDriveAdapter", FakeDrive)
    monkeypatch.setattr(api_module, "exchange_google_code", lambda **kwargs: {
        "access_token": "fake-access", "refresh_token": "fake-refresh",
        "client_id": "test-client", "client_secret": "test-secret",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "token_endpoint": "https://oauth2.googleapis.com/token", "scope": " ".join(GOOGLE_SCOPES),
    })
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(api_module.app) as client:
        signup = client.post("/api/v1/auth/signup", json={
            "email": "google-source-admin@example.com",
            "password": "correct horse battery staple",
            "organization_name": "Google Source Pilot",
        })
        assert signup.status_code == 201, signup.text
        account = signup.json()
        headers = {"Authorization": f"Bearer {account['session_token']}",
                   "X-Organization-ID": account["organization_id"]}
        created = client.post("/api/v1/current/sources", headers=headers, json={
            "provider": "google-drive", "name": "Drive", "boundary": "approved-root",
            "credentials": {},
        })
        assert created.status_code == 201, created.text
        source_id = created.json()["id"]
        begin_url = f"/api/v1/current/sources/{source_id}/google-oauth/begin"
        def begin():
            result = client.post(begin_url, headers=headers)
            assert result.status_code == 200, result.text
            params = parse_qs(urlparse(result.json()["authorization_url"]).query)
            assert params["code_challenge_method"] == ["S256"]
            assert params["access_type"] == ["offline"]
            return params["state"][0]
        state = begin()
        failed = client.get("/api/v1/current/sources/google-oauth/callback",
                            params={"state": state, "error": "access_denied"},
                            follow_redirects=False)
        assert failed.status_code == 303 and "consent-failed" in failed.headers["location"]
        assert client.get("/api/v1/current/sources/google-oauth/callback",
                          params={"state": state, "code": "replay"}).status_code == 400
        state = begin()
        success = client.get("/api/v1/current/sources/google-oauth/callback",
                             params={"state": state, "code": "synthetic-code"},
                             follow_redirects=False)
        assert success.status_code == 303 and "consent-complete" in success.headers["location"]
        with SessionLocal() as db:
            row = db.get(SourceConnection, source_id)
            assert row.status == "connected"
            assert "fake-refresh" not in row.encrypted_credentials
            creds = __import__("json").loads(api_module._secret_box.decrypt(row.encrypted_credentials))
            assert creds["refresh_token"] == "fake-refresh"
            claims = list(db.query(GoogleSourceOAuthState))
            assert len(claims) == 2 and all(state.consumed_at is not None for state in claims)
            assert all("synthetic-code" not in state.encrypted_verifier for state in claims)


def test_google_oauth_helper_requires_all_readonly_scopes_and_refresh_token():
    verifier = "a" * 64
    url = authorization_url(
        client_id="client", redirect_uri="https://api.example.com/callback",
        state="random-state", verifier=verifier,
    )
    assert urlparse(url).hostname == "accounts.google.com"
    captured = []
    def handler(req: httpx.Request):
        captured.append(req)
        return httpx.Response(200, json={
            "access_token": "access", "expires_in": 3600, "scope": " ".join(GOOGLE_SCOPES),
            "refresh_token": "refresh", "token_type": "Bearer",
        })
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = exchange_code(code="synthetic", client_id="client", client_secret="secret",
                               redirect_uri="https://api.example.com/callback", verifier=verifier,
                               client=client)
    assert result["refresh_token"] == "refresh"
    assert str(captured[0].url) == "https://oauth2.googleapis.com/token"
    assert b"code_verifier=" in captured[0].content
    def missing(req: httpx.Request):
        return httpx.Response(200, json={
            "access_token": "access", "expires_in": 3600, "scope": GOOGLE_SCOPES[0],
        })
    with httpx.Client(transport=httpx.MockTransport(missing)) as client:
        import pytest
        with pytest.raises(GoogleConsentError, match="GOOGLE_OAUTH_SCOPES_OR_OFFLINE_ACCESS_MISSING"):
            exchange_code(code="synthetic", client_id="client", client_secret="secret",
                          redirect_uri="https://api.example.com/callback", verifier=verifier,
                          client=client)
