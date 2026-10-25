from datetime import datetime, timedelta, timezone
import json

import httpx
import pytest

from packages.auth.oauth_refresh import OAuthCredentials, OAuthRefreshError, refresh_credentials


def test_refresh_rotates_token_and_preserves_existing_when_omitted():
    current = OAuthCredentials("old", "refresh-old", datetime.now(timezone.utc) - timedelta(seconds=1))
    saved = []
    client = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"access_token": "new", "expires_in": 3600})))
    refreshed = refresh_credentials(current, token_endpoint="https://issuer.test/token", client_id="id", client_secret="secret", save=saved.append, client=client)
    assert refreshed.access_token == "new" and refreshed.refresh_token == "refresh-old"
    assert saved == [refreshed]


def test_refresh_classifies_invalid_grant_without_exposing_provider_body():
    client = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(400, json={"error": "invalid_grant", "error_description": "sensitive"})))
    with pytest.raises(OAuthRefreshError, match="REAUTHORIZATION_REQUIRED"):
        refresh_credentials(OAuthCredentials("old", "refresh"), token_endpoint="https://issuer.test/token", client_id="id", client_secret="secret", save=lambda _: None, client=client)


@pytest.mark.asyncio
async def test_worker_refresh_reencrypts_rotated_source_credentials(monkeypatch):
    from types import SimpleNamespace
    from apps.worker.accessproof_worker import main as worker

    refreshed = OAuthCredentials("new-access", "new-refresh", datetime.now(timezone.utc) + timedelta(hours=1))

    def fake_refresh(_credentials, **kwargs):
        kwargs["save"](refreshed)
        return refreshed

    monkeypatch.setattr(worker, "refresh_credentials", fake_refresh)
    source = SimpleNamespace(encrypted_credentials=None)
    original = {
        "access_token": "old-access", "refresh_token": "old-refresh",
        "expires_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        "token_endpoint": "https://issuer.test/token", "client_id": "client", "client_secret": "secret",
    }
    result = await worker.refresh_source_credentials_if_needed(None, source, original)
    assert result["access_token"] == "new-access"
    assert result["refresh_token"] == "new-refresh"
    persisted = json.loads(worker.box.decrypt(source.encrypted_credentials))
    assert persisted["access_token"] == "new-access"



@pytest.mark.asyncio
async def test_google_refresh_does_not_send_credentials_to_untrusted_endpoint(monkeypatch):
    from types import SimpleNamespace
    from apps.worker.accessproof_worker import main as worker

    touched = []

    def must_not_call(*args, **kwargs):
        touched.append(True)
        raise AssertionError("Refresh token must not be sent to arbitrary host")

    monkeypatch.setattr(worker, "refresh_credentials", must_not_call)
    source = SimpleNamespace(provider="google-drive", encrypted_credentials=None)
    original = {
        "access_token": "old-access", "refresh_token": "private-refresh",
        "expires_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        "token_endpoint": "http://127.0.0.1:8000/token", "client_id": "client",
        "client_secret": "secret",
    }
    with pytest.raises(OAuthRefreshError, match="UNTRUSTED_GOOGLE_TOKEN_ENDPOINT"):
        await worker.refresh_source_credentials_if_needed(None, source, original)
    assert not touched


@pytest.mark.asyncio
async def test_microsoft_refresh_endpoint_rejects_credential_exfiltration(monkeypatch):
    from apps.worker.accessproof_worker.main import refresh_source_credentials_if_needed
    from packages.auth.oauth_refresh import OAuthRefreshError
    from types import SimpleNamespace

    source = SimpleNamespace(provider="microsoft365")
    creds = {
        "access_token": "synthetic",
        "refresh_token": "synthetic-refresh",
        "client_id": "client",
        "client_secret": "secret",
        "tenant_id": "11111111-2222-3333-4444-555555555555",
        "expires_at": "2020-01-01T00:00:00+00:00",
        "token_endpoint": "https://attacker.invalid/capture",
    }
    with pytest.raises(OAuthRefreshError, match="UNTRUSTED_MICROSOFT_TOKEN_ENDPOINT"):
        await refresh_source_credentials_if_needed(None, source, creds)


@pytest.mark.asyncio
async def test_microsoft_refresh_requires_specific_tenant():
    from apps.worker.accessproof_worker.main import refresh_source_credentials_if_needed
    from packages.auth.oauth_refresh import OAuthRefreshError
    from types import SimpleNamespace

    with pytest.raises(OAuthRefreshError, match="INVALID_MICROSOFT_TENANT"):
        await refresh_source_credentials_if_needed(None, SimpleNamespace(provider="microsoft365"), {
            "refresh_token": "synthetic", "tenant_id": "common",
        })


@pytest.mark.asyncio
async def test_microsoft_application_token_auto_renewal_preserves_scoped_source(monkeypatch):
    from types import SimpleNamespace
    from apps.worker.accessproof_worker import main as worker

    expected_tenant = "11111111-2222-3333-4444-555555555555"
    renewed = []
    def issue(**kwargs):
        renewed.append(kwargs)
        return "new-synthetic-graph-token", datetime.now(timezone.utc) + timedelta(hours=1)
    monkeypatch.setattr(worker, "graph_app_token", issue)
    source = SimpleNamespace(provider="microsoft365", encrypted_credentials=None)
    expiring = {
        "tenant_id": expected_tenant,
        "tenant_hint": expected_tenant,
        "grant_type": "client_credentials",
        "access_token": "old-synthetic-graph-token",
        "client_id": "client-id",
        "client_secret": "client-secret",
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=50)).isoformat(),
        "token_endpoint": f"https://login.microsoftonline.com/{expected_tenant}/oauth2/v2.0/token",
    }
    changed = await worker.refresh_source_credentials_if_needed(None, source, expiring)
    assert changed["access_token"] == "new-synthetic-graph-token"
    assert changed["grant_type"] == "client_credentials"
    assert source.encrypted_credentials and "new-synthetic-graph-token" not in source.encrypted_credentials
    assert renewed == [{
        "tenant_id": expected_tenant,
        "client_id": "client-id",
        "client_secret": "client-secret",
    }]
    cached = await worker.refresh_source_credentials_if_needed(None, source, changed)
    assert cached == changed
    assert len(renewed) == 1
    malicious = dict(expiring, token_endpoint="https://attacker.invalid/steal")
    with pytest.raises(OAuthRefreshError, match="UNTRUSTED_MICROSOFT_TOKEN_ENDPOINT"):
        await worker.refresh_source_credentials_if_needed(None, source, malicious)


@pytest.mark.asyncio
async def test_microsoft_app_token_renewal_rejects_missing_tenant(monkeypatch):
    from types import SimpleNamespace
    from apps.worker.accessproof_worker.main import refresh_source_credentials_if_needed
    credentials = {
        "grant_type": "client_credentials", "access_token": "old",
        "client_id": "client", "client_secret": "secret",
        "expires_at": "2020-01-01T00:00:00+00:00", "tenant_id": "common",
    }
    with pytest.raises(OAuthRefreshError, match="INVALID_MICROSOFT_TENANT"):
        await refresh_source_credentials_if_needed(
            None, SimpleNamespace(provider="microsoft365"), credentials,
        )
