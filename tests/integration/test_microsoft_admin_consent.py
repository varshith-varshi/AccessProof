"""Microsoft admin consent: source/tenant-bound, one-time and no credential leaks."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from apps.api.accessproof_api import app as api_module
from apps.api.accessproof_api.db import (
    Base, MicrosoftConsentState, SourceConnection, SessionLocal, engine,
)
from connectors.microsoft365.adapter import ConnectionIdentity
from packages.auth.microsoft_consent import (
    MicrosoftConsentError, graph_app_token,
)

TENANT = "11111111-2222-3333-4444-555555555555"
OTHER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class FakeGraph:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self._client = self

    async def validate_connection(self):
        return ConnectionIdentity(
            provider="microsoft365", tenant=self.kwargs.get("tenant_hint"),
            account=None, boundary=self.kwargs["test_root_item_id"], metadata={},
        )

    async def aclose(self):
        return None


def signup(client: TestClient):
    resp = client.post("/api/v1/auth/signup", json={
        "email": "ms-admin-flow@example.com",
        "password": "correct horse battery staple",
        "organization_name": "Test Microsoft Admin Consent",
    })
    assert resp.status_code == 201, resp.text
    account = resp.json()
    return {
        "Authorization": f"Bearer {account['session_token']}",
        "X-Organization-ID": account["organization_id"],
    }


def create_source(client: TestClient, headers: dict[str, str]):
    resp = client.post("/api/v1/current/sources", headers=headers, json={
        "provider": "microsoft365", "name": "Consent Preview", "boundary": "root",
        "credentials": {"drive_id": "drive1", "test_root_item_id": "root",
                        "tenant_id": TENANT},
    })
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def begin(client: TestClient, headers: dict[str, str], source_id: str):
    resp = client.post(
        f"/api/v1/current/sources/{source_id}/microsoft-admin-consent/begin",
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    url = urlparse(resp.json()["authorization_url"])
    assert url.hostname == "login.microsoftonline.com"
    assert url.path == f"/{TENANT}/v2.0/adminconsent"
    query = parse_qs(url.query)
    return query["state"][0]


def test_admin_consent_tenant_replay_and_tokenless_draft(monkeypatch):
    monkeypatch.setenv("ACCESSPROOF_MICROSOFT_CLIENT_ID", "synthetic-client")
    monkeypatch.setenv("ACCESSPROOF_MICROSOFT_CLIENT_SECRET", "synthetic-secret")
    monkeypatch.setattr(api_module, "Microsoft365Adapter", FakeGraph)
    monkeypatch.setattr(api_module, "graph_app_token", lambda **kwargs: (
        "synthetic-graph-token", datetime.now(timezone.utc) + timedelta(hours=1),
    ))
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(api_module.app) as client:
        headers = signup(client)
        source_id = create_source(client, headers)
        state = begin(client, headers, source_id)
        bad = client.get("/api/v1/current/sources/microsoft-admin-consent/callback", params={
            "state": state, "admin_consent": "True", "tenant": OTHER,
        }, follow_redirects=False)
        assert bad.status_code == 303
        assert "consent-failed" in bad.headers["location"]
        replay = client.get("/api/v1/current/sources/microsoft-admin-consent/callback", params={
            "state": state, "admin_consent": "True", "tenant": TENANT,
        })
        assert replay.status_code == 400
        state = begin(client, headers, source_id)
        good = client.get("/api/v1/current/sources/microsoft-admin-consent/callback", params={
            "state": state, "admin_consent": "True", "tenant": TENANT,
        }, follow_redirects=False)
        assert good.status_code == 303
        assert "consent-complete" in good.headers["location"]
        with SessionLocal() as db:
            row = db.get(SourceConnection, source_id)
            assert row.status == "connected"
            assert row.encrypted_credentials is not None
            assert "synthetic-graph-token" not in row.encrypted_credentials
            assert db.query(MicrosoftConsentState).count() == 2
        listed = client.get("/api/v1/current/sources", headers=headers)
        assert listed.status_code == 200
        assert "synthetic-graph-token" not in listed.text
        assert "synthetic-secret" not in listed.text


def test_microsoft_token_post_is_pinned_and_validates_response():
    observed = []
    def handler(request: httpx.Request):
        observed.append(request)
        return httpx.Response(200, json={
            "access_token": "synthetic-test-token",
            "expires_in": 3600, "token_type": "Bearer",
        })
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        token, expiration = graph_app_token(
            tenant_id=TENANT, client_id="client", client_secret="secret", client=client,
        )
    assert token == "synthetic-test-token"
    assert expiration > datetime.now(timezone.utc)
    assert observed[0].url.host == "login.microsoftonline.com"
    assert observed[0].url.path == f"/{TENANT}/oauth2/v2.0/token"
    assert b"client_credentials" in observed[0].content
    assert b"https%3A%2F%2Fgraph.microsoft.com%2F.default" in observed[0].content
    with pytest.raises(MicrosoftConsentError):
        graph_app_token(tenant_id="common", client_id="client", client_secret="secret")


def test_unconfigured_admin_consent_fails_before_creating_state(monkeypatch):
    monkeypatch.delenv("ACCESSPROOF_MICROSOFT_CLIENT_ID", raising=False)
    monkeypatch.delenv("ACCESSPROOF_MICROSOFT_CLIENT_SECRET", raising=False)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(api_module.app) as client:
        headers = signup(client)
        source_id = create_source(client, headers)
        resp = client.post(
            f"/api/v1/current/sources/{source_id}/microsoft-admin-consent/begin",
            headers=headers,
        )
        assert resp.status_code == 503
        with SessionLocal() as db:
            assert db.query(MicrosoftConsentState).count() == 0


def test_microsoft_consent_invalidates_when_source_changes_and_guards_tenant_scope(monkeypatch):
    from apps.api.accessproof_api.app import _secret_box
    import json
    from apps.api.accessproof_api.db import Membership
    from sqlalchemy import select

    monkeypatch.setenv("ACCESSPROOF_MICROSOFT_CLIENT_ID", "synthetic-client")
    monkeypatch.setenv("ACCESSPROOF_MICROSOFT_CLIENT_SECRET", "synthetic-secret")
    calls = []
    monkeypatch.setattr(api_module, "graph_app_token", lambda **kwargs: calls.append(kwargs))
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(api_module.app) as client:
        headers = signup(client)
        source_id = create_source(client, headers)
        other_tenant = client.post("/api/v1/current/sources", headers=headers, json={
            "provider": "microsoft365", "name": "Other tenant", "boundary": "root",
            "credentials": {"tenant_id": OTHER, "drive_id": "d2", "test_root_item_id": "root"},
        })
        assert other_tenant.status_code == 409
        rotate = client.post(f"/api/v1/sources/{source_id}/rotate-credential", headers=headers, json={
            "credentials": {"tenant_id": TENANT, "drive_id": "another-drive", "test_root_item_id": "root"},
        })
        assert rotate.status_code == 409
        changed_root = client.post(f"/api/v1/sources/{source_id}/rotate-credential", headers=headers, json={
            "credentials": {"tenant_id": TENANT, "drive_id": "drive1", "test_root_item_id": "wrong-root"},
        })
        assert changed_root.status_code == 409
        state = begin(client, headers, source_id)
        # Simulate a concurrent privileged/manual database operation changing
        # the protected drive after consent began.
        with SessionLocal() as db:
            source = db.get(SourceConnection, source_id)
            config = json.loads(_secret_box.decrypt(source.encrypted_credentials))
            config["drive_id"] = "another-drive"
            source.encrypted_credentials = _secret_box.encrypt(json.dumps(config))
            db.commit()
        bad = client.get("/api/v1/current/sources/microsoft-admin-consent/callback", params={
            "state": state, "tenant": TENANT, "admin_consent": "True",
        }, follow_redirects=False)
        assert bad.status_code == 303
        assert "consent-failed" in bad.headers["location"]
        assert calls == []
        # A newly authorized consent session must also become invalid when
        # the original administrator loses their admin role.
        with SessionLocal() as db:
            source = db.get(SourceConnection, source_id)
            config = json.loads(_secret_box.decrypt(source.encrypted_credentials))
            config["drive_id"] = "drive1"
            source.encrypted_credentials = _secret_box.encrypt(json.dumps(config))
            db.commit()
        state = begin(client, headers, source_id)
        with SessionLocal() as db:
            membership = db.scalar(select(Membership))
            membership.role = "VIEWER"
            db.commit()
        blocked = client.get("/api/v1/current/sources/microsoft-admin-consent/callback", params={
            "state": state, "tenant": TENANT, "admin_consent": "True",
        }, follow_redirects=False)
        assert blocked.status_code == 303
        assert "consent-failed" in blocked.headers["location"]
        assert calls == []


def test_admin_consent_preserves_sharepoint_service_not_ready_diagnostic(monkeypatch):
    from packages.connector_sdk.base import ProviderUnavailableError

    class LicensePendingGraph(FakeGraph):
        async def validate_connection(self):
            raise ProviderUnavailableError("MICROSOFT_SHAREPOINT_SERVICE_NOT_READY")

    monkeypatch.setenv("ACCESSPROOF_MICROSOFT_CLIENT_ID", "synthetic-client")
    monkeypatch.setenv("ACCESSPROOF_MICROSOFT_CLIENT_SECRET", "synthetic-secret")
    monkeypatch.setattr(api_module, "Microsoft365Adapter", LicensePendingGraph)
    monkeypatch.setattr(api_module, "graph_app_token", lambda **kwargs: (
        "synthetic-graph-token", datetime.now(timezone.utc) + timedelta(hours=1),
    ))
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(api_module.app) as client:
        headers = signup(client)
        source_id = create_source(client, headers)
        state = begin(client, headers, source_id)
        result = client.get(
            "/api/v1/current/sources/microsoft-admin-consent/callback",
            params={"state": state, "admin_consent": "True", "tenant": TENANT},
            follow_redirects=False,
        )
        assert result.status_code == 303
        assert "consent-failed" in result.headers["location"]
        with SessionLocal() as db:
            row = db.get(SourceConnection, source_id)
            assert row is not None
            assert row.status == "not_configured"
            assert row.last_error == "MICROSOFT_SHAREPOINT_SERVICE_NOT_READY"
        listed = client.get("/api/v1/current/sources", headers=headers)
        assert listed.status_code == 200
        assert "MICROSOFT_SHAREPOINT_SERVICE_NOT_READY" in listed.text
        assert "synthetic-graph-token" not in listed.text
        assert "synthetic-secret" not in listed.text


def test_microsoft_source_validation_keeps_provider_error_private(monkeypatch):
    from packages.connector_sdk.base import ProviderUnavailableError

    class BlockedMicrosoft:
        def __init__(self):
            self._client = self

        async def validate_connection(self):
            raise ProviderUnavailableError("MICROSOFT_SHAREPOINT_SERVICE_NOT_READY")

        async def aclose(self):
            pass

    monkeypatch.setattr(api_module, "create_source_adapter", lambda *args: BlockedMicrosoft())
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(api_module.app) as client:
        headers = signup(client)
        source_id = create_source(client, headers)
        result = client.post(f"/api/v1/sources/{source_id}/validate", headers=headers)
        assert result.status_code == 502
        with SessionLocal() as db:
            row = db.get(SourceConnection, source_id)
            assert row is not None
            assert row.last_error == "MICROSOFT_SHAREPOINT_SERVICE_NOT_READY"
        assert "synthetic-graph-token" not in result.text
