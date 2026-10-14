from __future__ import annotations

from fastapi.testclient import TestClient

from apps.api.accessproof_api import app as app_module
from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, Membership, SessionLocal, User, engine
from packages.auth.oidc import OidcDiscovery
from packages.crypto.passwords import hash_password


class FakeOidcProvider:
    claims = {
        "sub": "subject-bob",
        "email": "bob@example.com",
        "email_verified": True,
        "groups": ["engineering"],
    }

    def __init__(self, issuer_url: str):
        self.issuer_url = issuer_url.rstrip("/")

    def close(self):
        return None

    def discovery(self):
        return OidcDiscovery(
            issuer=self.issuer_url,
            authorization_endpoint=f"{self.issuer_url}/authorize",
            token_endpoint=f"{self.issuer_url}/token",
            jwks_uri=f"{self.issuer_url}/jwks",
        )

    @staticmethod
    def new_pkce():
        return "verifier", "challenge"

    @staticmethod
    def authorization_url(discovery, *, client_id, redirect_uri, state, nonce, code_challenge):
        return f"{discovery.authorization_endpoint}?client_id={client_id}&state={state}&nonce={nonce}&code_challenge={code_challenge}"

    def exchange_code(self, discovery, **kwargs):
        assert kwargs["client_secret"] == "client-secret"
        assert kwargs["code_verifier"] == "verifier"
        return {"id_token": "signed-id-token"}

    def validate_id_token(self, discovery, **kwargs):
        assert kwargs["id_token"] == "signed-id-token"
        assert kwargs["client_id"] == "client-id"
        return dict(self.claims)


def _signup(client: TestClient):
    r = client.post(
        "/api/v1/auth/signup",
        json={
            "email": "owner@example.com",
            "password": "VeryStrongPass123!",
            "organization_name": "OIDC Org",
        },
    )
    assert r.status_code == 201
    body = r.json()
    return body["organization_id"], {
        "Authorization": f"Bearer {body['session_token']}",
        "X-Organization-ID": body["organization_id"],
    }


def test_oidc_config_begin_callback_autoprovisions_and_enforces_sso(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(app_module, "OidcProviderClient", FakeOidcProvider)
    with TestClient(app) as client:
        org_id, owner_headers = _signup(client)
        cfg = client.put(
            "/api/v1/auth/oidc/config",
            headers=owner_headers,
            json={
                "issuer_url": "https://idp.example.com",
                "client_id": "client-id",
                "client_secret": "client-secret",
                "allowed_domains": ["example.com"],
                "role_claim": "groups",
                "role_mapping": {"engineering": "ENGINEER"},
                "default_role": "VIEWER",
                "enforced": True,
            },
        )
        assert cfg.status_code == 200, cfg.text
        assert cfg.json()["enforced"] is True
        assert "client_secret" not in cfg.json()

        begin = client.post("/api/v1/auth/oidc/begin", json={"organization_id": org_id})
        assert begin.status_code == 200, begin.text
        state = begin.json()["state"]
        assert "code_challenge=challenge" in begin.json()["authorization_url"]

        callback = client.post(
            "/api/v1/auth/oidc/callback", json={"code": "authorization-code", "state": state}
        )
        assert callback.status_code == 200, callback.text
        body = callback.json()
        assert body["role"] == "ENGINEER"

        # The SSO-origin session is valid for the enforced organization.
        projects = client.get(
            "/api/v1/projects",
            headers={
                "Authorization": f"Bearer {body['session_token']}",
                "X-Organization-ID": org_id,
            },
        )
        assert projects.status_code == 200

        # State is one-time and cannot be replayed.
        replay = client.post(
            "/api/v1/auth/oidc/callback", json={"code": "authorization-code", "state": state}
        )
        assert replay.status_code == 400


def test_enforced_sso_blocks_member_password_but_owner_is_break_glass(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(app_module, "OidcProviderClient", FakeOidcProvider)
    with TestClient(app) as client:
        org_id, owner_headers = _signup(client)
        cfg = client.put(
            "/api/v1/auth/oidc/config",
            headers=owner_headers,
            json={
                "issuer_url": "https://idp.example.com",
                "client_id": "client-id",
                "client_secret": "client-secret",
                "allowed_domains": ["example.com"],
                "default_role": "ENGINEER",
                "enforced": True,
            },
        )
        assert cfg.status_code == 200
        with SessionLocal() as db:
            user = User(
                email="engineer@example.com",
                password_hash=hash_password("EngineerPass123!"),
                email_verified=True,
            )
            db.add(user)
            db.flush()
            db.add(Membership(user_id=user.id, organization_id=org_id, role="ENGINEER"))
            db.commit()

        blocked = client.post(
            "/api/v1/auth/login",
            json={
                "email": "engineer@example.com",
                "password": "EngineerPass123!",
                "organization_id": org_id,
            },
        )
        assert blocked.status_code == 403
        assert blocked.json()["detail"]["code"] == "sso_required"

        owner = client.post(
            "/api/v1/auth/login",
            json={
                "email": "owner@example.com",
                "password": "VeryStrongPass123!",
                "organization_id": org_id,
            },
        )
        assert owner.status_code == 200


def test_browser_oidc_get_callback_sets_session_and_redirects(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(app_module, "OidcProviderClient", FakeOidcProvider)
    with TestClient(app, follow_redirects=False) as client:
        org_id, owner_headers = _signup(client)
        cfg = client.put(
            "/api/v1/auth/oidc/config",
            headers=owner_headers,
            json={
                "issuer_url": "https://idp.example.com",
                "client_id": "client-id",
                "client_secret": "client-secret",
                "allowed_domains": ["example.com"],
                "default_role": "ENGINEER",
                "enforced": True,
            },
        )
        assert cfg.status_code == 200
        begin = client.post("/api/v1/auth/oidc/begin", json={"organization_id": org_id})
        state = begin.json()["state"]
        callback = client.get(
            "/api/v1/auth/oidc/callback", params={"code": "authorization-code", "state": state}
        )
        assert callback.status_code == 303
        assert f"organization_id={org_id}" in callback.headers["location"]
        assert "accessproof_session=" in callback.headers.get("set-cookie", "")
