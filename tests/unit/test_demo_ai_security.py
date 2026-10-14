import asyncio

import pytest
from apps.demo_ai import app as demo
from apps.runner.accessproof_runner.main import _checkpoint_safe_job
from packages.connector_sdk.http_target import render_template
from packages.domain.models import Principal


def test_runner_checkpoint_redacts_identity_tokens():
    safe = _checkpoint_safe_job({"allowed_principal": {"external_id": "alice", "access_token": "alice-token"}, "denied_principal": {"external_id": "bob", "access_token": "bob-token"}})
    assert "access_token" not in safe["allowed_principal"]
    assert "access_token" not in safe["denied_principal"]


def test_session_and_principal_token_templates_render():
    principal = Principal("alice", email="alice@example.test", access_token="token-a", session_id="session-a")
    rendered = render_template({"Authorization": "Bearer {{ principal.access_token }}", "Session": "{{ session.id }}"}, prompt="question", principal=principal)
    assert rendered == {"Authorization": "Bearer token-a", "Session": "session-a"}


def test_oidc_discovery_uses_well_known_metadata_and_caches(monkeypatch):
    calls = []
    async def fake_json(url):
        calls.append(url)
        return {"issuer": "https://issuer.test", "jwks_uri": "https://issuer.test/keys"}
    monkeypatch.setattr(demo, "OIDC_ISSUER", "https://issuer.test")
    monkeypatch.setattr(demo, "_oidc_metadata", None)
    monkeypatch.setattr(demo, "_oidc_json", fake_json)
    first = asyncio.run(demo._oidc_discovery())
    second = asyncio.run(demo._oidc_discovery())
    assert first["jwks_uri"] == "https://issuer.test/keys" and second == first
    assert calls == ["https://issuer.test/.well-known/openid-configuration"]


@pytest.mark.parametrize(("claims", "expected"), [({"oid": "entra-oid", "sub": "generic-sub"}, "entra-oid"), ({"sub": "generic-sub"}, "generic-sub")])
def test_verified_oidc_identity_prefers_oid_and_ignores_body_user(monkeypatch, claims, expected):
    async def signing_key(token):
        return object(), "RS256"
    monkeypatch.setattr(demo, "REQUIRE_OIDC", True)
    monkeypatch.setattr(demo, "OIDC_ISSUER", "https://issuer.test")
    monkeypatch.setattr(demo, "OIDC_AUDIENCE", "api://test")
    monkeypatch.setattr(demo, "OIDC_REQUIRED_SCOPES", set())
    monkeypatch.setattr(demo, "_oidc_signing_key", signing_key)
    monkeypatch.setattr(demo.jwt, "decode", lambda *args, **kwargs: claims)
    assert asyncio.run(demo._authenticated_identity("Bearer a.valid.token", "attacker")) == expected
