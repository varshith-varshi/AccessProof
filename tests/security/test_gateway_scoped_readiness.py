"""Gateway readiness is not another application's Guard readiness."""
from __future__ import annotations

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from apps.gateway.accessproof_gateway.app import GatewaySettings, create_app
from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache
from packages.rag_core import SourceAttestationVerifier


def test_guard_health_checks_selected_application_binding_and_source(tmp_path, monkeypatch):
    cache = PolicyCache(str(tmp_path / "scoped-ready.db"))
    cache.install(1, [{"subject_id": "employee-a", "source_id": "drive-a",
                       "resource_id": "document-a", "decision": "allow"}])
    cache.set_application_bindings([
        {"application_id": "ready-rag", "source_id": "drive-a",
         "mode": "protect", "source_acl_healthy": True},
    ])
    cache.mark_sync_success()
    for key, value in {
        "cache": cache, "control_plane_url": "https://control.example",
        "guard_id": "enrolled-guard", "guard_credential": "synthetic-machine-only",
        "_sync_error": None,
    }.items():
        monkeypatch.setattr(guard_app, key, value)
    with TestClient(guard_app.app) as client:
        assert client.get("/health").json()["ready"] is True
        assert client.get("/health", params={"application_id": "ready-rag"}).json()["ready"] is True
        unrelated = client.get("/health", params={"application_id": "unrelated-rag"})
        assert unrelated.status_code == 200
        assert unrelated.json()["ready"] is False
        assert unrelated.json()["status"] == "degraded"

        cache.set_application_bindings([
            {"application_id": "ready-rag", "source_id": "drive-a",
             "mode": "shadow", "source_acl_healthy": True},
        ])
        assert client.get("/health", params={"application_id": "ready-rag"}).json()["ready"] is False

        cache.set_application_bindings([
            {"application_id": "ready-rag", "source_id": "drive-a",
             "mode": "protect", "source_acl_healthy": False},
        ])
        assert client.get("/health", params={"application_id": "ready-rag"}).json()["ready"] is False
    cache.db.close()


@pytest.mark.parametrize(("guard_ready", "expected_status"), [
    (True, 200),
    (False, 503),
])
def test_gateway_readiness_forwards_only_its_own_app_id(guard_ready, expected_status):
    signer = Ed25519PrivateKey.generate()
    seen = []
    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.url.path == "/health"
        assert request.url.params["application_id"] == "selected-rag"
        assert "authorization" not in request.headers
        return httpx.Response(200, json={
            "status": "ok" if guard_ready else "degraded",
            "ready": guard_ready,
            "policy_version": 1,
        })

    settings = GatewaySettings(
        guard_url="http://guard:8080", model_url="http://model:8000/v1/chat/completions",
        tenant_id="tenant-a", application_id="selected-rag",
        verifier=SourceAttestationVerifier(
            tenant_id="tenant-a", trusted_keys={"source": signer.public_key()},
        ),
    )
    mock = httpx.Client(transport=httpx.MockTransport(respond))
    with TestClient(create_app(settings, client=mock)) as gateway:
        assert gateway.get("/health/ready").status_code == expected_status
    assert len(seen) == 1


def test_gateway_ready_refuses_other_app_even_when_guard_global_health_ok():
    signer = Ed25519PrivateKey.generate()
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "status": "ok", "ready": request.url.params.get("application_id") == "some-other-app",
        })

    settings = GatewaySettings(
        guard_url="http://guard:8080", model_url="http://model:8000/v1/chat/completions",
        tenant_id="tenant-a", application_id="selected-rag",
        verifier=SourceAttestationVerifier(
            tenant_id="tenant-a", trusted_keys={"source": signer.public_key()},
        ),
    )
    with TestClient(create_app(settings, client=httpx.Client(
        transport=httpx.MockTransport(respond),
    ))) as gateway:
        assert gateway.get("/health/ready").status_code == 503


def test_production_guard_fails_closed_until_revisions_and_identity_mapping_synced(
    tmp_path, monkeypatch,
):
    from fastapi import HTTPException

    monkeypatch.setenv("ACCESSPROOF_ENV", "production")
    state = PolicyCache(str(tmp_path / "prod-no-revision.db"))
    state.install(1, [{"subject_id": "workspace-alice", "source_id": "google-drive",
                       "resource_id": "file-a", "decision": "allow"}])
    state.set_application_bindings([
        {"application_id": "production-rag", "source_id": "google-drive",
         "mode": "protect", "source_acl_healthy": True},
    ])
    state.mark_sync_success()
    for key, value in {
        "cache": state, "control_plane_url": "https://control.example",
        "guard_id": "enrolled-guard", "guard_credential": "synthetic-only",
        "_sync_error": None,
    }.items():
        monkeypatch.setattr(guard_app, key, value)

    with TestClient(guard_app.app) as client:
        assert client.get("/health", params={
            "application_id": "production-rag",
        }).json()["ready"] is False
        with pytest.raises(HTTPException) as missing_revision:
            guard_app._application_mode("production-rag")
        assert missing_revision.value.status_code == 503
        assert missing_revision.value.detail == "AUTHORIZATION_REVISION_NOT_SYNCED"

        state.set_authorization_revisions([{
            "application_id": "production-rag", "revision": 1,
            "revision_hash": "b" * 64, "generated_at": "2026-10-26T00:00:00Z",
        }])
        # Authorization revision alone is not enough. A configured production
        # Guard still cannot map a verified employee to its Drive identity.
        assert client.get("/health", params={
            "application_id": "production-rag",
        }).json()["ready"] is False
        state.set_identity_mappings([{
            "source_id": "google-drive", "issuer": "https://idp.example",
            "subject": "employee-alice", "tenant_id": "tenant-a",
            "source_subject_id": "workspace-alice",
        }])
        assert client.get("/health", params={
            "application_id": "production-rag",
        }).json()["ready"] is True
        assert guard_app._application_mode("production-rag") == ("protect", "google-drive")
    state.db.close()
