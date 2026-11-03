"""Gateway -> actual Guard V2 -> signed mixed-source snapshots, no cloud mocks.

The model transport is synthetic; Guard HTTP routes and SQLite policies are real.
"""
from datetime import datetime, timedelta, timezone

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from apps.gateway.accessproof_gateway.app import GatewaySettings, create_app
from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache
from packages.demo_cache.trusted_snapshot import write_snapshot
from packages.rag_core import (
    SourceAttestationSigner, SourceAttestationVerifier, TrustedSourceIngestor,
    VerifiedSourceDocument,
)


def test_single_app_uses_two_sources_with_real_guard_and_blocks_inflight_revoke(tmp_path, monkeypatch):
    app_id, tenant = "mixed-enterprise-rag", "test-tenant"
    sources = ("google-test", "sharepoint-test")
    issuer, secret = "https://issuer.synthetic", "local-test-key-" + "k" * 48
    guard = PolicyCache(str(tmp_path / "guard.db"))
    guard.install(1, [
        {
            "subject_id": src_user, "source_id": src,
            "resource_id": "same-document-id", "decision": decision,
        }
        for src, users in (
            (sources[0], (("alice-g", "allow"), ("bob-g", "allow"))),
            (sources[1], (("alice-m", "allow"), ("bob-m", "deny"))),
        )
        for src_user, decision in users
    ])
    guard.set_application_bindings([{
        "application_id": app_id, "source_id": sources[0],
        "source_ids": list(sources), "mode": "protect",
        "source_acl_healthy": True,
        "source_health": {src: True for src in sources},
    }])
    guard.set_identity_mappings([
        {
            "source_id": src, "issuer": issuer, "tenant_id": tenant,
            "subject": user, "source_subject_id": f"{user}-{suffix}",
        }
        for src, suffix in ((sources[0], "g"), (sources[1], "m"))
        for user in ("alice", "bob")
    ])
    guard.set_authorization_revisions([{
        "application_id": app_id, "revision": 1,
        "revision_hash": "a" * 64, "generated_at": "2026-10-27T00:00:00Z",
    }])
    guard.mark_sync_success()
    for name, value in {
        "cache": guard, "identity_mode": "static", "issuer": issuer,
        "audience": "rag-test", "subject_claim": "sub",
        "verification_key": secret, "expected_tenant": tenant,
        "_sync_error": None, "guard_id": None, "guard_credential": None,
        "control_plane_url": None, "max_policy_age_seconds": 180,
    }.items():
        monkeypatch.setattr(guard_app, name, value)
    monkeypatch.setenv("ACCESSPROOF_ENV", "development")

    keys = {src: Ed25519PrivateKey.generate() for src in sources}
    snapshots = {}
    for source in sources:
        chunks = TrustedSourceIngestor(SourceAttestationSigner(
            key_id=source, private_key=keys[source],
        )).attest_document(VerifiedSourceDocument(
            tenant_id=tenant, application_id=app_id, source_id=source,
            resource_id="same-document-id", content_version="rev1",
            content="SYNTHETIC_" + source + "_CONFIDENTIAL",
            provider_identity_verified=True,
        ))
        path = tmp_path / (source + ".json")
        write_snapshot(path, tenant_id=tenant, application_id=app_id,
                       source_id=source, resources=chunks)
        snapshots[source] = path

    seen = {"model_calls": [], "revoke_at_model": False, "v2_calls": []}
    with TestClient(guard_app.app) as guard_client:
        def handle(request: httpx.Request) -> httpx.Response:
            if request.url.path.startswith("/guard/"):
                seen["v2_calls"].append(request.url.path)
                result = guard_client.request(
                    request.method, request.url.path, content=request.content,
                    headers={"Authorization": request.headers.get("Authorization", ""), "Content-Type": request.headers.get("Content-Type", "")},
                )
                return httpx.Response(result.status_code, content=result.content)
            assert request.url.path == "/v1/chat/completions"
            seen["model_calls"].append(request.content.decode())
            if seen["revoke_at_model"]:
                guard.install(2, [{
                    "subject_id": "alice-m", "source_id": sources[1],
                    "resource_id": "same-document-id", "decision": "deny",
                }])
            return httpx.Response(200, json={
                "choices": [{"message": {"content": "SYNTHETIC_RESPONSE"},
                             "finish_reason": "stop"}],
            })

        settings = GatewaySettings(
            guard_url="https://guard.synthetic",
            model_url="https://model.synthetic/v1/chat/completions",
            application_id=app_id, tenant_id=tenant,
            verifier=SourceAttestationVerifier(tenant_id=tenant, trusted_keys={
                src: key.public_key() for src, key in keys.items()
            }),
            source_snapshots=snapshots, multisource_guard_v2=True,
        )
        def token(user: str):
            return jwt.encode({
                "iss": issuer, "aud": "rag-test", "sub": user, "tid": tenant,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
            }, secret, algorithm="HS256")
        with TestClient(create_app(settings, client=httpx.Client(
            transport=httpx.MockTransport(handle),
        ))) as gateway:
            def call(user: str, selection=list(sources)):
                return gateway.post("/v1/snapshots/chat/completions", headers={
                    "Authorization": "Bearer " + token(user),
                }, json={
                    "application_id": app_id, "employee_question": "What is accessible?",
                    "source_ids": selection,
                })
            alice = call("alice")
            assert alice.status_code == 200, alice.text
            assert all(("SYNTHETIC_" + src) in seen["model_calls"][-1] for src in sources)
            bob = call("bob")
            assert bob.status_code == 200, bob.text
            assert "SYNTHETIC_google-test" in seen["model_calls"][-1]
            assert "SYNTHETIC_sharepoint-test" not in seen["model_calls"][-1]
            # V2 remains selected for a single source on a multi-source app.
            assert call("alice", selection=[sources[0]]).status_code == 200
            seen["revoke_at_model"] = True
            response = call("alice")
            assert response.status_code in {403, 503}
            assert "SYNTHETIC_RESPONSE" not in response.text
            assert "/guard/v2/filter-resources" in seen["v2_calls"]
            assert "/guard/v2/check-output" in seen["v2_calls"]
    guard.db.close()
