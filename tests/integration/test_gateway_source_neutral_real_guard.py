"""One Gateway implementation reused for SharePoint and Drive with REAL Guard.

The sources are separate app bindings because the production Guard does not
allow multiple source IDs under the same application. No live cloud calls.
"""
from __future__ import annotations

import json
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


def test_same_gateway_code_enforces_each_real_guard_app_source_binding(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    guard = PolicyCache(str(tmp_path / "source-neutral-guard.db"))
    tenant = "tenant-test"
    identity_issuer = "https://employee.synthetic"
    secret = "local-only-guard-testing-static-key-32-characters"
    apps = {"google-drive": "rag-google", "sharepoint": "rag-sharepoint"}
    guard.install(1, [
        {"subject_id": person, "source_id": source,
         "resource_id": "approved-doc", "decision": "allow" if person == "alice" else "deny"}
        for source in apps for person in ("alice", "bob")
    ], full_snapshot=True)
    guard.set_application_bindings([
        {"application_id": app, "source_id": source,
         "mode": "protect", "source_acl_healthy": True}
        for source, app in apps.items()
    ])
    guard.set_identity_mappings([
        {"source_id": source, "issuer": identity_issuer, "subject": person,
         "tenant_id": tenant, "source_subject_id": person}
        for source in apps for person in ("alice", "bob")
    ])
    guard.mark_sync_success()
    for name, value in {
        "cache": guard, "identity_mode": "static", "issuer": identity_issuer,
        "audience": "rag-customer-test", "subject_claim": "sub",
        "verification_key": secret, "expected_tenant": tenant,
        "_sync_error": None, "guard_id": None, "guard_credential": None,
        "control_plane_url": None, "max_policy_age_seconds": 180,
    }.items():
        monkeypatch.setattr(guard_app, name, value)

    model_inputs: list[str] = []
    with TestClient(guard_app.app) as guard_client:
        def handle(request: httpx.Request) -> httpx.Response:
            if request.url.path.startswith("/guard/"):
                response = guard_client.request(
                    request.method, request.url.path, content=request.content,
                    headers={"Authorization": request.headers.get("Authorization", "")},
                )
                return httpx.Response(response.status_code, content=response.content)
            assert request.url.path == "/v1/chat/completions"
            model_inputs.append(json.dumps(request.content.decode()))
            return httpx.Response(200, json={
                "choices": [{"message": {"content": "SYNTHETIC_AUTHORIZED_RESPONSE"},
                             "finish_reason": "stop"}],
            })

        def token(user: str) -> str:
            return jwt.encode({
                "iss": identity_issuer, "aud": "rag-customer-test", "sub": user,
                "tid": tenant,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
            }, secret, algorithm="HS256")

        for source, app_id in apps.items():
            chunk = TrustedSourceIngestor(SourceAttestationSigner(
                key_id="ingester", private_key=key,
            )).attest_document(VerifiedSourceDocument(
                tenant_id=tenant, application_id=app_id, source_id=source,
                resource_id="approved-doc", content_version="source-etag-1",
                content=f"SYNTHETIC_{source}_DOCUMENT", provider_identity_verified=True,
            ))
            source_file = tmp_path / (source + ".json")
            write_snapshot(source_file, tenant_id=tenant, application_id=app_id,
                           source_id=source, resources=chunk)
            settings = GatewaySettings(
                guard_url="https://guard.synthetic",
                model_url="https://model.synthetic/v1/chat/completions",
                application_id=app_id, tenant_id=tenant,
                verifier=SourceAttestationVerifier(tenant_id=tenant, trusted_keys={
                    "ingester": key.public_key(),
                }),
                source_snapshots={source: source_file},
            )
            with TestClient(create_app(settings, client=httpx.Client(
                transport=httpx.MockTransport(handle),
            ))) as gateway:
                def call(user: str, requested_source: str):
                    return gateway.post("/v1/snapshots/chat/completions", headers={
                        "Authorization": "Bearer " + token(user),
                    }, json={"application_id": app_id, "employee_question": "Tell me about it",
                             "source_ids": [requested_source]})

                allowed = call("alice", source)
                assert allowed.status_code == 200, allowed.text
                assert "SYNTHETIC_AUTHORIZED_RESPONSE" in allowed.text
                assert f"SYNTHETIC_{source}_DOCUMENT" in model_inputs[-1]
                before = len(model_inputs)
                denied = call("bob", source)
                assert denied.status_code == 403, denied.text
                assert len(model_inputs) == before
                assert "SYNTHETIC_AUTHORIZED_RESPONSE" not in denied.text
        # These tests do not assume a single app's Guard binding can mix
        # source IDs, identities, and policy revisions.
    guard.db.close()
