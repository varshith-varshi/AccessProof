"""A real three-service TCP test: Guard, model, Gateway on loopback.

This establishes a local *reference* enforcement boundary, not the
production equivalence of an arbitrary customer application's RAG route.
"""
from __future__ import annotations

import socket
import json
import threading
import time
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Request

from apps.gateway.accessproof_gateway.app import GatewaySettings, create_app
from apps.gateway.accessproof_gateway.challenge_agent import GatewayRouteChallenge, Probe
from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache
from packages.rag_sdk import (
    SourceAttestationSigner, SourceAttestationVerifier, TrustedSourceIngestor,
    VerifiedSourceDocument,
)


def _port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _serve(app: FastAPI, port: int) -> tuple[uvicorn.Server, threading.Thread]:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
                                           log_level="critical", lifespan="off"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 6
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started
    return server, thread


def test_gateway_real_tcp_allow_deny_tamper_and_inflight_revocation(monkeypatch, tmp_path) -> None:
    source = "customer-drive"
    application = "customer-rag"
    policy = PolicyCache(str(tmp_path / "tcp-guard.db"))
    policy.install(1, [
        {"subject_id": "alice", "source_id": source, "resource_id": "public", "decision": "allow"},
        {"subject_id": "alice", "source_id": source, "resource_id": "private", "decision": "deny"},
        {"subject_id": "bob", "source_id": source, "resource_id": "public", "decision": "deny"},
        {"subject_id": "bob", "source_id": source, "resource_id": "private", "decision": "deny"},
    ], full_snapshot=True)
    policy.set_application_bindings([{
        "application_id": application, "source_id": source, "mode": "protect",
        "source_acl_healthy": True,
    }])
    policy.mark_sync_success()
    issuer_key = "synthetic-tcp-identity-issuer-key-32"
    for name, value in {
        "cache": policy, "identity_mode": "static", "issuer": "https://issuer.local",
        "audience": application, "verification_key": issuer_key,
        "expected_tenant": "alpha", "subject_claim": "sub", "guard_id": None,
        "guard_credential": None, "control_plane_url": None,
        "max_policy_age_seconds": 300,
    }.items():
        monkeypatch.setattr(guard_app, name, value)
    # Other TestClient lifespans in the same pytest process can leave this
    # module-global diagnostic value from their isolated, unconfigured Guard.
    # This real-TCP harness owns a healthy disposable policy/cache, so reset
    # the diagnostic state just as a successful control-plane poll would.
    monkeypatch.setattr(guard_app, "_sync_error", None)

    guard_port, model_port, gateway_port = _port(), _port(), _port()
    server_guard, thread_guard = _serve(guard_app.app, guard_port)
    seen_model_inputs: list[str] = []
    revoke_on_generation = [False]
    model = FastAPI()

    @model.post("/v1/chat/completions")
    async def mock_model(request: Request) -> dict:
        payload = await request.json()
        seen_model_inputs.append(str(payload))
        if revoke_on_generation[0] or "layer2_revoke" in json.dumps(payload):
            policy.install(policy.version() + 1, [
                {"subject_id": "alice", "source_id": source,
                 "resource_id": "public", "decision": "deny"},
            ])
            revoke_on_generation[0] = False
        return {"choices": [{"message": {"content": "PUBLIC_REFERENCE_RESULT"}}]}

    server_model, thread_model = _serve(model, model_port)

    private = Ed25519PrivateKey.generate()
    signer = SourceAttestationSigner(key_id="ingester", private_key=private)
    trusted = TrustedSourceIngestor(signer)
    def source_resource(resource_id: str, value: str) -> dict:
        chunks = trusted.attest_document(VerifiedSourceDocument(
            tenant_id="alpha", application_id=application, source_id=source,
            resource_id=resource_id, content_version="1", content=value,
            provider_identity_verified=True,
        ))
        return {
            "source_id": chunks[0].source_id,
            "resource_id": chunks[0].resource_id,
            "chunk_id": chunks[0].chunk_id,
            "content": chunks[0].content,
            "content_version": chunks[0].content_version,
            "content_attestation": chunks[0].content_attestation,
        }
    public = source_resource("public", "PUBLIC_APPROVED_CONTENT")
    confidential = source_resource("private", "CONFIDENTIAL_PRIVATE_CANARY")

    gateway_settings = GatewaySettings(
        guard_url=f"http://127.0.0.1:{guard_port}",
        model_url=f"http://127.0.0.1:{model_port}/v1/chat/completions",
        application_id=application, tenant_id="alpha",
        verifier=SourceAttestationVerifier(tenant_id="alpha", trusted_keys={
            "ingester": private.public_key(),
        }),
    )
    gateway = create_app(gateway_settings)
    server_gateway, thread_gateway = _serve(gateway, gateway_port)

    def token(subject: str) -> str:
        return jwt.encode({
            "sub": subject, "tid": "alpha", "iss": "https://issuer.local",
            "aud": application, "exp": datetime.now(timezone.utc) + timedelta(minutes=3),
        }, issuer_key, algorithm="HS256")

    def call(client: httpx.Client, subject: str, resources: list[dict]) -> httpx.Response:
        return client.post("/v1/chat/completions",
            headers={"Authorization": f"Bearer {token(subject)}"},
            json={"application_id": application, "employee_question": "Summarize",
                  "retrieved_resources": resources})
    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{gateway_port}",
                          timeout=4, follow_redirects=False, trust_env=False) as client:
            allowed = call(client, "alice", [public, confidential])
            assert allowed.status_code == 200, allowed.text
            assert "PUBLIC_REFERENCE_RESULT" in allowed.text
            assert "CONFIDENTIAL_PRIVATE_CANARY" not in allowed.text
            assert len(seen_model_inputs) == 1
            assert "PUBLIC_APPROVED_CONTENT" in seen_model_inputs[0]
            assert "CONFIDENTIAL_PRIVATE_CANARY" not in seen_model_inputs[0]

            denied = call(client, "bob", [public, confidential])
            assert denied.status_code == 403, denied.text
            assert "CONFIDENTIAL_PRIVATE_CANARY" not in denied.text
            assert len(seen_model_inputs) == 1

            forged = dict(public, content="SECRET_REPLACED_DOCUMENT")
            tampered = call(client, "alice", [forged])
            assert tampered.status_code == 503
            assert "SECRET_REPLACED_DOCUMENT" not in tampered.text
            assert len(seen_model_inputs) == 1

            # Revoke while the mock model is generating: Layer 2 must block.
            revoke_on_generation[0] = True
            with client.stream("POST", "/v1/chat/completions",
                headers={"Authorization": f"Bearer {token('alice')}"},
                json={"application_id": application, "employee_question": "Summarize",
                      "retrieved_resources": [public]}) as response:
                released_bytes = b"".join(response.iter_bytes())
                assert response.status_code in (403, 503)
                assert b"PUBLIC_REFERENCE_RESULT" not in released_bytes

            after_revocation = call(client, "alice", [public])
            assert after_revocation.status_code == 403
            assert "PUBLIC_REFERENCE_RESULT" not in after_revocation.text
            # Restore a new synthetic allow revision for the independent
            # customer-side HTTP byte observer; its last challenge causes
            # revocation *during* generation, again blocking Layer 2 release.
            policy.install(policy.version() + 1, [
                {"subject_id": "alice", "source_id": source,
                 "resource_id": "public", "decision": "allow"},
            ])
            forged_again = dict(public, content="UNSIGNED_PRIVATE_CONTENT")
            challenge = GatewayRouteChallenge(
                url=f"http://127.0.0.1:{gateway_port}/v1/chat/completions",
                application_id=application, challenge_nonce="c" * 40,
                forbidden_canary="CONFIDENTIAL_PRIVATE_CANARY",
                allowed_canary="PUBLIC_REFERENCE_RESULT",
                probes=(
                    Probe("allow", token("alice"), [public, confidential], (200,), "PUBLIC_REFERENCE_RESULT"),
                    Probe("deny", token("bob"), [public, confidential], (403,)),
                    Probe("tamper", token("alice"), [forged_again], (503,)),
                    Probe("layer2_revoke", token("alice"), [public], (403,)),
                ),
            )
            result = challenge.run(client=client)
            assert result["status"] == "PASS_LOCAL_REFERENCE_ONLY"
            assert result["production_certification"] is False
            assert len(result["probes"]) == 4
            assert policy.version() >= 4
    finally:
        for server in (server_gateway, server_model, server_guard):
            server.should_exit = True
        for thread in (thread_gateway, thread_model, thread_guard):
            thread.join(timeout=6)
        policy.db.close()
