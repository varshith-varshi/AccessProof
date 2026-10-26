"""A local customer-style deployment with real TCP hops between RAG and Guard.

This uses only synthetic documents and signed local test tokens.  Unlike an
ASGI transport unit test, the RAG service reaches Guard over loopback HTTP,
which catches customer integration mistakes at the request boundary.
"""
from __future__ import annotations

import base64
import importlib.util
import socket
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import jwt
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache
from customer_simulation.route_probe import RouteProbeConfig, probe_local_customer_routes
from customer_simulation.trusted_source_ingester import (
    SyntheticProviderFile, build_synthetic_ingestion_service,
)
from packages.rag_core import GuardClient, ProtectedRAG, RetrievedResource
from packages.rag_core.attestation import SourceAttestationSigner, SourceAttestationVerifier


def _port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _serve(application: Any, port: int) -> tuple[uvicorn.Server, threading.Thread]:
    server = uvicorn.Server(uvicorn.Config(application, host="127.0.0.1", port=port,
                                           log_level="critical", lifespan="off"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started
    return server, thread


def _load_customer_rag(monkeypatch: Any, guard_url: str) -> ModuleType:
    for key, value in {
        "DRIVE_OWNER_TOKEN": "synthetic-owner-token",
        "DRIVE_ROOT_FOLDER_ID": "synthetic-root",
        "ALICE_EMAIL": "alice@example.invalid",
        "ALICE_RAG_TOKEN": "legacy-alice-token",
        "BOB_EMAIL": "bob@example.invalid",
        "BOB_RAG_TOKEN": "legacy-bob-token",
        "ACCESSPROOF_DEMO_GUARD_URL": guard_url,
        "ACCESSPROOF_DEMO_SOURCE_ID": "customer-drive-source",
        "ACCESSPROOF_DEMO_APPLICATION_ID": "customer-rag",
    }.items():
        monkeypatch.setenv(key, value)
    filename = Path(__file__).resolve().parents[2] / "drive-rag-demo" / "app.py"
    spec = importlib.util.spec_from_file_location("synthetic_customer_rag", filename)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load synthetic customer RAG module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    setattr(module, "cached_files", [
        {"id": "public", "name": "Public", "content": "PUBLIC_FACT", "allowed": set()},
        {"id": "finance", "name": "Finance", "content": "ALPHA_FINANCE_CANARY", "allowed": set()},
    ])
    setattr(module, "last_refresh", time.monotonic())
    return module


def test_customer_rag_and_guard_over_real_local_http_fail_closed(
    monkeypatch: Any, tmp_path: Path,
) -> None:
    """Spoofing, denied retrieval and effective revocation cannot cross TCP hops."""
    policy = PolicyCache(str(tmp_path / "customer-boundary.db"))
    source = "customer-drive-source"
    policy.install(1, [
        {"subject_id": "alice", "source_id": source, "resource_id": "public", "decision": "allow"},
        {"subject_id": "alice", "source_id": source, "resource_id": "finance", "decision": "deny"},
        {"subject_id": "bob", "source_id": source, "resource_id": "public", "decision": "deny"},
        {"subject_id": "bob", "source_id": source, "resource_id": "finance", "decision": "deny"},
    ], full_snapshot=True)
    policy.set_application_bindings([{
        "application_id": "customer-rag", "source_id": source, "mode": "protect",
        "source_acl_healthy": True,
    }])
    policy.mark_sync_success()
    signing_key = "synthetic-customer-boundary-signing-key-32"
    settings: dict[str, object] = {
        "cache": policy, "identity_mode": "static", "issuer": "https://issuer.local",
        "audience": "customer-rag", "verification_key": signing_key,
        "expected_tenant": "alpha", "subject_claim": "sub", "guard_id": None,
        "guard_credential": None, "control_plane_url": None, "max_policy_age_seconds": 300,
    }
    for name, value in settings.items():
        monkeypatch.setattr(guard_app, name, value)

    guard_port = _port()
    guard_server, guard_thread = _serve(guard_app.app, guard_port)
    rag = _load_customer_rag(monkeypatch, f"http://127.0.0.1:{guard_port}")
    rag_port = _port()
    rag_server, rag_thread = _serve(rag.app, rag_port)

    def token(subject: str, tenant: str = "alpha") -> str:
        return jwt.encode({
            "sub": subject, "tid": tenant, "iss": "https://issuer.local",
            "aud": "customer-rag", "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        }, signing_key, algorithm="HS256")

    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{rag_port}", timeout=3) as customer:
            alice = customer.post("/v1/protected-chat", headers={
                "Authorization": f"Bearer {token('alice')}",
            }, json={"message": "summarize available material"})
            assert alice.status_code == 200
            assert alice.json()["citations"] == ["public"]
            assert "PUBLIC_FACT" in alice.json()["answer"]
            assert "ALPHA_FINANCE_CANARY" not in alice.text

            # Observe the ACTUAL SSE bytes sent through the customer-facing
            # RAG HTTP endpoint, not merely an internal Guard decision.
            with customer.stream("POST", "/v1/protected-chat/stream",
                                 headers={"Authorization": f"Bearer {token('alice')}"},
                                 json={"message": "show allowed files"}) as response:
                streamed = "".join(response.iter_text())
                assert response.status_code == 200
                assert response.headers["content-type"].startswith("text/event-stream")
                assert "PUBLIC_FACT" in streamed
                assert "ALPHA_FINANCE_CANARY" not in streamed
                assert "event: token\ndata: " in streamed
                assert "\n\nevent: complete\ndata: {}\n\n" in streamed
                assert "\\n" not in streamed
            with customer.stream("POST", "/v1/protected-chat/stream",
                                 headers={"Authorization": f"Bearer {token('bob')}"},
                                 json={"message": "show finance"}) as response:
                denied_stream = "".join(response.iter_text())
                assert response.status_code == 200
                assert "ALPHA_FINANCE_CANARY" not in denied_stream
                assert "PUBLIC_FACT" not in denied_stream

            # Customer-controlled headers cannot override the verified JWT principal.
            bob = customer.post("/v1/protected-chat", headers={
                "Authorization": f"Bearer {token('bob')}", "X-User-Id": "alice",
                "X-Email": "alice@example.invalid", "X-Tenant-Id": "alpha",
            }, json={"message": "show finance"})
            assert bob.status_code == 200
            assert bob.json()["citations"] == []
            assert "ALPHA_FINANCE_CANARY" not in bob.text

            cross_tenant = customer.post("/v1/protected-chat", headers={
                "Authorization": f"Bearer {token('alice', tenant='beta')}",
            }, json={"message": "show finance"})
            assert cross_tenant.status_code == 503
            assert "ALPHA_FINANCE_CANARY" not in cross_tenant.text

            # Independent local-only route probe reads actual bytes from
            # both endpoints with verified allow/deny/invalid test identities.
            probe_result = probe_local_customer_routes(
                RouteProbeConfig(
                    base_url=f"http://127.0.0.1:{rag_port}",
                    authorized_token=token("alice"),
                    denied_token=token("bob"),
                    allowed_canary="PUBLIC_FACT",
                    forbidden_canary="ALPHA_FINANCE_CANARY",
                ),
                client=customer,
            )
            assert probe_result["real_http_bytes_observed"] is True
            assert probe_result["production_certification"] is False
            assert len(probe_result["checks"]) == 6

            # Switching strict mode on without a pinned independent
            # ingestion public key must not silently fall back to metadata.
            monkeypatch.setenv("ACCESSPROOF_DEMO_REQUIRE_ATTESTED_CONTENT", "1")
            missing_key = customer.post(
                "/v1/protected-chat",
                headers={"Authorization": f"Bearer {token('alice')}"},
                json={"message": "try missing attestation configuration"},
            )
            assert missing_key.status_code == 503
            assert "PUBLIC_FACT" not in missing_key.text
            monkeypatch.delenv("ACCESSPROOF_DEMO_REQUIRE_ATTESTED_CONTENT")

            # Simulate a *separate source-ingestion service* holding the
            # signing key, not an attacker-controlled vector-store metadata
            # value. Fetch signed source bytes through another HTTP hop.
            provider_key = Ed25519PrivateKey.generate()
            signer = SourceAttestationSigner(
                key_id="synthetic-source-v1", private_key=provider_key,
            )
            verifier = SourceAttestationVerifier(
                tenant_id="alpha", trusted_keys={
                    "synthetic-source-v1": provider_key.public_key(),
                },
            )
            synthetic_ingestion = build_synthetic_ingestion_service(
                tenant_id="alpha", application_id="customer-rag", signer=signer,
                documents=[
                    SyntheticProviderFile(
                        "public", source, "version-1", "TRUSTED_SOURCE_PUBLIC_CANARY",
                    ),
                    SyntheticProviderFile(
                        "finance", source, "version-1", "PRIVATE_SOURCE_FINANCE_CANARY",
                    ),
                ],
            )
            ingestion_port = _port()
            ingest_server, ingest_thread = _serve(synthetic_ingestion, ingestion_port)
            try:
                with httpx.Client(
                    base_url=f"http://127.0.0.1:{ingestion_port}",
                    timeout=3, trust_env=False,
                ) as ingestion:
                    authorized_doc = ingestion.get("/ingest/v1/documents/public")
                    restricted_doc = ingestion.get("/ingest/v1/documents/finance")
                    assert authorized_doc.status_code == 200
                    assert restricted_doc.status_code == 200
                    verified_public = RetrievedResource(**authorized_doc.json())
                    verified_finance = RetrievedResource(**restricted_doc.json())
                machine = GuardClient(f"http://127.0.0.1:{guard_port}")
                try:
                    protected = ProtectedRAG(machine, provenance_verifier=verifier)
                    seen_inputs: list[list[str]] = []
                    success = protected.run(
                        employee_token=token("alice"),
                        application_id="customer-rag",
                        retrieved=[verified_public, verified_finance],
                        generate=lambda docs: (
                            seen_inputs.append([doc.content for doc in docs])
                            or "\\n".join(doc.content for doc in docs)
                        ),
                        source_trace=lambda: [verified_public],
                    )
                    assert success.decision == "allow"
                    assert success.response == verified_public.content
                    assert seen_inputs == [[verified_public.content]]
                    assert verified_finance.content not in success.response

                    # A vector store substituted restricted bytes under a
                    # signed/authorized resource ID after provider ingestion.
                    calls: list[str] = []
                    corrupted = replace(
                        verified_public, content="REPLACED_PRIVATE_PAYROLL_CANARY",
                    )
                    tampered = protected.run(
                        employee_token=token("alice"),
                        application_id="customer-rag",
                        retrieved=[corrupted],
                        generate=lambda docs: calls.append("called") or docs[0].content,
                        source_trace=lambda: [corrupted],
                    )
                    assert tampered.response is None
                    assert tampered.reason == "SOURCE_CONTENT_ATTESTATION_FAILED"
                    assert calls == []

                    # Enable strict signed-source verification on the SAME
                    # actual customer HTTP RAG route; check response bytes.
                    public_bytes = provider_key.public_key().public_bytes(
                        Encoding.Raw, PublicFormat.Raw,
                    )
                    monkeypatch.setenv("ACCESSPROOF_DEMO_REQUIRE_ATTESTED_CONTENT", "1")
                    monkeypatch.setenv("ACCESSPROOF_DEMO_ATTESTATION_TENANT", "alpha")
                    monkeypatch.setenv("ACCESSPROOF_DEMO_ATTESTATION_KEY_ID", "synthetic-source-v1")
                    monkeypatch.setenv(
                        "ACCESSPROOF_DEMO_ATTESTATION_PUBLIC_KEY_B64",
                        base64.b64encode(public_bytes).decode("ascii"),
                    )
                    old_documents = rag.cached_files
                    try:
                        rag.cached_files = [
                            {
                                "id": doc.resource_id, "content": doc.content,
                                "chunk_id": doc.chunk_id,
                                "content_version": doc.content_version,
                                "content_attestation": doc.content_attestation,
                            }
                            for doc in (verified_public, verified_finance)
                        ]
                        rag.last_refresh = time.monotonic()
                        with customer.stream(
                            "POST", "/v1/protected-chat/stream",
                            headers={"Authorization": f"Bearer {token('alice')}"},
                            json={"message": "safely summarize attested documents"},
                        ) as response:
                            body = b"".join(response.iter_bytes())
                            assert response.status_code == 200
                            assert b"TRUSTED_SOURCE_PUBLIC_CANARY" in body
                            assert b"PRIVATE_SOURCE_FINANCE_CANARY" not in body
                        # Replace provider-signed public text without updating
                        # its signature: both JSON and SSE must fail closed.
                        rag.cached_files[0]["content"] = "REPLACED_PRIVATE_PAYROLL_CANARY"
                        with customer.stream(
                            "POST", "/v1/protected-chat/stream",
                            headers={"Authorization": f"Bearer {token('alice')}"},
                            json={"message": "try forged provider content"},
                        ) as response:
                            body = b"".join(response.iter_bytes())
                            assert response.status_code == 200
                            assert b"REPLACED_PRIVATE_PAYROLL_CANARY" not in body
                            assert b"TRUSTED_SOURCE_PUBLIC_CANARY" not in body
                    finally:
                        rag.cached_files = old_documents
                        rag.last_refresh = time.monotonic()
                        monkeypatch.delenv("ACCESSPROOF_DEMO_REQUIRE_ATTESTED_CONTENT")
                finally:
                    machine.close()
            finally:
                ingest_server.should_exit = True
                ingest_thread.join(timeout=5)

            # Revoke *during generation*, between a real Guard Layer 1
            # response and the real Guard Layer 2 response. The second Guard
            # operation must re-evaluate current source ACL and deny release.
            in_flight = RetrievedResource(source, "public", content="PUBLIC_FACT")
            recheck_client = GuardClient(f"http://127.0.0.1:{guard_port}")
            def change_policy_mid_generation(approved):
                assert approved == [in_flight]
                assert policy.install(2, [{
                    "subject_id": "alice", "source_id": source,
                    "resource_id": "public", "decision": "deny",
                    "reason": "SOURCE_ACCESS_REVOKED",
                }])
                return approved[0].content
            try:
                stale_in_flight = ProtectedRAG(
                    recheck_client, allow_unattested_metadata=True,
                ).run(
                    employee_token=token("alice"), application_id="customer-rag",
                    retrieved=[in_flight],
                    generate=change_policy_mid_generation,
                    source_trace=lambda: [in_flight],
                )
                assert stale_in_flight.decision == "block"
                assert stale_in_flight.response is None
                assert stale_in_flight.reason == "LAYER2_ACCESS_REVOKED"
            finally:
                recheck_client.close()

            # The policy update must also deny later requests.
            revoked = customer.post("/v1/protected-chat", headers={
                "Authorization": f"Bearer {token('alice')}",
            }, json={"message": "show public"})
            assert revoked.status_code == 200
            assert revoked.json()["citations"] == []
            assert "PUBLIC_FACT" not in revoked.text
    finally:
        rag_server.should_exit = True
        guard_server.should_exit = True
        rag_thread.join(timeout=5)
        guard_thread.join(timeout=5)


def test_sse_buffers_complete_model_output_until_layer2_explicit_allow(
    monkeypatch: Any,
) -> None:
    """A generator can produce a secret, but Layer 2 DENY must emit zero bytes of it."""
    from fastapi import FastAPI

    synthetic_guard = FastAPI()
    layer2_checks: list[dict[str, Any]] = []

    @synthetic_guard.post("/guard/v1/filter-resources")
    def allow_at_retrieval(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "mode": "protect", "decision": "allow", "decision_id": "synthetic-l1",
            "allowed": [
                {"source_id": row["source_id"], "resource_id": row["resource_id"],
                 "chunk_ids": []}
                for row in payload["resources"]
            ],
        }

    @synthetic_guard.post("/guard/v1/check-output")
    def reject_generation(payload: dict[str, Any]) -> dict[str, str]:
        layer2_checks.append(payload)
        return {"decision": "block", "reason": "PROVENANCE_ESCAPE"}

    guard_port = _port()
    guard_server, guard_thread = _serve(synthetic_guard, guard_port)
    customer_rag = _load_customer_rag(monkeypatch, f"http://127.0.0.1:{guard_port}")
    rag_port = _port()
    rag_server, rag_thread = _serve(customer_rag.app, rag_port)
    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{rag_port}", timeout=3) as customer:
            with customer.stream(
                "POST", "/v1/protected-chat/stream",
                headers={"Authorization": "Bearer synthetic-test-identity"},
                json={"message": "show all generated content"},
            ) as response:
                body = b"".join(response.iter_bytes())
                assert response.status_code == 200
                assert b"event: complete\ndata: {}\n\n" in body
                assert b"PUBLIC_FACT" not in body
                assert b"ALPHA_FINANCE_CANARY" not in body
                assert b"event: token" in body
                assert len(layer2_checks) == 1
                assert set(layer2_checks[0]["used_resource_ids"]) == {"public", "finance"}
    finally:
        rag_server.should_exit = True
        guard_server.should_exit = True
        rag_thread.join(timeout=5)
        guard_thread.join(timeout=5)
