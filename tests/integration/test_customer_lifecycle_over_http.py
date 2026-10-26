"""Synthetic customer lifecycle through the actual control-plane and Guard HTTP APIs.

The test deliberately uses only loopback listeners, synthetic JWTs and opaque
fake source credentials.  It covers the seams a customer deploys separately:
the control plane, a source ACL snapshot, Guard enrollment/synchronization,
the customer RAG enforcement boundary, audit upload, revocation, and stale-source
fail-closed behavior.
"""
from __future__ import annotations

import json
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
import uvicorn

from apps.api.accessproof_api import app as control_plane
from apps.api.accessproof_api.db import (
    AIApplication,
    Base,
    GuardPermissionEvent,
    GuardIdentityMapping,
    GuardResource,
    GuardSubject,
    ProviderSyncCursor,
    SessionLocal,
    SourceConnection,
    engine,
)
from apps.api.accessproof_api.guard_pipeline import process_guard_event
from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache
from apps.guard.accessproof_guard.sync import GuardMachineCredentials, GuardSyncClient
from packages.rag_core.protection import GuardClient, ProtectedRAG, RetrievedResource


def _port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _serve(application: Any, port: int) -> tuple[uvicorn.Server, threading.Thread]:
    server = uvicorn.Server(uvicorn.Config(
        application, host="127.0.0.1", port=port, log_level="critical", lifespan="off",
    ))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started
    return server, thread


def _event(
    db: Any, *, organization_id: str, source_id: str, subject_id: str,
    resource_id: str, key: str, revision: int, change: str,
) -> None:
    mutation: dict[str, object] = {
        "grant_key": key,
        "scope": "read",
        "snapshot_complete": True,
    }
    if change == "grant_upsert":
        mutation.update({
            "principal_type": "subject", "principal_id": subject_id,
            "grant_effect": "allow",
        })
    row = GuardPermissionEvent(
        organization_id=organization_id, source_id=source_id, provider="google-drive",
        provider_revision=revision, subject_id=subject_id, resource_id=resource_id,
        change_type=change, dedupe_key=f"synthetic-customer:{key}:{revision}",
        processing_status="queued", mutation_json=json.dumps(mutation),
    )
    db.add(row)
    db.commit()
    process_guard_event(db, row.id)


@pytest.mark.parametrize(("customer_name", "admin_email"), [
    ("Northstar Technologies", "northstar-admin@example.com"),
    ("BlueHarbor Financial", "blueharbor-admin@example.com"),
    ("Meridian Global Systems", "meridian-admin@example.com"),
])
def test_customer_lifecycle_connects_source_guard_rag_and_revokes_over_http(
    monkeypatch: Any, tmp_path: Path, customer_name: str, admin_email: str,
) -> None:
    """A customer never receives a denied document before or after revocation."""
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    api_port = _port()
    api_server, api_thread = _serve(control_plane.app, api_port)
    api_url = f"http://127.0.0.1:{api_port}"
    signing_key = "synthetic-customer-lifecycle-signing-key-32"
    cache = PolicyCache(str(tmp_path / "customer-guard.db"))
    guard_server: uvicorn.Server | None = None
    guard_thread: threading.Thread | None = None
    sync: GuardSyncClient | None = None

    def employee(subject: str) -> str:
        return jwt.encode({
            "sub": subject, "tid": "customer-tenant", "iss": "https://issuer.synthetic",
            "aud": "customer-rag", "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        }, signing_key, algorithm="HS256")

    try:
        with httpx.Client(base_url=api_url, timeout=5) as control:
            signup = control.post("/api/v1/auth/signup", json={
                "email": admin_email,
                "password": "synthetic customer password",
                "organization_name": customer_name,
            })
            assert signup.status_code == 201, signup.text
            account = signup.json()
            headers = {
                "Authorization": f"Bearer {account['session_token']}",
                "X-Organization-ID": account["organization_id"],
            }
            source_response = control.post("/api/v1/current/sources", headers=headers, json={
                "provider": "google-drive", "name": "Synthetic Drive",
                "boundary": "synthetic-drive-root",
                "credentials": {"access_token": "synthetic-only"},
            })
            assert source_response.status_code == 201, source_response.text
            source_id = source_response.json()["id"]
            guard_response = control.post("/api/v1/guards", headers=headers, json={
                "name": "Synthetic customer Guard", "environment": "test",
            })
            assert guard_response.status_code == 201, guard_response.text
            guard_id = guard_response.json()["id"]
            enrollment = control.post(
                f"/api/v1/guards/{guard_id}/enrollments", headers=headers, json={},
            )
            assert enrollment.status_code == 201, enrollment.text
            exchanged = control.post("/api/v1/guards/exchange", json={
                "enrollment_token": enrollment.json()["enrollment_token"], "version": "test",
            })
            assert exchanged.status_code == 201, exchanged.text
            credential = exchanged.json()["guard_credential"]
            application = control.post("/api/v1/current/ai-applications", headers=headers, json={
                "application_id": "customer-rag", "name": "Customer RAG",
                "guard_id": guard_id, "source_id": source_id,
                "adapter_type": "accessproof-gateway", "adapter_contract_version": "accessproof.rag/v1",
            })
            assert application.status_code == 201, application.text

        # This represents a completed, trusted customer Google Drive/directory
        # sync. Provider HTTP parsing is exercised separately with mocked
        # Google responses; this lifecycle test consumes its normalized events.
        with SessionLocal() as db:
            source = db.get(SourceConnection, source_id)
            assert source is not None
            now = datetime.now(timezone.utc)
            source.status = "connected"
            source.last_validated_at = now
            for kind in ("acl", "directory"):
                db.add(ProviderSyncCursor(
                    organization_id=account["organization_id"], source_id=source_id,
                    provider="google-drive", sync_kind=kind, status="connected",
                    last_success_at=now,
                ))
            alice = GuardSubject(
                organization_id=account["organization_id"], provider="google-drive",
                provider_subject_id="alice-oid", primary_email="alice@example.com",
            )
            bob = GuardSubject(
                organization_id=account["organization_id"], provider="google-drive",
                provider_subject_id="bob-oid", primary_email="bob@example.com",
            )
            public = GuardResource(
                organization_id=account["organization_id"], source_id=source_id,
                provider_resource_id="public-file",
            )
            finance = GuardResource(
                organization_id=account["organization_id"], source_id=source_id,
                provider_resource_id="finance-file",
            )
            db.add_all([alice, bob, public, finance])
            db.commit()
            # This is the customer-admin verified bridge between independent
            # workforce IdP and Google Workspace identities. It is not email
            # matching; both sides use immutable opaque subjects.
            db.add_all([
                GuardIdentityMapping(
                    organization_id=account["organization_id"], source_id=source_id,
                    oidc_issuer="https://issuer.synthetic", oidc_subject="alice-oid",
                    oidc_tenant_id="customer-tenant", source_subject_id=alice.id,
                    status="VERIFIED", method="admin_verified", verified_at=now,
                ),
                GuardIdentityMapping(
                    organization_id=account["organization_id"], source_id=source_id,
                    oidc_issuer="https://issuer.synthetic", oidc_subject="bob-oid",
                    oidc_tenant_id="customer-tenant", source_subject_id=bob.id,
                    status="VERIFIED", method="admin_verified", verified_at=now,
                ),
            ])
            db.commit()
            _event(db, organization_id=account["organization_id"], source_id=source_id,
                   subject_id=alice.id, resource_id=public.id, key="public:alice",
                   revision=1, change="grant_upsert")
            _event(db, organization_id=account["organization_id"], source_id=source_id,
                   subject_id=alice.id, resource_id=finance.id, key="finance:alice",
                   revision=2, change="grant_revoke")
            _event(db, organization_id=account["organization_id"], source_id=source_id,
                   subject_id=bob.id, resource_id=finance.id, key="finance:bob",
                   revision=3, change="grant_revoke")
            row = db.query(AIApplication).filter_by(application_id="customer-rag").one()
            # Protect normally reaches this state only after readiness evidence.
            # The API readiness/activation gate is separately covered; this
            # test verifies the policy the machine receives after that gate.
            row.mode = "protect_pending"
            db.commit()

        sync = GuardSyncClient(cache, GuardMachineCredentials(
            control_plane_url=api_url, guard_id=guard_id, credential=credential, version="test",
        ))
        assert sync.sync_once()
        assert cache.application_binding("customer-rag") == (source_id, "protect")
        # The first machine poll still sees uninstalled policy distributions.
        # Only after the installed ACK reaches the control plane and a second
        # authenticated sync may this source become ready for Protect.
        assert not cache.source_acl_healthy("customer-rag")
        assert not sync.sync_once()
        assert cache.source_acl_healthy("customer-rag")

        for name, value in {
            "cache": cache, "identity_mode": "static", "issuer": "https://issuer.synthetic",
            "audience": "customer-rag", "verification_key": signing_key,
            "expected_tenant": "customer-tenant", "subject_claim": "sub",
            "guard_id": guard_id, "guard_credential": credential,
            "control_plane_url": api_url, "max_policy_age_seconds": 300,
        }.items():
            monkeypatch.setattr(guard_app, name, value)
        guard_port = _port()
        guard_server, guard_thread = _serve(guard_app.app, guard_port)
        client = GuardClient(f"http://127.0.0.1:{guard_port}")
        rag = ProtectedRAG(client, allow_unattested_metadata=True)
        retrieved = [
            RetrievedResource(source_id, "public-file", content="PUBLIC_CUSTOMER_FACT"),
            RetrievedResource(source_id, "finance-file", content="FINANCE_CANARY_DO_NOT_RELEASE"),
        ]
        try:
            alice_result = rag.run(
                employee_token=employee("alice-oid"), application_id="customer-rag",
                retrieved=retrieved,
                generate=lambda allowed: "\n".join(item.content for item in allowed),
                source_trace=lambda: [retrieved[0]],
            )
            assert alice_result.decision == "allow"
            assert alice_result.response == "PUBLIC_CUSTOMER_FACT"
            assert "FINANCE_CANARY_DO_NOT_RELEASE" not in (alice_result.response or "")

            # The internal Gateway authorization engine already exercised the
            # real Guard HTTP boundary. No framework SDK integration remains
            # part of the customer-facing lifecycle.

            bob_result = rag.run(
                employee_token=employee("bob-oid"), application_id="customer-rag",
                retrieved=retrieved,
                generate=lambda allowed: "\n".join(item.content for item in allowed),
                source_trace=lambda: [retrieved[0]],
            )
            assert bob_result.response is None

            escaped_provenance = rag.run(
                employee_token=employee("alice-oid"), application_id="customer-rag",
                retrieved=[retrieved[0]], generate=lambda allowed: allowed[0].content,
                source_trace=lambda: [retrieved[1]],
            )
            assert escaped_provenance.response is None
            assert escaped_provenance.reason == "ADDITIONAL_SOURCE_NOT_AUTHORIZED"
        finally:
            client.close()

        # The source reports Alice's direct grant revoked. The API generates a
        # new policy, the real Guard downloads it, and the same RAG boundary
        # refuses to release the previously allowed document.
        with SessionLocal() as db:
            alice = db.query(GuardSubject).filter_by(provider_subject_id="alice-oid").one()
            public = db.query(GuardResource).filter_by(provider_resource_id="public-file").one()
            _event(db, organization_id=account["organization_id"], source_id=source_id,
                   subject_id=alice.id, resource_id=public.id, key="public:alice",
                   revision=4, change="grant_revoke")
        assert sync.sync_once()
        client = GuardClient(f"http://127.0.0.1:{guard_port}")
        try:
            revoked = ProtectedRAG(client, allow_unattested_metadata=True).run(
                employee_token=employee("alice-oid"), application_id="customer-rag",
                retrieved=[retrieved[0]], generate=lambda allowed: allowed[0].content,
            )
            assert revoked.response is None
            # While the newly revoked policy awaits installed ACK, the Guard
            # deliberately refuses to serve responses (safe 503 / block).
            assert revoked.reason in {"GUARD_REQUEST_FAILED", "NO_AUTHORIZED_RESOURCES"}
            assert not sync.sync_once()
            settled = ProtectedRAG(client, allow_unattested_metadata=True).run(
                employee_token=employee("alice-oid"), application_id="customer-rag",
                retrieved=[retrieved[0]], generate=lambda allowed: allowed[0].content,
            )
            assert settled.response is None
            assert settled.reason == "NO_AUTHORIZED_RESOURCES"
        finally:
            client.close()

        # A stale or failed ACL source immediately disables Protect release.
        with SessionLocal() as db:
            cursor = db.query(ProviderSyncCursor).filter_by(
                source_id=source_id, sync_kind="acl",
            ).one()
            cursor.status = "degraded"
            cursor.last_error_code = "ACL_SYNC_FAILED"
            db.commit()
        assert not sync.sync_once()
        unavailable = httpx.post(
            f"http://127.0.0.1:{guard_port}/guard/v1/filter-resources",
            headers={"Authorization": f"Bearer {employee('alice-oid')}"},
            json={"application_id": "customer-rag", "request_id": "stale-source",
                  "resources": [{"source_id": source_id, "resource_id": "public-file"}]},
            timeout=3,
        )
        assert unavailable.status_code == 503
        assert unavailable.json()["detail"] == "SOURCE_ACL_STALE"

        # Audit evidence is delivered through the machine-only API and is not
        # left stranded in the Guard after a successful control-plane round trip.
        assert sync.upload_audit() >= 4
        sync.heartbeat()
        with httpx.Client(base_url=api_url, timeout=3) as control:
            guards = control.get("/api/v1/guards", headers=headers)
            assert guards.status_code == 200
            assert guards.json()[0]["active_policy_version"] >= 4
    finally:
        if sync is not None:
            sync.close()
        if guard_server is not None:
            guard_server.should_exit = True
        if guard_thread is not None:
            guard_thread.join(timeout=5)
        api_server.should_exit = True
        api_thread.join(timeout=5)
