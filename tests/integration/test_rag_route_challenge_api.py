"""Reference Gateway challenge lifecycle: machine auth, replay and audit proof."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    Base, engine, SessionLocal, AIApplication, GuardRegistration, GuardAuditEvent,
    ProviderSyncCursor, GuardPolicy, GuardPolicyDistribution, SourceConnection,
)
from apps.api.accessproof_api.rag_challenge_verifier import request_ids
from packages.crypto.secrets import hash_token


CREDENTIAL = "synthetic-testing-guard-machine-credential"
APP = "reference-pilot"
DEPLOY = "a" * 64
ROUTE = "b" * 64


def test_machine_proof_requires_current_guard_audits_and_real_ack():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        sign = client.post("/api/v1/auth/signup", json={
            "email": "routepilot@example.com", "password": "correct horse battery staple",
            "organization_name": "Route Pilot",
        })
        assert sign.status_code == 201, sign.text
        data = sign.json()
        org = data["organization_id"]
        owner = {"Authorization": "Bearer " + data["session_token"], "X-Organization-ID": org}
        src = client.post("/api/v1/current/sources", headers=owner, json={
            "provider": "google-drive", "name": "Synthetic Drive",
            "boundary": "root", "credentials": {"test_root_folder_id": "root"},
        })
        guard = client.post("/api/v1/guards", headers=owner, json={"name": "synthetic-guard"})
        assert src.status_code == 201 and guard.status_code == 201
        src_id, guard_id = src.json()["id"], guard.json()["id"]
        app_reg = client.post("/api/v1/current/ai-applications", headers=owner, json={
            "application_id": APP, "name": "Synthetic pilot app",
            "guard_id": guard_id, "source_id": src_id,
            "adapter_type": "accessproof-gateway",
            "adapter_contract_version": "accessproof.rag/v1",
        })
        assert app_reg.status_code == 201, app_reg.text

        now = datetime.now(timezone.utc)
        with SessionLocal() as db:
            machine = db.get(GuardRegistration, guard_id)
            machine.enrolled_at, machine.last_heartbeat_at = now, now
            machine.credential_hash, machine.active_policy_version = hash_token(CREDENTIAL), 7
            machine.health = "healthy"
            source = db.get(SourceConnection, src_id)
            source.status, source.last_validated_at = "connected", now
            source.encrypted_credentials = "synthetic-local-test-only"
            for kind in ("acl", "directory"):
                db.add(ProviderSyncCursor(
                    organization_id=org, source_id=src_id, provider="google-drive",
                    sync_kind=kind, status="connected", last_success_at=now,
                ))
            policy = GuardPolicy(organization_id=org, policy_key="allow-pilot", version=7,
                                 decision="allow", subject_id="alice", resource_id="doc",
                                 source_id=src_id)
            db.add(policy)
            db.flush()
            db.add(GuardPolicyDistribution(organization_id=org, policy_id=policy.id,
                                           guard_id=guard_id, status="installed"))
            db.commit()

        prefix = f"/api/v1/current/ai-applications/{APP}/protection"
        preflight = client.post(prefix + "/enable", headers=owner)
        assert preflight.status_code == 202, preflight.text
        started = client.post(prefix + "/challenge", headers=owner, json={
            "deployment_sha256": DEPLOY, "route_sha256": ROUTE,
        })
        assert started.status_code == 201, started.text
        challenge = started.json()
        assert challenge["production_certification"] is False
        machine_headers = {"Authorization": "Bearer " + CREDENTIAL}

        def heartbeat():
            return client.post("/api/v1/guards/heartbeat", headers=machine_headers, json={
                "guard_id": guard_id, "version": "0.1.0", "active_policy_version": 7,
                "cache_status": "healthy", "active_applications": {APP: "protect"},
            })

        assert heartbeat().status_code == 200
        with SessionLocal() as db:
            assert db.scalar(select(AIApplication).where(AIApplication.application_id == APP)).mode == "protect_pending"

        ids = request_ids(challenge["nonce"])
        observations = []
        codes = {"deny": "NO_AUTHORIZED_RESOURCES",
                 "tamper": "SOURCE_CONTENT_ATTESTATION_FAILED",
                 "layer2_revoke": "LAYER2_ACCESS_REVOKED"}
        for name, status in (("allow", 200), ("deny", 403), ("tamper", 503), ("layer2_revoke", 403)):
            observations.append({
                "name": name, "request_id": ids[name], "http_status": status,
                "response_sha256": "c" * 64, "response_byte_count": 90,
                "forbidden_content_observed": False,
                "reason_code": codes.get(name),
                "decision": "allow" if name == "allow" else None,
                "decision_id": "positive" if name == "allow" else None,
            })
        url = f"/api/v1/guards/{guard_id}/rag-challenges/{challenge['challenge_id']}/submit"
        proof = {
            "challenge_id": challenge["challenge_id"], "guard_id": guard_id,
            "nonce": challenge["nonce"], "deployment_sha256": DEPLOY,
            "route_sha256": ROUTE, "contract": "accessproof.gateway/v1",
            "observations": observations,
            "customer_route_verified": True, "ingress_boundary_verified": True,
            "retrieval_boundary_verified": True, "output_boundary_verified": True,
            "alternate_route_blocked": True,
        }
        assert client.post(url, json=proof).status_code == 401
        assert client.post(url, json={**proof, "nonce": "x" * 40},
                           headers=machine_headers).status_code == 403
        missing = client.post(url, json=proof, headers=machine_headers)
        assert missing.status_code == 409, missing.text
        assert missing.json()["detail"]["code"] == "GUARD_AUDIT_EVIDENCE_MISSING"

        rows = [
            ("allow", "layer1", "allow", "LAYER1_EFFECTIVE_ACCESS", "positive", "alice"),
            ("allow", "layer2", "allow", "TRUSTED_PROVENANCE_VALID", "positive", "alice"),
            ("deny", "layer1", "block", "LAYER1_EFFECTIVE_ACCESS", "denial", "bob"),
            ("tamper", "layer1", "allow", "LAYER1_EFFECTIVE_ACCESS", "forgery", "alice"),
            ("layer2_revoke", "layer1", "allow", "LAYER1_EFFECTIVE_ACCESS", "revoke", "alice"),
            ("layer2_revoke", "layer2", "block", "LAYER2_ACCESS_REVOKED", "revoke", "alice"),
        ]
        with SessionLocal() as db:
            for n, (name, layer, decision, reason, decision_id, subject) in enumerate(rows):
                db.add(GuardAuditEvent(
                    organization_id=org, guard_id=guard_id, event_id=f"test-event-{n}",
                    request_id=ids[name], application_id=APP, subject_id=subject,
                    layer=layer, result=decision, reason=reason,
                    decision_id=decision_id, policy_version=7,
                ))
            db.commit()
        result = client.post(url, json=proof, headers=machine_headers)
        assert result.status_code == 202, result.text
        assert result.json()["state"] == "tested_awaiting_customer_cutover"
        assert result.json()["protection_ready"] is False
        assert result.json()["production_certification"] is False
        assert client.post(url, json=proof, headers=machine_headers).status_code == 409
        assert heartbeat().status_code == 200
        before_cutover = client.get(prefix + "/status", headers=owner).json()
        assert before_cutover["state"] != "protected"
        assert not before_cutover["guard_acknowledged"]
        pending_certificate = before_cutover["route_certificate"]
        assert pending_certificate["status"] == "TESTED_NOT_CUTOVER", pending_certificate
        assert pending_certificate["certified"] is False
        assert pending_certificate["evidence_level"] == "LOCAL_INTEGRATION_VERIFIED"
        assert pending_certificate["expires_at"] is not None
        assert pending_certificate["age_seconds"] is not None
        assert pending_certificate["independent_certification"] is False

        # The real customer-facing RAG must execute a separate request after
        # changing its configured route; reference tests alone are not enough.
        cutover_id = "ap-cutover-" + __import__("hashlib").sha256(
            challenge["nonce"].encode()
        ).hexdigest()[:24]
        cutover_url = f"/api/v1/guards/{guard_id}/rag-challenges/{challenge['challenge_id']}/cutover"
        cutover_proof = {
            "challenge_id": challenge["challenge_id"], "guard_id": guard_id,
            "nonce": challenge["nonce"], "deployment_sha256": DEPLOY,
            "route_sha256": ROUTE, "application_request_id": cutover_id,
            "application_http_status": 200,
            "application_response_sha256": "d" * 64,
            "decision_id": "cutover-decision",
            "forbidden_canary_observed": False,
            "gateway_route_enforced": True,
            "negative_request_id": cutover_id + "-deny",
            "negative_http_status": 403,
            "negative_response_sha256": "e" * 64,
            "negative_reason_code": "NO_AUTHORIZED_RESOURCES",
            "negative_forbidden_canary_observed": False,
            "tamper_request_id": cutover_id + "-tamper",
            "tamper_http_status": 503,
            "tamper_response_sha256": "f" * 64,
            "tamper_reason_code": "SOURCE_CONTENT_ATTESTATION_FAILED",
        }
        assert client.post(cutover_url, headers=machine_headers, json=cutover_proof).status_code == 409
        with SessionLocal() as db:
            for number, (layer, reason) in enumerate([
                ("layer1", "LAYER1_EFFECTIVE_ACCESS"),
                ("layer2", "TRUSTED_PROVENANCE_VALID"),
            ]):
                db.add(GuardAuditEvent(
                    organization_id=org, guard_id=guard_id,
                    event_id=f"cutover-{number}", request_id=cutover_id,
                    application_id=APP, subject_id="alice",
                    layer=layer, result="allow", reason=reason,
                    decision_id="cutover-decision", policy_version=7,
                ))
            db.commit()
        # An actual customer-RAG DENY path must also have reached Guard.
        assert client.post(cutover_url, headers=machine_headers, json=cutover_proof).status_code == 409
        with SessionLocal() as db:
            db.add(GuardAuditEvent(
                organization_id=org, guard_id=guard_id, event_id="cutover-deny",
                request_id=cutover_id + "-deny", application_id=APP,
                subject_id="bob", layer="layer1", result="block",
                reason="LAYER1_EFFECTIVE_ACCESS", decision_id="cutover-denial",
                policy_version=7,
            ))
            db.commit()
        # Denial audit is not enough: the forged-source case must separately
        # prove a real Guard-authorized source was rejected by attestation.
        assert client.post(cutover_url, headers=machine_headers, json=cutover_proof).status_code == 409
        with SessionLocal() as db:
            db.add(GuardAuditEvent(
                organization_id=org, guard_id=guard_id, event_id="cutover-tamper",
                request_id=cutover_id + "-tamper", application_id=APP,
                subject_id="alice", layer="layer1", result="allow",
                reason="LAYER1_EFFECTIVE_ACCESS", decision_id="cutover-forgery",
                policy_version=7,
            ))
            db.commit()
        verified_cutover = client.post(cutover_url, headers=machine_headers, json=cutover_proof)
        assert verified_cutover.status_code == 202, verified_cutover.text
        # A verified customer route alone does not override an unverified
        # Google ACL/directory source or unacknowledged Guard policy. Keep
        # Protect false until all independent source checks succeed.
        assert verified_cutover.json()["protection_ready"] is False, verified_cutover.text
        assert client.post(cutover_url, headers=machine_headers, json=cutover_proof).status_code == 409
        assert heartbeat().status_code == 200
        after = client.get(prefix + "/status", headers=owner).json()
        assert after["state"] != "protected", after
        assert after["guard_acknowledged"] is False
        certificate = after["route_certificate"]
        assert certificate["status"] == "CERTIFIED", certificate
        assert certificate["certified"] is True
        assert certificate["evidence_level"] == "LOCAL_INTEGRATION_VERIFIED"
        assert certificate["verified_at"] is not None
        assert certificate["cutover_at"] is not None
        assert certificate["expires_at"] is not None
        assert certificate["age_seconds"] >= 0
        assert certificate["certification_scope"] == "REFERENCE_GATEWAY_ROUTE_ONLY"
        assert certificate["independent_certification"] is False
