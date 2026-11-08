"""Reference Gateway challenge lifecycle: machine auth, replay and audit proof."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api import gateway_presence
from apps.api.accessproof_api.route_certification import CERTIFICATE_TTL, describe_route_certificate
from apps.api.accessproof_api.db import (
    Base, engine, SessionLocal, AIApplication, GuardRegistration, GuardAuditEvent,
    ProviderSyncCursor, GuardPolicy, GuardPolicyDistribution, SourceConnection, RAGRouteChallenge,
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
        # The real challenge API refuses historical installer receipts and
        # requires current, authenticated Gateway presence. Exercise both
        # the negative path and the exact machine-bound successful path.
        missing_gateway = client.post(prefix + "/challenge", headers=owner, json={
            "deployment_sha256": DEPLOY, "route_sha256": ROUTE,
        })
        assert missing_gateway.status_code == 409
        assert missing_gateway.json()["detail"] == "LIVE_ENFORCEMENT_READY_GATEWAY_REQUIRED"
        with SessionLocal() as db:
            row = db.scalar(select(AIApplication).where(AIApplication.application_id == APP))
            installation, presence_credential = gateway_presence.issue_installation(
                db, row, deployment_sha256=DEPLOY, route_sha256=ROUTE,
            )
            installation_id = installation.id
            db.commit()
        presence = client.post(
            "/api/v1/gateway-installations/heartbeat",
            headers={"Authorization": "Bearer " + presence_credential},
            json={"organization_id": org, "installation_id": installation_id,
                  "application_id": APP, "route_sha256": ROUTE, "sequence": 1,
                  "version": "gateway-test-v1", "ready": True},
        )
        assert presence.status_code == 200, presence.text
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

        # P0: once a customer has genuinely entered Protect, the 24-hour
        # application-level certificate must be renewable without silently
        # downgrading the application to protect_pending (which would interrupt
        # the customer). Revalidation is Owner-initiated and MUST repeat all
        # nonce/Guard-audit/cutover challenges. No timestamp extension.
        with SessionLocal() as db:
            row = db.scalar(select(AIApplication).where(AIApplication.application_id == APP))
            row.mode = "protect"
            past = db.scalar(select(RAGRouteChallenge).where(
                RAGRouteChallenge.id == challenge["challenge_id"]))
            past.verified_at = datetime.now(timezone.utc) - CERTIFICATE_TTL - timedelta(minutes=1)
            db.commit()
        plain = {"deployment_sha256": DEPLOY, "route_sha256": ROUTE}
        no_consent = client.post(prefix + "/challenge", headers=owner, json=plain)
        assert no_consent.status_code == 409, no_consent.text
        assert no_consent.json()["detail"] == "ACTIVE_PROTECT_REQUIRES_CONTROLLED_RECERTIFICATION"
        invalid_consent = client.post(prefix + "/challenge", headers=owner, json={
            **plain, "controlled_recertification": True, "confirmation": "RECERTIFY wrong-app",
        })
        assert invalid_consent.status_code == 409
        # An org ADMIN is allowed to create new-app diagnostic challenges but
        # cannot recertify an active Protect route; only the interactive Owner.
        from apps.api.accessproof_api.db import Membership
        with SessionLocal() as db:
            member = db.scalar(select(Membership).where(
                Membership.organization_id == org))
            member.role = "ADMIN"
            db.commit()
        no_owner = client.post(prefix + "/challenge", headers=owner, json={
            **plain, "controlled_recertification": True, "confirmation": f"RECERTIFY {APP}",
        })
        assert no_owner.status_code == 403
        assert no_owner.json()["detail"] == "OWNER_SESSION_REQUIRED_FOR_PROTECT_RECERTIFICATION"
        with SessionLocal() as db:
            member = db.scalar(select(Membership).where(
                Membership.organization_id == org))
            member.role = "OWNER"
            db.commit()
        controlled = client.post(prefix + "/challenge", headers=owner, json={
            **plain, "controlled_recertification": True, "confirmation": f"RECERTIFY {APP}",
        })
        assert controlled.status_code == 201, controlled.text
        renewed_challenge = controlled.json()
        with SessionLocal() as db:
            row = db.scalar(select(AIApplication).where(AIApplication.application_id == APP))
            assert row.mode == "protect"
            record = db.get(RAGRouteChallenge, renewed_challenge["challenge_id"])
            assert json.loads(record.result_json)["controlled_recertification"] is True

        recert_ids = request_ids(renewed_challenge["nonce"])
        recert_obs = [{**old, "request_id": recert_ids[old["name"]]} for old in observations]
        recert_proof = {
            **proof,
            "challenge_id": renewed_challenge["challenge_id"],
            "nonce": renewed_challenge["nonce"],
            "observations": recert_obs,
        }
        recert_submit = (
            f"/api/v1/guards/{guard_id}/rag-challenges/"
            f"{renewed_challenge['challenge_id']}/submit"
        )
        assert client.post(recert_submit, headers=machine_headers,
                           json=recert_proof).status_code == 409  # no audit yet
        with SessionLocal() as db:
            for n, (name, layer, decision, reason, decision_id, subject) in enumerate(rows):
                db.add(GuardAuditEvent(
                    organization_id=org, guard_id=guard_id,
                    event_id=f"recert-stage-{n}",
                    request_id=recert_ids[name], application_id=APP, subject_id=subject,
                    layer=layer, result=decision, reason=reason,
                    decision_id=decision_id, policy_version=7,
                ))
            db.commit()
        tested_again = client.post(recert_submit, headers=machine_headers, json=recert_proof)
        assert tested_again.status_code == 202, tested_again.text
        with SessionLocal() as db:
            row = db.scalar(select(AIApplication).where(AIApplication.application_id == APP))
            assert row.mode == "protect", "recertification must not demote active Protect"
            record = db.get(RAGRouteChallenge, renewed_challenge["challenge_id"])
            assert json.loads(record.result_json)["controlled_recertification"] is True
            assert record.status == "tested"

        recert_cutover_id = "ap-cutover-" + __import__("hashlib").sha256(
            renewed_challenge["nonce"].encode()).hexdigest()[:24]
        recert_cutover_proof = {
            **cutover_proof,
            "challenge_id": renewed_challenge["challenge_id"],
            "nonce": renewed_challenge["nonce"],
            "application_request_id": recert_cutover_id,
            "negative_request_id": recert_cutover_id + "-deny",
            "tamper_request_id": recert_cutover_id + "-tamper",
        }
        recert_cutover_url = (
            f"/api/v1/guards/{guard_id}/rag-challenges/"
            f"{renewed_challenge['challenge_id']}/cutover"
        )
        assert client.post(recert_cutover_url, headers=machine_headers,
                           json=recert_cutover_proof).status_code == 409
        with SessionLocal() as db:
            for key, request_id, layer, decision, reason, subject, decision_id in (
                ("allow1", recert_cutover_id, "layer1", "allow",
                 "LAYER1_EFFECTIVE_ACCESS", "alice", "cutover-decision"),
                ("allow2", recert_cutover_id, "layer2", "allow",
                 "TRUSTED_PROVENANCE_VALID", "alice", "cutover-decision"),
                ("deny", recert_cutover_id + "-deny", "layer1", "block",
                 "LAYER1_EFFECTIVE_ACCESS", "bob", "cutover-denial"),
                ("tamper", recert_cutover_id + "-tamper", "layer1", "allow",
                 "LAYER1_EFFECTIVE_ACCESS", "alice", "cutover-forgery"),
            ):
                db.add(GuardAuditEvent(
                    organization_id=org, guard_id=guard_id,
                    event_id="recert-cutover-" + key,
                    request_id=request_id, application_id=APP, subject_id=subject,
                    layer=layer, result=decision, reason=reason,
                    decision_id=decision_id, policy_version=7,
                ))
            db.commit()
        cutover_again = client.post(
            recert_cutover_url, headers=machine_headers, json=recert_cutover_proof)
        assert cutover_again.status_code == 202, cutover_again.text
        assert cutover_again.json()["guard_acknowledgment_required"] is False
        with SessionLocal() as db:
            row = db.scalar(select(AIApplication).where(AIApplication.application_id == APP))
            record = db.get(RAGRouteChallenge, renewed_challenge["challenge_id"])
            assert row.mode == "protect"
            assert record.status == "cutover_verified"
            assert json.loads(record.result_json)["controlled_recertification"] is True
            certificate = describe_route_certificate(db, row)
            assert certificate["certified"] and certificate["status"] == "CERTIFIED"
        assert client.post(recert_cutover_url, headers=machine_headers,
                           json=recert_cutover_proof).status_code == 409
