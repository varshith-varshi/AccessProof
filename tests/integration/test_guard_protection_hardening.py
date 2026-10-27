"""Secure Guard distribution, evidence-backed readiness, and Protect ack tests."""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    Base, SessionLocal, AIApplication, GuardPolicy,
    GuardPolicyDistribution, engine,
)
from sqlalchemy import select

api_module = importlib.import_module("apps.api.accessproof_api.app")


def signup(client):
    account = client.post("/api/v1/auth/signup", json={
        "email": "guard-hardening@example.com",
        "password": "correct horse battery staple",
        "organization_name": "Guard Hardening",
    }).json()
    return account, {"Authorization": f"Bearer {account['session_token']}",
                     "X-Organization-ID": account["organization_id"]}


def provision(client, headers):
    guard = client.post("/api/v1/guards", headers=headers, json={"name": "hardening"}).json()
    token = client.post(f"/api/v1/guards/{guard['id']}/enrollments",
                        headers=headers, json={}).json()["enrollment_token"]
    machine = client.post("/api/v1/guards/exchange",
                          json={"enrollment_token": token, "version": "1"}).json()["guard_credential"]
    return guard["id"], machine


@pytest.mark.parametrize(("adapter_type", "contract_version"), [
    ("generic-python", "accessproof.rag/v1"),
    ("generic-typescript", "accessproof.rag/v1"),
    ("langchain-python", "accessproof.rag/v1"),
    ("llamaindex-python", "accessproof.rag/v1"),
    ("langchain-typescript", "accessproof.rag/v1"),
    ("haystack-python", "accessproof.rag/v1"),
    ("generic-http", "target-config/v1"),
])
def test_old_sdk_application_types_cannot_be_registered(adapter_type, contract_version):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        _, headers = signup(client)
        response = client.post("/api/v1/current/ai-applications", headers=headers, json={
            "application_id": f"{adapter_type}-test",
            "name": adapter_type,
            "adapter_type": adapter_type,
            "adapter_contract_version": contract_version,
        })
        assert response.status_code == 422, response.text
        listed = client.get("/api/v1/current/ai-applications", headers=headers)
        assert listed.status_code == 200
        assert listed.json() == []


def test_gateway_is_the_only_new_customer_integration():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        _, headers = signup(client)
        response = client.post("/api/v1/current/ai-applications", headers=headers, json={
            "application_id": "gateway-only", "name": "Gateway",
            "adapter_type": "accessproof-gateway",
            "adapter_contract_version": "accessproof.rag/v1",
        })
        assert response.status_code == 201, response.text
        assert response.json()["adapter_type"] == "accessproof-gateway"
        readiness = client.get(
            "/api/v1/current/ai-applications/gateway-only/protect-readiness", headers=headers,
        )
        assert readiness.status_code == 200
        assert not readiness.json()["ready"]
        checks = {row["code"]: row["ok"] for row in readiness.json()["checks"]}
        assert checks["ENFORCEMENT_ADAPTER_CONFIGURED"] is True


def test_ai_application_rejects_a_mismatched_adapter_contract():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        _, headers = signup(client)
        response = client.post("/api/v1/current/ai-applications", headers=headers, json={
            "application_id": "http-wrong-contract",
            "name": "HTTP target",
            "adapter_type": "generic-http",
            "adapter_contract_version": "accessproof.rag/v1",
        })
        assert response.status_code == 422


def test_guard_archive_is_downloadable_only_by_authenticated_admin(tmp_path: Path, monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    filename = "accessproof-guard-0.1.0.tar.gz"
    (tmp_path / filename).write_bytes(b"synthetic-test-archive")
    monkeypatch.setenv("ACCESSPROOF_GUARD_RELEASE_DIR", str(tmp_path))
    with TestClient(app) as client:
        response = client.get("/api/v1/guards/download")
        assert response.status_code in (401, 403)
        _, headers = signup(client)
        response = client.get("/api/v1/guards/download", headers=headers)
        assert response.status_code == 200
        assert response.content == b"synthetic-test-archive"
        assert "attachment" in response.headers["content-disposition"]
        assert "private" in response.headers["cache-control"]


def test_readiness_requires_guard_events_not_boolean_flags():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        _, headers = signup(client)
        guard_id, machine = provision(client, headers)
        source = client.post("/api/v1/current/sources", headers=headers, json={
            "provider": "google-drive", "name": "test source", "boundary": "fake-drive-folder",
            "credentials": {"access_token": "synthetic-not-real"},
        })
        assert source.status_code == 201, source.text
        created = client.post("/api/v1/current/ai-applications", headers=headers, json={
            "application_id": "rag-test", "name": "RAG Test", "guard_id": guard_id,
            "source_id": source.json()["id"],
        })
        assert created.status_code == 201, created.text
        url = "/api/v1/current/ai-applications/rag-test/verification"
        proof = {"positive_request_id": "r-allow", "denial_request_id": "r-deny",
                 "provenance_request_id": "r-provenance",
                 "buffering_test_passed": True, "layer1": True,
                 "layer2": True, "provenance": True, "buffering": True}
        # The old booleans cannot activate the application without Guard events.
        assert client.post(url, headers=headers, json=proof).status_code == 409
        payloads = [
            ("allow-l1", "r-allow", "layer1", "would_allow", "LAYER1_EFFECTIVE_ACCESS", "d-allow"),
            ("allow-l2", "r-allow", "layer2", "would_allow", "TRUSTED_PROVENANCE_VALID", "d-allow"),
            ("deny-l1", "r-deny", "layer1", "would_block", "LAYER1_EFFECTIVE_ACCESS", "d-deny"),
            ("prov-l2", "r-provenance", "layer2", "would_block", "PROVENANCE_ESCAPE", "d-prov"),
        ]
        audit = []
        for event_id, request_id, layer, result, reason, decision_id in payloads:
            audit.append({"event_id": event_id, "request_id": request_id, "layer": layer,
                          "result": result, "reason": reason, "decision_id": decision_id,
                          "application_id": "rag-test", "subject_id": "alice", "policy_version": 1})
        uploaded = client.post("/api/v1/guards/audit-events",
                               headers={"Authorization": f"Bearer {machine}"},
                               json={"guard_id": guard_id, "events": audit})
        assert uploaded.status_code == 202, uploaded.text
        assert uploaded.json()["accepted"] == 4
        assert client.post(url, headers=headers, json={**proof, "buffering_test_passed": False}).status_code == 409
        validated = client.post(url, headers=headers, json=proof)
        assert validated.status_code == 200, validated.text
        state = {item["code"]: item["ok"] for item in validated.json()["checks"]}
        assert state["LAYER1_INTEGRATION_CONFIRMED"] is True
        assert state["LAYER2_INTEGRATION_CONFIRMED"] is True
        assert state["PROVENANCE_READY"] is True
        assert state["BUFFERED_RESPONSE_GATE_READY"] is True


def test_protect_activation_waits_for_guard_machine_ack(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        _, headers = signup(client)
        guard_id, machine = provision(client, headers)
        assert client.post("/api/v1/current/ai-applications", headers=headers, json={
            "application_id": "secure-rag", "name": "Secure RAG", "guard_id": guard_id,
        }).status_code == 201
        # Exercise the *post-certification machine acknowledgement protocol* in
        # isolation. The actual activation readiness path is separately tested
        # to reject missing customer-side route proof, never forged by clients.
        monkeypatch.setattr(api_module, "_automatic_activation_checklist",
                            lambda *args: [{"code": "INTEGRATION_READY", "ok": True, "reason": None}])
        changed = client.patch("/api/v1/current/ai-applications/secure-rag/mode",
                               headers=headers, json={"mode": "protect"})
        assert changed.status_code == 200, changed.text
        assert changed.json()["mode"] == "protect_pending"
        with SessionLocal() as db:
            assert db.scalar(select(AIApplication).where(AIApplication.application_id == "secure-rag")).mode == "protect_pending"
        heartbeat = client.post("/api/v1/guards/heartbeat",
                                headers={"Authorization": f"Bearer {machine}"},
                                json={"guard_id": guard_id, "version": "1",
                                      "active_applications": {"secure-rag": "shadow"}})
        assert heartbeat.status_code == 200, heartbeat.text
        with SessionLocal() as db:
            assert db.scalar(select(AIApplication).where(AIApplication.application_id == "secure-rag")).mode == "protect_pending"
        # Never infer active Protect from a policy-less, unready Guard.
        heartbeat = client.post("/api/v1/guards/heartbeat",
                                headers={"Authorization": f"Bearer {machine}"},
                                json={"guard_id": guard_id, "version": "1",
                                      "active_applications": {"secure-rag": "protect"}})
        assert heartbeat.status_code == 200, heartbeat.text
        with SessionLocal() as db:
            assert db.scalar(select(AIApplication).where(AIApplication.application_id == "secure-rag")).mode == "protect_pending"
        # Never accept a policy version not actually distributed and installed
        # for this machine. Reject the forged heartbeat before health checks.
        heartbeat = client.post("/api/v1/guards/heartbeat",
                                headers={"Authorization": f"Bearer {machine}"},
                                json={"guard_id": guard_id, "version": "1", "cache_status": "healthy",
                                      "active_policy_version": 2,
                                      "active_applications": {"secure-rag": "protect"}})
        assert heartbeat.status_code == 409, heartbeat.text
        assert "not distributed and installed" in heartbeat.json()["detail"]
        with SessionLocal() as db:
            assert db.scalar(select(AIApplication).where(
                AIApplication.application_id == "secure-rag")).mode == "protect_pending"
            row = db.scalar(select(AIApplication).where(AIApplication.application_id == "secure-rag"))
            policy = GuardPolicy(
                organization_id=row.organization_id, policy_key="guard-hardening-ack",
                version=2, mode="protect", decision="deny",
                subject_id="synthetic-test-subject", resource_id="synthetic-test-resource",
            )
            db.add(policy)
            db.flush()
            db.add(GuardPolicyDistribution(
                organization_id=row.organization_id, policy_id=policy.id,
                guard_id=guard_id, status="installed",
            ))
            db.commit()
        # Even an installed policy cannot activate Protect from an unhealthy Guard.
        heartbeat = client.post("/api/v1/guards/heartbeat",
                                headers={"Authorization": f"Bearer {machine}"},
                                json={"guard_id": guard_id, "version": "1", "cache_status": "degraded",
                                      "active_policy_version": 2,
                                      "active_applications": {"secure-rag": "protect"}})
        assert heartbeat.status_code == 200, heartbeat.text
        with SessionLocal() as db:
            assert db.scalar(select(AIApplication).where(AIApplication.application_id == "secure-rag")).mode == "protect_pending"
        heartbeat = client.post("/api/v1/guards/heartbeat",
                                headers={"Authorization": f"Bearer {machine}"},
                                json={"guard_id": guard_id, "version": "1", "cache_status": "healthy",
                                      "active_policy_version": 2,
                                      "active_applications": {"secure-rag": "protect"}})
        assert heartbeat.status_code == 200, heartbeat.text
        with SessionLocal() as db:
            assert db.scalar(select(AIApplication).where(AIApplication.application_id == "secure-rag")).mode == "protect"
