"""Automatic protection preflight is tenant isolated, repeatable and never fake-active."""
from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    Base, engine, SessionLocal, ProtectionActivationRun, AIApplication,
)


def _signup(client, label):
    response = client.post("/api/v1/auth/signup", json={
        "email": f"{label}@example.com", "password": "correct horse battery staple",
        "organization_name": f"Synthetic {label}",
    })
    assert response.status_code == 201, response.text
    account = response.json()
    return {"Authorization": f"Bearer {account['session_token']}", "X-Organization-ID": account["organization_id"]}


def test_one_click_checks_are_durable_idempotent_and_do_not_fake_activation():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        headers = _signup(client, "preflight-owner")
        source = client.post("/api/v1/current/sources", headers=headers, json={
            "provider": "microsoft365", "name": "SharePoint Preview", "boundary": "root",
            "credentials": {"drive_id": "drive1", "test_root_item_id": "root", "tenant_id": "11111111-2222-3333-4444-555555555555"},
        })
        assert source.status_code == 201, source.text
        guard = client.post("/api/v1/guards", headers=headers, json={"name": "synthetic-guard"})
        assert guard.status_code == 201, guard.text
        application = client.post("/api/v1/current/ai-applications", headers=headers, json={
            "application_id": "synthetic-rag", "name": "Synthetic RAG",
            "source_id": source.json()["id"], "guard_id": guard.json()["id"],
            "adapter_type": "accessproof-gateway", "adapter_contract_version": "accessproof.rag/v1",
        })
        assert application.status_code == 201, application.text
        path = "/api/v1/current/ai-applications/synthetic-rag/protection"
        before = client.get(path + "/status", headers=headers)
        assert before.status_code == 200
        assert before.json()["state"] == "protection_not_enabled"
        for action in ("enable", "enable", "retry"):
            response = client.post(path + "/" + action, headers=headers)
            assert response.status_code == 202, response.text
            payload = response.json()
            assert payload["state"] == "action_required"
            assert payload["guard_acknowledged"] is False
            assert payload["run_id"]
            checks = {check["code"]: check for check in payload["checks"]}
            assert not checks["CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED"]["ok"]
            assert not checks["MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED"]["ok"]
        with SessionLocal() as db:
            assert len(list(db.scalars(select(ProtectionActivationRun)))) == 1
            app_row = db.scalar(select(AIApplication).where(AIApplication.application_id == "synthetic-rag"))
            assert app_row.mode == "shadow"
        # Another organization must not see the registration or its preflight.
        outsider = _signup(client, "preflight-outsider")
        assert client.get(path + "/status", headers=outsider).status_code == 404
        assert client.post(path + "/enable", headers=outsider).status_code == 404
        assert client.post(path + "/enable").status_code == 401
