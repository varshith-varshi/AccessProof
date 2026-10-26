from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine


def _account(client):
    return client.post("/api/v1/auth/signup", json={
        "email": "protect-admin@example.com",
        "password": "correct horse battery staple",
        "organization_name": "Protect organization",
    }).json()


def _headers(account):
    return {"Authorization": f"Bearer {account['session_token']}", "X-Organization-ID": account["organization_id"]}


def test_ai_application_is_tenant_scoped_and_protect_requires_readiness():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        account = _account(client)
        headers = _headers(account)
        created = client.post("/api/v1/current/ai-applications", headers=headers, json={"application_id": "finance-rag", "name": "Finance RAG"})
        assert created.status_code == 201
        listed = client.get("/api/v1/current/ai-applications", headers=headers)
        assert listed.status_code == 200
        assert listed.json()[0]["application_id"] == "finance-rag"
        readiness = client.get("/api/v1/current/ai-applications/finance-rag/protect-readiness", headers=headers)
        assert readiness.status_code == 200
        assert readiness.json()["ready"] is False
        blocked = client.patch("/api/v1/current/ai-applications/finance-rag/mode", headers=headers, json={"mode": "protect"})
        assert blocked.status_code == 409
        assert blocked.json()["detail"]["code"] == "PROTECT_NOT_READY"
        assert "GUARD_BOUND" in blocked.json()["detail"]["failed_checks"]
