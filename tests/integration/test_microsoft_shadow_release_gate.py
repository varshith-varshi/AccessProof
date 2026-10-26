"""Microsoft source is preview only; Guard Protect can never be activated yet."""
from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine


def test_microsoft_protect_readiness_reports_blocker_and_rejects_mode():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        account_response = client.post("/api/v1/auth/signup", json={
            "email": "ms-shadow-release@example.com",
            "password": "correct horse battery staple",
            "organization_name": "Microsoft Shadow Customer",
        })
        assert account_response.status_code == 201, account_response.text
        account = account_response.json()
        headers = {
            "Authorization": f"Bearer {account['session_token']}",
            "X-Organization-ID": account["organization_id"],
        }
        invalid = client.post("/api/v1/current/sources", headers=headers, json={
            "provider": "microsoft365", "name": "Invalid", "boundary": "root",
            "credentials": {"access_token": "fake", "drive_id": "d1", "test_root_item_id": "other"},
        })
        assert invalid.status_code == 422

        source_response = client.post("/api/v1/current/sources", headers=headers, json={
            "provider": "microsoft365", "name": "SharePoint Preview", "boundary": "root",
            "credentials": {"access_token": "synthetic", "drive_id": "d1", "test_root_item_id": "root", "tenant_id": "11111111-2222-3333-4444-555555555555"},
        })
        assert source_response.status_code == 201, source_response.text
        guard_response = client.post("/api/v1/guards", headers=headers, json={
            "name": "preview-guard",
        })
        assert guard_response.status_code == 201, guard_response.text
        create = client.post("/api/v1/current/ai-applications", headers=headers, json={
            "application_id": "ms-preview-rag", "name": "Preview RAG",
            "guard_id": guard_response.json()["id"],
            "source_id": source_response.json()["id"],
            "adapter_type": "accessproof-gateway",
            "adapter_contract_version": "accessproof.rag/v1",
        })
        assert create.status_code == 201, create.text
        ready = client.get("/api/v1/current/ai-applications/ms-preview-rag/protect-readiness",
                           headers=headers)
        assert ready.status_code == 200
        assert not ready.json()["ready"]
        checks = {item["code"]: item for item in ready.json()["checks"]}
        assert checks["MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED"]["ok"] is False
        patch = client.patch("/api/v1/current/ai-applications/ms-preview-rag/mode", headers=headers,
                             json={"mode": "protect"})
        assert patch.status_code == 409
        assert "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED" in patch.json()["detail"]["failed_checks"]
