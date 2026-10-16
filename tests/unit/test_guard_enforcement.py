from datetime import datetime, timedelta, timezone

import jwt
from fastapi.testclient import TestClient

from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache


def _token(*, tenant: str = "tenant-a") -> str:
    return jwt.encode(
        {"sub": "fallback", "oid": "BOB-123", "tid": tenant, "iss": "https://issuer", "aud": "rag", "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        "test-key-with-at-least-thirty-two-bytes", algorithm="HS256",
    )


def test_guard_binds_identity_tenant_request_and_one_time_provenance(tmp_path, monkeypatch) -> None:
    cache = PolicyCache(str(tmp_path / "guard.db"))
    cache.install(1, [
        {"subject_id": "BOB-123", "source_id": "drive", "resource_id": "F123", "decision": "deny", "reason": "NO_ACTIVE_GRANT_PATH"},
        {"subject_id": "BOB-123", "source_id": "drive", "resource_id": "H456", "decision": "allow", "reason": "ACTIVE_GRANT_PATH"},
    ])
    monkeypatch.setattr(guard_app, "cache", cache)
    monkeypatch.setattr(guard_app, "issuer", "https://issuer")
    monkeypatch.setattr(guard_app, "audience", "rag")
    monkeypatch.setattr(guard_app, "verification_key", "test-key-with-at-least-thirty-two-bytes")
    monkeypatch.setattr(guard_app, "expected_tenant", "tenant-a")
    monkeypatch.setattr(guard_app, "subject_claim", "oid")
    monkeypatch.setattr(guard_app, "mode", "protect")
    monkeypatch.setattr(guard_app, "fail_mode", "fail_closed")
    headers = {"Authorization": f"Bearer {_token()}"}
    with TestClient(guard_app.app) as client:
        filtered = client.post("/guard/v1/filter-resources", headers=headers, json={"application_id": "rag", "request_id": "r1", "resources": [{"source_id": "drive", "resource_id": "H456"}]}).json()
        assert filtered["decision"] == "allow"
        wrong_request = client.post("/guard/v1/check-output", headers=headers, json={"decision_id": filtered["decision_id"], "application_id": "rag", "request_id": "other", "used_resource_ids": ["H456"], "provenance": [{"source_resource_ids": ["H456"]}]}).json()
        assert wrong_request["reason"] == "DECISION_CONTEXT_INVALID"
        approved = client.post("/guard/v1/check-output", headers=headers, json={"decision_id": filtered["decision_id"], "application_id": "rag", "request_id": "r1", "used_resource_ids": ["H456"], "provenance": [{"source_resource_ids": ["H456"]}]}).json()
        assert approved["decision"] == "allow"
        replay = client.post("/guard/v1/check-output", headers=headers, json={"decision_id": filtered["decision_id"], "application_id": "rag", "request_id": "r1", "used_resource_ids": ["H456"], "provenance": [{"source_resource_ids": ["H456"]}]}).json()
        assert replay["reason"] == "DECISION_CONTEXT_INVALID"
        assert client.post("/guard/v1/filter-resources", headers={"Authorization": f"Bearer {_token(tenant='tenant-b')}"}, json={"application_id": "rag", "request_id": "r2", "resources": []}).status_code == 401
