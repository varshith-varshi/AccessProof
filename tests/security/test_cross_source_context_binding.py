"""Synthetic cross-source race: a Layer 1 decision cannot be reused after app source rebinding."""
from datetime import datetime, timedelta, timezone

import jwt
from fastapi.testclient import TestClient

from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache


def test_layer2_rejects_context_from_previous_source_after_rebinding(tmp_path, monkeypatch):
    policy = PolicyCache(str(tmp_path / "source-rebind.db"))
    key = "synthetic-bind-key-with-more-than-32-characters"
    policy.install(1, [
        {"subject_id": "alice", "source_id": "drive-tenant-a",
         "resource_id": "same-local-id", "decision": "allow"},
        {"subject_id": "alice", "source_id": "drive-tenant-b",
         "resource_id": "same-local-id", "decision": "allow"},
    ])
    policy.set_application_bindings([{
        "application_id": "rag", "source_id": "drive-tenant-a",
        "mode": "protect", "source_acl_healthy": True,
    }])
    policy.mark_sync_success()
    for attr, value in {
        "cache": policy, "identity_mode": "static", "issuer": "https://local",
        "audience": "rag", "verification_key": key, "expected_tenant": None,
        "subject_claim": "sub", "max_policy_age_seconds": 300,
    }.items():
        monkeypatch.setattr(guard_app, attr, value)
    token = jwt.encode({
        "sub": "alice", "iss": "https://local", "aud": "rag",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }, key, algorithm="HS256")
    headers = {"Authorization": f"Bearer {token}"}
    with TestClient(guard_app.app) as client:
        first = client.post("/guard/v1/filter-resources", headers=headers, json={
            "application_id": "rag", "request_id": "source-switch",
            "resources": [{"source_id": "drive-tenant-a", "resource_id": "same-local-id"}],
        })
        assert first.status_code == 200
        assert first.json()["decision"] == "allow"
        # A trusted sync updates the app binding, without revoking either source.
        # Old model output from drive-tenant-a must not be reinterpreted as B.
        policy.set_application_bindings([{
            "application_id": "rag", "source_id": "drive-tenant-b",
            "mode": "protect", "source_acl_healthy": True,
        }])
        policy.mark_sync_success()
        output = client.post("/guard/v1/check-output", headers=headers, json={
            "application_id": "rag", "request_id": "source-switch",
            "decision_id": first.json()["decision_id"],
            "used_resource_ids": ["same-local-id"],
            "provenance": [{"source_resource_ids": ["same-local-id"]}],
        })
        assert output.status_code == 200
        assert output.json()["decision"] == "block", output.json()
