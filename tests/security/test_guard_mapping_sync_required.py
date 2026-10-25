"""Guard must not interpret an OIDC subject directly as a SharePoint employee ID."""
from datetime import datetime, timedelta, timezone

import jwt
from fastapi.testclient import TestClient

from apps.guard.accessproof_guard import app as guard
from apps.guard.accessproof_guard.cache import PolicyCache


def test_machine_guard_fails_closed_if_source_identity_mappings_not_synced(tmp_path, monkeypatch):
    cache = PolicyCache(str(tmp_path / "must-map.db"))
    cache.install(1, [{
        "subject_id": "same-subject", "source_id": "sharepoint-source",
        "resource_id": "document", "decision": "allow",
    }])
    cache.set_application_bindings([{
        "application_id": "customer-rag", "source_id": "sharepoint-source",
        "mode": "shadow", "source_acl_healthy": False,
    }])
    cache.mark_sync_success()
    key = "long-synthetic-jwt-signing-key-at-least-32"
    for prop, value in {
        "cache": cache, "guard_id": "machine-guard", "identity_mode": "static",
        "issuer": "https://issuer.example.test", "audience": "customer-rag",
        "verification_key": key, "expected_tenant": None, "subject_claim": "sub",
        "guard_credential": "synthetic-guard-machine",
    }.items():
        monkeypatch.setattr(guard, prop, value)
    token = jwt.encode({
        "sub": "same-subject", "iss": "https://issuer.example.test",
        "aud": "customer-rag",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }, key, algorithm="HS256")
    with TestClient(guard.app) as client:
        result = client.post("/guard/v1/filter-resources", headers={
            "Authorization": f"Bearer {token}",
        }, json={
            "application_id": "customer-rag", "request_id": "req",
            "resources": [{
                "source_id": "sharepoint-source", "resource_id": "document",
                "scope": "read", "chunk_ids": [],
            }],
        })
    assert result.status_code == 503
    assert result.json()["detail"] == "IDENTITY_MAPPINGS_NOT_SYNCED"
