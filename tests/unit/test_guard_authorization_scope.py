"""The Guard issues a bounded, revision-bound resource scope for retrieval."""
from datetime import datetime, timedelta, timezone

import jwt
from fastapi.testclient import TestClient

from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache

REVISION_HASH = "a" * 64


def _setup(tmp_path, monkeypatch) -> tuple[PolicyCache, str]:
    cache = PolicyCache(str(tmp_path / "guard-scope.db"))
    cache.install(3, [
        {"subject_id": "alice", "source_id": "drive", "resource_id": "doc-b", "decision": "allow"},
        {"subject_id": "alice", "source_id": "drive", "resource_id": "doc-a", "decision": "allow"},
        {"subject_id": "alice", "source_id": "drive", "resource_id": "secret", "decision": "deny"},
        {"subject_id": "bob", "source_id": "drive", "resource_id": "doc-b", "decision": "allow"},
    ])
    cache.set_application_bindings([
        {"application_id": "rag", "source_id": "drive", "mode": "protect", "source_acl_healthy": True},
        {"application_id": "rag-unrevisioned", "source_id": "drive", "mode": "protect", "source_acl_healthy": True},
    ])
    cache.set_authorization_revisions([{
        "application_id": "rag", "revision": 7, "revision_hash": REVISION_HASH,
        "generated_at": "2026-10-24T00:00:00+00:00",
    }])
    cache.mark_sync_success()
    for key, value in {
        "cache": cache, "issuer": "https://issuer.example", "audience": "rag",
        "verification_key": "test-key-with-at-least-thirty-two-bytes",
        "identity_mode": "static", "expected_tenant": None,
        "subject_claim": "sub", "mode": "protect", "fail_mode": "fail_closed",
    }.items():
        monkeypatch.setattr(guard_app, key, value)
    token = jwt.encode({
        "sub": "alice", "iss": "https://issuer.example", "aud": "rag",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }, "test-key-with-at-least-thirty-two-bytes", algorithm="HS256")
    return cache, token


def _scope(client: TestClient, token: str, application_id: str = "rag"):
    return client.post(
        "/guard/v1/authorization-scope",
        headers={"Authorization": f"Bearer {token}"},
        json={"application_id": application_id, "request_id": "scope-request"},
    )


def test_scope_returns_only_allowed_resources_and_a_bound_revision(tmp_path, monkeypatch):
    cache, token = _setup(tmp_path, monkeypatch)
    with TestClient(guard_app.app) as client:
        response = _scope(client, token)
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "allow"
    assert body["reason"] == "AUTHORIZATION_SCOPE"
    assert body["source_id"] == "drive"
    assert body["allowed_resource_ids"] == ["doc-a", "doc-b"]
    assert "secret" not in body["allowed_resource_ids"]
    assert body["truncated"] is False
    assert body["scope_complete"] is True
    assert body["policy_version"] == 3
    assert body["authorization_revision"] == 7
    assert body["authorization_revision_hash"] == REVISION_HASH

    audit = cache.pending_audit()
    assert len(audit) == 1
    assert audit[0]["reason"] == "AUTHORIZATION_SCOPE"
    assert audit[0]["authorization_revision"] == 7
    assert audit[0]["authorization_revision_hash"] == REVISION_HASH
    assert audit[0]["resource_ids"] == ["doc-a", "doc-b"]
    assert audit[0]["occurred_at"]


def test_scope_requires_a_current_revision_for_protect(tmp_path, monkeypatch):
    _, token = _setup(tmp_path, monkeypatch)
    with TestClient(guard_app.app) as client:
        response = _scope(client, token, application_id="rag-unrevisioned")
    assert response.status_code == 503
    assert response.json()["detail"] == "AUTHORIZATION_REVISION_MISSING"


def test_truncated_scope_never_returns_a_partial_allow_set(tmp_path, monkeypatch):
    cache, token = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(
        cache, "allowed_resources",
        lambda subject_id, source_id, **kwargs: (["doc-a"], True),
    )
    with TestClient(guard_app.app) as client:
        response = _scope(client, token)
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "block"
    assert body["reason"] == "AUTHORIZATION_SCOPE_TRUNCATED"
    assert body["allowed_resource_ids"] == []
    assert body["truncated"] is True
    assert body["scope_complete"] is False


def test_cache_allowed_resources_reports_truncation_at_its_own_bound(tmp_path):
    cache = PolicyCache(str(tmp_path / "guard-scope-bound.db"))
    cache.install(1, [
        {"subject_id": "alice", "source_id": "drive", "resource_id": f"doc-{index}", "decision": "allow"}
        for index in range(4)
    ])
    values, truncated = cache.allowed_resources("alice", "drive", limit=2)
    assert values == ["doc-0", "doc-1"]
    assert truncated is True
    values, truncated = cache.allowed_resources("alice", "drive", limit=10)
    assert values == ["doc-0", "doc-1", "doc-2", "doc-3"]
    assert truncated is False
