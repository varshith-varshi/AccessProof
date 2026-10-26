"""Adversarial tests for a customer-side Guard exposed to buggy/untrusted RAG traffic.

No customer credentials or production systems; tests use disposable cache and
synthetic requests. Fail before hardening, then remain as regressions.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from apps.guard.accessproof_guard.cache import PolicyCache
from apps.guard.accessproof_guard import app as guard_app


def test_future_dated_policy_sync_does_not_hide_stale_acl(tmp_path):
    policy = PolicyCache(str(tmp_path / "future-policy.db"))
    policy.install(1, [{
        "subject_id": "alice", "source_id": "source", "resource_id": "private",
        "scope": "read", "decision": "allow",
    }])
    policy.set_application_bindings([{
        "application_id": "rag", "source_id": "source", "mode": "protect",
        "source_acl_healthy": True,
    }])
    policy.mark_sync_success()
    # Clock jumped backward or persisted timestamp was from a future clock:
    # the previous implementation clamped negative ages to zero forever.
    future = (datetime.now(timezone.utc) + timedelta(days=180)).isoformat()
    with policy.db:
        policy.db.execute(
            "UPDATE metadata SET value=? WHERE key='last_policy_sync'", (future,),
        )
    assert policy.sync_age_seconds() is None
    assert policy.version() == 1


def test_unbounded_filter_batch_must_be_rejected_before_work(monkeypatch, tmp_path):
    policy = PolicyCache(str(tmp_path / "batch.db"))
    policy.mark_sync_success()
    policy.set_application_bindings([{
        "application_id": "rag", "source_id": "source", "mode": "protect",
        "source_acl_healthy": True,
    }])
    monkeypatch.setattr(guard_app, "cache", policy)
    # The request is intentionally missing identity to ensure oversized
    # batches are rejected by schema validation BEFORE any identity/ACL work.
    with TestClient(guard_app.app) as client:
        result = client.post("/guard/v1/filter-resources", json={
            "application_id": "rag", "request_id": "oversized",
            "resources": [
                {"source_id": "source", "resource_id": f"file-{i}"}
                for i in range(5001)
            ],
        })
    assert result.status_code == 422


def test_unbounded_layer2_provenance_must_be_rejected(monkeypatch, tmp_path):
    policy = PolicyCache(str(tmp_path / "layer2-batch.db"))
    monkeypatch.setattr(guard_app, "cache", policy)
    with TestClient(guard_app.app) as client:
        result = client.post("/guard/v1/check-output", json={
            "decision_id": "synthetic", "application_id": "rag",
            "request_id": "oversized",
            "provenance": [
                {"source_resource_ids": [f"file-{i}"]}
                for i in range(5001)
            ],
        })
    assert result.status_code == 422


def test_nested_chunk_ids_are_bounded_without_identity_lookup(monkeypatch, tmp_path):
    policy = PolicyCache(str(tmp_path / "chunk-limit.db"))
    monkeypatch.setattr(guard_app, "cache", policy)
    with TestClient(guard_app.app) as client:
        response = client.post("/guard/v1/filter-resources", json={
            "application_id": "rag", "request_id": "oversized-chunks",
            "resources": [{
                "source_id": "source", "resource_id": "file",
                "chunk_ids": [f"chunk-{i}" for i in range(129)],
            }],
        })
    assert response.status_code == 422


def test_oversized_source_resource_identifier_is_rejected(monkeypatch, tmp_path):
    policy = PolicyCache(str(tmp_path / "resource-limit.db"))
    monkeypatch.setattr(guard_app, "cache", policy)
    with TestClient(guard_app.app) as client:
        response = client.post("/guard/v1/filter-resources", json={
            "application_id": "rag", "request_id": "oversized-id",
            "resources": [{
                "source_id": "source", "resource_id": "x" * 1025,
            }],
        })
    assert response.status_code == 422


def test_unenrolled_production_guard_cannot_fallback_to_unbound_application(
    monkeypatch, tmp_path,
):
    from fastapi import HTTPException

    policy = PolicyCache(str(tmp_path / "legacy-guard-policy.db"))
    policy.install(1, [{
        "subject_id": "alice", "source_id": "source", "resource_id": "payroll",
        "scope": "read", "decision": "allow",
    }])
    policy.mark_sync_success()
    monkeypatch.setattr(guard_app, "cache", policy)
    monkeypatch.setattr(guard_app, "guard_id", None)
    monkeypatch.setattr(guard_app, "guard_credential", None)
    monkeypatch.setattr(guard_app, "mode", "protect")
    monkeypatch.setenv("ACCESSPROOF_ENV", "production")
    # No authoritative app/source bindings exist. A stale legacy local grant
    # must not authorize ANY arbitrary application in production mode.
    import pytest
    with pytest.raises(HTTPException) as error:
        guard_app._application_mode("arbitrary-customer-app")
    assert error.value.status_code == 503


def test_invalid_principal_or_resource_type_cannot_become_a_string_grant(tmp_path):
    import pytest

    policy = PolicyCache(str(tmp_path / "identity-typing.db"))
    for index, key in enumerate(("subject_id", "source_id", "resource_id", "scope")):
        for bad in (None, 1, True, ""):
            record = {
                "subject_id": "alice",
                "source_id": "drive",
                "resource_id": "restricted",
                "scope": "read",
                "decision": "allow",
            }
            record[key] = bad
            with pytest.raises(ValueError):
                policy.install(index + 1, [record])
            assert policy.version() == 0
    assert policy.decide("None", "drive", "restricted", "read")[0] == "unknown"
    assert policy.decide("1", "drive", "restricted", "read")[0] == "unknown"


def test_mutated_retrieval_list_during_guard_io_cannot_change_model_input():
    from packages.rag_sdk.protection import ProtectedRAG, RetrievedResource

    original = RetrievedResource("drive", "approved", content="PUBLIC_SAFE")
    shared_list = [original]
    seen: list[str] = []

    class GuardReplacingCallerList:
        def filter_resources(self, *, resources, **kwargs):
            assert resources[0].content == "PUBLIC_SAFE"
            # Mimics a shared retriever/cache list changing during synchronous
            # Guard network I/O. The resource ID remains authorized.
            shared_list[0] = RetrievedResource(
                "drive", "approved", content="PRIVATE_CANARY",
            )
            return {
                "mode": "protect", "decision": "allow", "decision_id": "d",
                "allowed": [{
                    "source_id": "drive", "resource_id": "approved", "chunk_ids": [],
                }],
            }

        def check_output(self, **kwargs):
            return {"decision": "allow", "reason": "TRUSTED_PROVENANCE_VALID"}

    result = ProtectedRAG(GuardReplacingCallerList(), allow_unattested_metadata=True).run(
        employee_token="synthetic", application_id="rag",
        retrieved=shared_list,
        generate=lambda docs: seen.append(docs[0].content) or docs[0].content,
        source_trace=lambda: [original],
    )
    assert result.decision == "allow"
    assert result.response == "PUBLIC_SAFE"
    assert seen == ["PUBLIC_SAFE"]


def test_missing_deployment_env_must_not_enable_unbound_guard_fallback(
    monkeypatch, tmp_path,
):
    import pytest
    from fastapi import HTTPException

    policy = PolicyCache(str(tmp_path / "unenrolled-default-deny.db"))
    policy.install(1, [{
        "subject_id": "alice", "source_id": "source",
        "resource_id": "payroll", "decision": "allow",
    }])
    policy.mark_sync_success()
    monkeypatch.setattr(guard_app, "cache", policy)
    monkeypatch.setattr(guard_app, "guard_id", None)
    monkeypatch.setattr(guard_app, "guard_credential", None)
    monkeypatch.delenv("ACCESSPROOF_ENV", raising=False)
    monkeypatch.delenv("ACCESSPROOF_GUARD_STANDALONE_TEST_MODE", raising=False)
    with pytest.raises(HTTPException) as error:
        guard_app._application_mode("unknown-application")
    assert error.value.status_code == 503


def test_chunked_oversized_body_is_rejected_before_json_parsing(monkeypatch, tmp_path):
    policy = PolicyCache(str(tmp_path / "body-limit.db"))
    monkeypatch.setattr(guard_app, "cache", policy)
    monkeypatch.setattr(guard_app, "max_request_bytes", 128)
    with TestClient(guard_app.app) as client:
        response = client.post(
            "/guard/v1/filter-resources",
            content=b"{" + b"x" * 256 + b"}",
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 413
