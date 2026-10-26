"""Security regression: full local audit backlog must block covered Guard/SDK paths.

All identities, documents and transport responses here are synthetic.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import jwt
from fastapi.testclient import TestClient

from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache
from packages.rag_sdk.protection import GuardClient, ProtectedRAG, RetrievedResource


def _local_guard(tmp_path, monkeypatch, capacity: int):
    local_cache = PolicyCache(str(tmp_path / "isolated-audit-guard.db"), max_audit_records=capacity)
    local_cache.install(1, [
        {"subject_id": "alice", "source_id": "drive", "resource_id": "public",
         "decision": "allow", "scope": "read"}
    ])
    monkeypatch.setattr(guard_app, "cache", local_cache)
    monkeypatch.setattr(guard_app, "identity_mode", "static")
    monkeypatch.setattr(guard_app, "verification_key", "synthetic-audit-signing-key-with-32-plus-bytes")
    monkeypatch.setattr(guard_app, "issuer", "test-issuer")
    monkeypatch.setattr(guard_app, "audience", "test-audience")
    monkeypatch.setattr(guard_app, "expected_tenant", None)
    monkeypatch.setattr(guard_app, "subject_claim", "sub")
    monkeypatch.setattr(guard_app, "mode", "protect")
    monkeypatch.setattr(guard_app, "guard_id", None)
    monkeypatch.setattr(guard_app, "guard_credential", None)
    bearer = jwt.encode(
        {"sub": "alice", "iss": "test-issuer", "aud": "test-audience",
         "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        "synthetic-audit-signing-key-with-32-plus-bytes", algorithm="HS256",
    )
    return local_cache, bearer


def _sdk(server: TestClient):
    def respond(request: httpx.Request) -> httpx.Response:
        response = server.request(request.method, str(request.url),
                                  content=request.content, headers=dict(request.headers))
        return httpx.Response(response.status_code, content=response.content,
                              headers=dict(response.headers))
    return ProtectedRAG(GuardClient("http://testserver",
        client=httpx.Client(transport=httpx.MockTransport(respond))),
        allow_unattested_metadata=True)


def test_full_audit_buffer_returns_503_and_never_calls_model(tmp_path, monkeypatch):
    local_cache, bearer = _local_guard(tmp_path, monkeypatch, capacity=1)
    local_cache.buffer_audit(
        "offline-undelivered", application_id="app", subject_id="alice",
        request_id="previous", result="block", reason="TEST_ONLY", policy_version=1,
    )
    generated = []
    with TestClient(guard_app.app, raise_server_exceptions=False) as server:
        raw = server.post("/guard/v1/filter-resources",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"application_id": "test-app", "request_id": "offline",
                  "resources": [{"source_id": "drive", "resource_id": "public"}]})
        assert raw.status_code == 503
        assert raw.json()["detail"] == "AUDIT_BUFFER_FULL"

        result = _sdk(server).run(
            employee_token=bearer, application_id="test-app",
            retrieved=[RetrievedResource("drive", "public", content="synthetic")],
            generate=lambda resources: (generated.append(resources) or "NEVER_RELEASE"),
        )
    assert generated == []
    assert result.decision == "block"
    assert result.response is None
    assert [row["event_id"] for row in local_cache.pending_audit()] == ["offline-undelivered"]


def test_audit_failure_after_generation_never_releases_buffered_result(
    tmp_path, monkeypatch
):
    local_cache, bearer = _local_guard(tmp_path, monkeypatch, capacity=1)
    generated = []
    with TestClient(guard_app.app, raise_server_exceptions=False) as server:
        protected = _sdk(server).run(
            employee_token=bearer, application_id="test-app", request_id="second-layer",
            retrieved=[RetrievedResource("drive", "public", content="synthetic")],
            generate=lambda resources: (generated.append(resources) or "NEVER_RELEASE"),
            source_trace=lambda: [RetrievedResource("drive", "public")],
        )
    assert len(generated) == 1  # Layer 1 succeeded: buffer fills
    assert protected.response is None  # Layer 2 cannot durably audit its verdict
    assert protected.decision == "block"
    assert protected.reason == "GUARD_REQUEST_FAILED"
    assert len(local_cache.pending_audit()) == 1
