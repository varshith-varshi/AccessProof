"""Regression coverage for mixed retrieval and Shadow mode semantics."""
from datetime import datetime, timedelta, timezone

import httpx
import jwt
from fastapi.testclient import TestClient

from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache
from packages.rag_sdk import GuardClient, ProtectedRAG, RetrievedResource


def _setup_guard(tmp_path, monkeypatch, mode="protect"):
    cache = PolicyCache(str(tmp_path / ("guard-" + mode + ".db")))
    cache.install(1, [
        {"subject_id": "alice", "source_id": "drive", "resource_id": "public", "decision": "allow"},
        {"subject_id": "alice", "source_id": "drive", "resource_id": "restricted", "decision": "deny"},
    ])
    for key, value in {
        "cache": cache, "issuer": "https://issuer.example", "audience": "rag",
        "verification_key": "test-key-with-at-least-thirty-two-bytes",
        "identity_mode": "static", "expected_tenant": None,
        "subject_claim": "sub", "mode": mode, "fail_mode": "fail_closed",
    }.items():
        monkeypatch.setattr(guard_app, key, value)
    token = jwt.encode({
        "sub": "alice", "iss": "https://issuer.example", "aud": "rag",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5)
    }, "test-key-with-at-least-thirty-two-bytes", algorithm="HS256")
    return token


def _sdk(client: TestClient):
    def handler(request: httpx.Request) -> httpx.Response:
        upstream = client.request(
            request.method, request.url.path,
            headers={"Authorization": request.headers["Authorization"]},
            content=request.content,
        )
        return httpx.Response(upstream.status_code, content=upstream.content)
    return ProtectedRAG(GuardClient("https://local-guard.test", client=httpx.Client(transport=httpx.MockTransport(handler))), allow_unattested_metadata=True)


def test_mixed_retrieval_passes_only_allowed_content_to_generator(tmp_path, monkeypatch):
    token = _setup_guard(tmp_path, monkeypatch)
    with TestClient(guard_app.app) as client:
        observed = []
        result = _sdk(client).run(
            employee_token=token, application_id="rag", request_id="r-mixed",
            retrieved=[
                RetrievedResource("drive", "restricted", content="TOP SECRET"),
                RetrievedResource("drive", "public", content="PUBLIC FACT"),
            ],
            generate=lambda allowed: (observed.extend(x.content for x in allowed) or "PUBLIC FACT"),
            source_trace=lambda: [RetrievedResource("drive", "public")],
        )
        assert result.response == "PUBLIC FACT"
        assert observed == ["PUBLIC FACT"]


def test_all_denied_prevents_generator_execution(tmp_path, monkeypatch):
    token = _setup_guard(tmp_path, monkeypatch)
    with TestClient(guard_app.app) as client:
        def must_not_run(_):
            raise AssertionError("Model received forbidden content")
        result = _sdk(client).run(
            employee_token=token, application_id="rag",
            retrieved=[RetrievedResource("drive", "restricted", content="TOP SECRET")],
            generate=must_not_run,
        )
        assert result.response is None


def test_shadow_observes_denied_retrieval_without_blocking(tmp_path, monkeypatch):
    token = _setup_guard(tmp_path, monkeypatch, mode="shadow")
    with TestClient(guard_app.app) as client:
        seen = []
        result = _sdk(client).run(
            employee_token=token, application_id="rag",
            retrieved=[RetrievedResource("drive", "restricted", content="SHADOW EXAMPLE")],
            generate=lambda allowed: (seen.extend(x.content for x in allowed) or "SHADOW EXAMPLE"),
        )
        assert result.decision == "would_block"
        assert result.response == "SHADOW EXAMPLE"
        assert seen == ["SHADOW EXAMPLE"]


def test_layer2_rejection_never_triggers_legacy_regeneration_callback():
    class Guard:
        def filter_resources(self, **kwargs):
            return {"decision": "allow", "decision_id": "d1", "allowed": [{"source_id": "drive", "resource_id": "a"}]}
        def check_output(self, **kwargs):
            return {"decision": "block", "reason": "PROVENANCE_NOT_APPROVED"}

    calls = {"generate": 0, "regenerate": 0}
    result = ProtectedRAG(Guard(), allow_unattested_metadata=True).run(
        employee_token="mock", application_id="rag",
        retrieved=[RetrievedResource("drive", "a")],
        generate=lambda _: calls.__setitem__("generate", calls["generate"] + 1) or "candidate",
        regenerate=lambda _: calls.__setitem__("regenerate", calls["regenerate"] + 1) or "must not run",
        source_trace=lambda: [RetrievedResource("drive", "a")],
    )
    assert result.decision == "block"
    assert result.response is None
    assert calls == {"generate": 1, "regenerate": 0}



def test_shadow_reports_provenance_missing_without_blocking(tmp_path, monkeypatch):
    token = _setup_guard(tmp_path, monkeypatch, mode="shadow")
    with TestClient(guard_app.app) as client:
        response = client.post(
            "/guard/v1/check-output", headers={"Authorization": f"Bearer {token}"},
            json={"decision_id": "missing", "application_id": "rag",
                  "request_id": "invalid", "used_resource_ids": [],
                  "provenance": []},
        )
    assert response.status_code == 200
    assert response.json()["decision"] == "would_block"



def test_layer2_denies_revocation_between_retrieval_and_release(tmp_path, monkeypatch):
    token = _setup_guard(tmp_path, monkeypatch, mode="protect")
    guard_app.cache.set_application_bindings([
        {"application_id": "rag", "source_id": "drive", "mode": "protect", "source_acl_healthy": True}
    ])
    guard_app.cache.mark_sync_success()
    with TestClient(guard_app.app) as client:
        authorization = {"Authorization": f"Bearer {token}"}
        layer1 = client.post("/guard/v1/filter-resources", headers=authorization, json={
            "application_id": "rag", "request_id": "revocation-race",
            "resources": [{"source_id": "drive", "resource_id": "public"}],
        })
        assert layer1.status_code == 200
        assert layer1.json()["decision"] == "allow"

        # Revoke in Guard cache before model output could be released.
        guard_app.cache.install(2, [
            {"subject_id": "alice", "source_id": "drive", "resource_id": "public",
             "decision": "deny", "reason": "REVOKED_DURING_GENERATION"}
        ])
        layer2 = client.post("/guard/v1/check-output", headers=authorization, json={
            "application_id": "rag", "request_id": "revocation-race",
            "decision_id": layer1.json()["decision_id"],
            "used_resource_ids": ["public"],
            "provenance": [{"derived_id": "summary",
                            "source_resource_ids": ["public"]}],
        })
        assert layer2.status_code == 200
        assert layer2.json()["decision"] == "block"
        assert layer2.json()["reason"] == "LAYER2_ACCESS_REVOKED"


def test_inflight_shadow_context_cannot_bypass_new_protect_mode(tmp_path, monkeypatch):
    token = _setup_guard(tmp_path, monkeypatch, mode="shadow")
    guard_app.cache.set_application_bindings([
        {"application_id": "rag", "source_id": "drive", "mode": "shadow"}
    ])
    guard_app.cache.mark_sync_success()
    with TestClient(guard_app.app) as client:
        authorization = {"Authorization": f"Bearer {token}"}
        layer1 = client.post("/guard/v1/filter-resources", headers=authorization, json={
            "application_id": "rag", "request_id": "mode-change-race",
            "resources": [{"source_id": "drive", "resource_id": "restricted"}],
        })
        assert layer1.status_code == 200
        assert layer1.json()["decision"] == "would_block"

        # A Shadow request already in flight must not become a bypass.
        guard_app.cache.set_application_bindings([
            {"application_id": "rag", "source_id": "drive", "mode": "protect", "source_acl_healthy": True}
        ])
        layer2 = client.post("/guard/v1/check-output", headers=authorization, json={
            "application_id": "rag", "request_id": "mode-change-race",
            "decision_id": layer1.json()["decision_id"],
            "used_resource_ids": ["restricted"],
            "provenance": [{"derived_id": "answer",
                            "source_resource_ids": ["restricted"]}],
        })
        assert layer2.status_code == 200
        assert layer2.json()["decision"] == "block"
        assert layer2.json()["reason"] == "LAYER2_ACCESS_REVOKED"



def test_protect_denies_old_or_failed_drive_acl_sync(tmp_path, monkeypatch):
    token = _setup_guard(tmp_path, monkeypatch)
    authorization = {"Authorization": f"Bearer {token}"}
    cache = guard_app.cache
    cache.set_application_bindings([{
        "application_id": "rag", "source_id": "drive",
        "mode": "protect", "source_acl_healthy": False,
    }])
    cache.mark_sync_success()
    with TestClient(guard_app.app) as client:
        response = client.post("/guard/v1/filter-resources", headers=authorization, json={
            "application_id": "rag", "request_id": "acl-outage",
            "resources": [{"source_id": "drive", "resource_id": "public"}],
        })
        assert response.status_code == 503
        assert response.json()["detail"] == "SOURCE_ACL_STALE"

        cache.set_application_bindings([{
            "application_id": "rag", "source_id": "drive",
            "mode": "protect", "source_acl_healthy": True,
        }])
        response = client.post("/guard/v1/filter-resources", headers=authorization, json={
            "application_id": "rag", "request_id": "acl-recovered",
            "resources": [{"source_id": "drive", "resource_id": "public"}],
        })
        assert response.status_code == 200
        assert response.json()["decision"] == "allow"
