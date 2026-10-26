"""Late cache/tool provenance must not bypass per-resource Layer 1 enforcement."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import jwt
from fastapi.testclient import TestClient

from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache
from packages.rag_core import GuardClient, ProtectedRAG, RetrievedResource


def _environment(tmp_path, monkeypatch):
    policy = PolicyCache(str(tmp_path / "late-sources.db"))
    policy.install(1, [
        {"subject_id": "alice", "source_id": "drive", "resource_id": "file-1", "decision": "allow"},
        {"subject_id": "alice", "source_id": "drive", "resource_id": "file-2", "decision": "allow"},
        {"subject_id": "alice", "source_id": "drive", "resource_id": "denied", "decision": "deny"},
        {"subject_id": "bob", "source_id": "drive", "resource_id": "file-2", "decision": "allow"},
    ])
    policy.set_application_bindings([{"application_id": "rag", "source_id": "drive", "mode": "protect", "source_acl_healthy": True}])
    policy.mark_sync_success()
    secret = "local-testing-key-with-at-least-32-bytes"
    for name, value in {
        "cache": policy, "identity_mode": "static", "issuer": "https://id.example",
        "audience": "rag", "verification_key": secret, "expected_tenant": None,
        "subject_claim": "sub", "max_policy_age_seconds": 300,
    }.items():
        monkeypatch.setattr(guard_app, name, value)

    def header(sub="alice"):
        token = jwt.encode({
            "sub": sub, "iss": "https://id.example", "aud": "rag",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        }, secret, algorithm="HS256")
        return {"Authorization": f"Bearer {token}"}

    return policy, header


def _filter(client, headers, request_id, resource):
    response = client.post("/guard/v1/filter-resources", headers=headers, json={
        "application_id": "rag", "request_id": request_id,
        "resources": [{"source_id": "drive", "resource_id": resource}],
    })
    assert response.status_code == 200, response.text
    return response.json()


def _output(client, headers, request_id, first_id, resource_ids, additional_ids=None):
    response = client.post("/guard/v1/check-output", headers=headers, json={
        "application_id": "rag", "request_id": request_id,
        "decision_id": first_id,
        "additional_decision_ids": additional_ids or [],
        "used_resource_ids": resource_ids,
        "provenance": [{"derived_type": "cache", "source_resource_ids": resource_ids}],
    })
    assert response.status_code == 200, response.text
    return response.json()


def _sdk(client):
    operations = []

    def forward(request):
        operations.append((request.url.path, request.content))
        result = client.request(
            request.method, request.url.path, content=request.content,
            headers={"Authorization": request.headers["Authorization"]},
        )
        return httpx.Response(result.status_code, content=result.content)

    guard = GuardClient("https://customer-guard.test",
                        client=httpx.Client(transport=httpx.MockTransport(forward)))
    return ProtectedRAG(guard, allow_unattested_metadata=True), operations


def test_sdk_allows_authorized_late_cached_source_with_second_layer1(tmp_path, monkeypatch):
    _, header = _environment(tmp_path, monkeypatch)
    with TestClient(guard_app.app) as client:
        sdk, calls = _sdk(client)
        observed = []
        result = sdk.run(
            employee_token=header()["Authorization"].split(" ", 1)[1],
            application_id="rag", request_id="cache-good",
            retrieved=[RetrievedResource("drive", "file-1", "chunk1", "initial context")],
            generate=lambda context: (observed.extend(x.resource_id for x in context)
                                      or "Response incorporating approved cached fact"),
            source_trace=lambda: [
                RetrievedResource("drive", "file-1", "chunk1"),
                RetrievedResource("drive", "file-2", "cached2", derived_type="cache"),
            ],
        )
        assert result.decision == "allow"
        assert result.response == "Response incorporating approved cached fact"
        assert observed == ["file-1"]
        assert [path for path, _ in calls] == [
            "/guard/v1/filter-resources", "/guard/v1/filter-resources", "/guard/v1/check-output"
        ]
        assert b"additional_decision_ids" in calls[-1][1]
        assert b"file-2" in calls[-1][1]


def test_sdk_denied_or_unknown_late_source_is_blocked(tmp_path, monkeypatch):
    _, header = _environment(tmp_path, monkeypatch)
    with TestClient(guard_app.app) as client:
        for key in ("denied", "unregistered"):
            sdk, calls = _sdk(client)
            result = sdk.run(
                employee_token=header()["Authorization"].split(" ", 1)[1],
                application_id="rag", request_id=f"late-{key}",
                retrieved=[RetrievedResource("drive", "file-1")],
                generate=lambda _: "not safe to release",
                source_trace=lambda key=key: [
                    RetrievedResource("drive", "file-1"),
                    RetrievedResource("drive", key, derived_type="cache"),
                ],
            )
            assert result.decision == "block"
            assert result.response is None
            assert result.reason == "ADDITIONAL_SOURCE_NOT_AUTHORIZED"
            assert len(calls) == 2  # Never reaches the output-release check.


def test_extra_source_without_layer1_decision_remains_blocked(tmp_path, monkeypatch):
    _, header = _environment(tmp_path, monkeypatch)
    with TestClient(guard_app.app) as client:
        first = _filter(client, header(), "unverified-extra", "file-1")
        result = _output(client, header(), "unverified-extra", first["decision_id"], ["file-1", "file-2"])
        assert result["decision"] == "block"
        assert result["reason"] == "PROVENANCE_ESCAPE"


def test_additional_decision_must_match_same_employee_and_request(tmp_path, monkeypatch):
    _, header = _environment(tmp_path, monkeypatch)
    with TestClient(guard_app.app) as client:
        first = _filter(client, header(), "request-one", "file-1")
        second = _filter(client, header(), "request-two", "file-2")
        result = _output(client, header(), "request-one", first["decision_id"], ["file-1", "file-2"], [second["decision_id"]])
        assert result["reason"] == "DECISION_CONTEXT_INVALID"
        assert result["decision"] == "block"
        # A secondary decision cannot be borrowed from a different employee, either.
        third = _filter(client, header(), "request-three", "file-1")
        fourth = _filter(client, header("bob"), "request-three", "file-2")
        assert fourth["decision"] == "allow"  # Authorization alone cannot transfer context.
        result = _output(client, header(), "request-three", third["decision_id"], ["file-1", "file-2"], [fourth["decision_id"]])
        assert result["decision"] == "block"


def test_extra_authorized_source_must_still_be_allowed_at_release(tmp_path, monkeypatch):
    policy, header = _environment(tmp_path, monkeypatch)
    with TestClient(guard_app.app) as client:
        first = _filter(client, header(), "race", "file-1")
        extra = _filter(client, header(), "race", "file-2")
        policy.install(2, [
            {"subject_id": "alice", "source_id": "drive", "resource_id": "file-2",
             "decision": "deny", "reason": "REVOKED"},
        ])
        result = _output(client, header(), "race", first["decision_id"],
                         ["file-1", "file-2"], [extra["decision_id"]])
        assert result == {"decision": "block", "reason": "LAYER2_ACCESS_REVOKED", "policy_version": 2}


def test_extra_allowed_subset_and_replay_rejected(tmp_path, monkeypatch):
    _, header = _environment(tmp_path, monkeypatch)
    with TestClient(guard_app.app) as client:
        first = _filter(client, header(), "subset", "file-1")
        extra = _filter(client, header(), "subset", "file-2")
        result = _output(client, header(), "subset", first["decision_id"], ["file-2"], [extra["decision_id"]])
        assert result["decision"] == "allow"  # A subset of checked sources is valid.
        replay = _output(client, header(), "subset", first["decision_id"], ["file-2"], [extra["decision_id"]])
        assert replay["decision"] == "block"
        assert replay["reason"] == "DECISION_CONTEXT_INVALID"


def test_explicit_empty_or_invalid_trace_fails_closed(tmp_path, monkeypatch):
    _, header = _environment(tmp_path, monkeypatch)
    with TestClient(guard_app.app) as client:
        sdk, _ = _sdk(client)
        for trace in (lambda: [], lambda: [RetrievedResource("", "file-1")],
                      lambda: (_ for _ in ()).throw(ValueError("broken trace"))):
            result = sdk.run(
                employee_token=header()["Authorization"].split(" ", 1)[1],
                application_id="rag", retrieved=[RetrievedResource("drive", "file-1")],
                generate=lambda _: "no verified provenance", source_trace=trace,
            )
            assert result.response is None
            assert result.reason == "PROVENANCE_MISSING"
