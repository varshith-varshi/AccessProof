"""The Guard-protected Drive demo must never fall back to its legacy ACL path."""
import importlib.util
import time
from pathlib import Path

import httpx
from fastapi.testclient import TestClient
from packages.rag_sdk import GuardClient


def _demo(monkeypatch):
    for key, value in {
        "DRIVE_OWNER_TOKEN": "synthetic", "DRIVE_ROOT_FOLDER_ID": "test-root",
        "ALICE_EMAIL": "alice@example.invalid", "ALICE_RAG_TOKEN": "legacy-alice",
        "BOB_EMAIL": "bob@example.invalid", "BOB_RAG_TOKEN": "legacy-bob",
        "ACCESSPROOF_DEMO_GUARD_URL": "https://fake-guard.test",
        "ACCESSPROOF_DEMO_SOURCE_ID": "drive-source",
        "ACCESSPROOF_DEMO_APPLICATION_ID": "private-rag",
    }.items():
        monkeypatch.setenv(key, value)
    filename = Path(__file__).resolve().parents[2] / "drive-rag-demo" / "app.py"
    spec = importlib.util.spec_from_file_location("accessproof_drive_demo_test", filename)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    module.cached_files = [
        {"id": "allowed", "name": "Safe", "content": "PUBLIC CONTENT", "allowed": set()},
        {"id": "restricted", "name": "Restricted", "content": "SECRET CANARY", "allowed": set()},
    ]
    module.last_refresh = time.monotonic()
    return module


def _mock_guard(monkeypatch, module, *, allowed, decision="allow", layer2_decision="allow"):
    operations = []
    def handler(request):
        operations.append(request.url.path)
        if request.url.path.endswith("filter-resources"):
            requested = request.read()
            assert b"drive-source" in requested
            return httpx.Response(200, json={
                "decision_id": "once", "decision": decision,
                "allowed": [{"source_id": "drive-source", "resource_id": resource_id} for resource_id in allowed]
            })
        assert request.url.path.endswith("check-output")
        return httpx.Response(200, json={"decision": layer2_decision, "reason": "TEST"})
    monkeypatch.setattr(module, "GuardClient", lambda url: GuardClient(
        url, client=httpx.Client(transport=httpx.MockTransport(handler))
    ))
    return operations


def test_protected_drive_only_releases_allowed_document(monkeypatch):
    module = _demo(monkeypatch)
    operations = _mock_guard(monkeypatch, module, allowed=["allowed"])
    with TestClient(module.app) as client:
        response = client.post("/v1/protected-chat", headers={"Authorization": "Bearer synthetic-jwt"}, json={"message": "What do the documents say?"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["citations"] == ["allowed"]
    assert "PUBLIC CONTENT" in payload["answer"]
    assert "SECRET CANARY" not in str(payload)
    assert operations == ["/guard/v1/filter-resources", "/guard/v1/check-output"]


def test_protected_drive_does_not_release_denied_or_layer2_block(monkeypatch):
    module = _demo(monkeypatch)
    operations = _mock_guard(monkeypatch, module, allowed=[], decision="block")
    with TestClient(module.app) as client:
        response = client.post("/v1/protected-chat", headers={"Authorization": "Bearer synthetic-jwt"}, json={"message": "secret?"})
    assert response.status_code == 200
    assert "SECRET CANARY" not in str(response.json())
    assert operations == ["/guard/v1/filter-resources"]

    operations = _mock_guard(monkeypatch, module, allowed=["restricted"], layer2_decision="block")
    with TestClient(module.app) as client:
        response = client.post("/v1/protected-chat", headers={"Authorization": "Bearer synthetic-jwt"}, json={"message": "secret?"})
    assert response.status_code == 200
    assert "SECRET CANARY" not in str(response.json())
    assert operations == ["/guard/v1/filter-resources", "/guard/v1/check-output"]


def test_protected_drive_fails_closed_when_guard_unavailable(monkeypatch):
    module = _demo(monkeypatch)
    def fail(_):
        return GuardClient("https://fake-guard.test", client=httpx.Client(
            transport=httpx.MockTransport(lambda _: httpx.Response(503))
        ))
    monkeypatch.setattr(module, "GuardClient", fail)
    with TestClient(module.app) as client:
        response = client.post("/v1/protected-chat", headers={"Authorization": "Bearer synthetic-jwt"}, json={"message": "secret?"})
    assert response.status_code == 503
    assert "SECRET CANARY" not in response.text


def test_legacy_simulator_remains_independently_identified(monkeypatch):
    module = _demo(monkeypatch)
    assert "/v1/chat" in [route.path for route in module.app.routes]
    assert "/v1/protected-chat" in [route.path for route in module.app.routes]


def test_legacy_route_is_disabled_by_default(monkeypatch):
    module = _demo(monkeypatch)
    with TestClient(module.app) as client:
        response = client.post("/v1/chat", headers={"Authorization": "Bearer legacy-alice"},
                               json={"message": "Show my document"})
    assert response.status_code == 404
    assert "SECRET CANARY" not in response.text


def test_real_guard_enforcement_revocation_and_bob_denial(monkeypatch, tmp_path):
    """Exercise the real Guard routes, SDK and demo RAG together.

    This is a controlled synthetic policy test, not a live Google provider
    validation. Crucially it does not mock Layer 1/Layer 2 decisions.
    """
    from datetime import datetime, timedelta, timezone

    import jwt

    from apps.guard.accessproof_guard import app as guard_app
    from apps.guard.accessproof_guard.cache import PolicyCache

    rag = _demo(monkeypatch)
    policy = PolicyCache(str(tmp_path / "full-path-guard.db"))
    source = "drive-source"
    policy.install(1, [
        {"subject_id": "alice", "source_id": source, "resource_id": "allowed", "decision": "allow"},
        {"subject_id": "alice", "source_id": source, "resource_id": "restricted", "decision": "deny"},
        {"subject_id": "bob", "source_id": source, "resource_id": "allowed", "decision": "deny"},
        {"subject_id": "bob", "source_id": source, "resource_id": "restricted", "decision": "deny"},
    ])
    policy.set_application_bindings([{
        "application_id": "private-rag", "source_id": source, "mode": "protect",
        "source_acl_healthy": True,
    }])
    # Production-style machine Guards never infer source identity from an
    # unrelated OIDC subject. Install explicit verified synthetic mappings.
    policy.set_identity_mappings([
        {
            "source_id": source, "issuer": "https://test-issuer.example",
            "subject": employee, "tenant_id": "", "source_subject_id": employee,
        }
        for employee in ("alice", "bob")
    ])
    policy.mark_sync_success()
    key = "local-test-only-signing-key-with-32-characters"
    for name, value in {
        "cache": policy,
        "identity_mode": "static",
        "issuer": "https://test-issuer.example",
        "audience": "test-rag",
        "verification_key": key,
        "expected_tenant": None,
        "subject_claim": "sub",
        "guard_id": "test-guard",
        "guard_credential": "test-machine-credential",
        "max_policy_age_seconds": 180,
    }.items():
        monkeypatch.setattr(guard_app, name, value)

    def make_token(subject: str) -> str:
        return jwt.encode({
            "iss": "https://test-issuer.example",
            "aud": "test-rag",
            "sub": subject,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        }, key, algorithm="HS256")

    with TestClient(guard_app.app) as guard_client:
        def forward(request: httpx.Request) -> httpx.Response:
            response = guard_client.request(
                request.method,
                request.url.path,
                content=request.content,
                headers={"Authorization": request.headers.get("Authorization", "")},
            )
            return httpx.Response(response.status_code, content=response.content)

        monkeypatch.setattr(rag, "GuardClient", lambda url: GuardClient(
            url, client=httpx.Client(transport=httpx.MockTransport(forward)),
        ))

        with TestClient(rag.app) as rag_client:
            alice = {"Authorization": f"Bearer {make_token('alice')}"}
            bob = {"Authorization": f"Bearer {make_token('bob')}"}
            before = rag_client.post("/v1/protected-chat", headers=alice, json={"message": "show documents"})
            assert before.status_code == 200, before.text
            assert before.json()["citations"] == ["allowed"]
            assert "PUBLIC CONTENT" in before.json()["answer"]
            assert "SECRET CANARY" not in str(before.json())

            unauthorized = rag_client.post("/v1/protected-chat", headers=bob, json={"message": "show documents"})
            assert unauthorized.status_code == 200
            assert not unauthorized.json()["citations"]
            assert "PUBLIC CONTENT" not in str(unauthorized.json())
            assert "SECRET CANARY" not in str(unauthorized.json())

            policy.install(2, [
                {"subject_id": "alice", "source_id": source, "resource_id": "allowed",
                 "decision": "deny", "reason": "SOURCE_ACCESS_REVOKED"},
            ])
            revoked = rag_client.post("/v1/protected-chat", headers=alice, json={"message": "show documents"})
            assert revoked.status_code == 200
            assert not revoked.json()["citations"]
            assert "PUBLIC CONTENT" not in str(revoked.json())
            assert "SECRET CANARY" not in str(revoked.json())

    audits = policy.pending_audit(limit=100)
    assert any(event.get("layer", "layer1") == "layer2" and event["result"] == "allow" for event in audits)
    assert any(event["result"] == "block" and event["subject_id"] == "alice" for event in audits)
    assert any(event["result"] == "block" and event["subject_id"] == "bob" for event in audits)
