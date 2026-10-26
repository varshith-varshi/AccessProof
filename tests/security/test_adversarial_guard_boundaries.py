"""Local synthetic adversarial tests for the Guard's public enforcement API.

No external networks, real Google accounts, or production databases.
"""
from __future__ import annotations

import importlib
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from apps.guard.accessproof_guard.cache import PolicyCache
from packages.rag_core.protection import GuardClient, ProtectedRAG, RetrievedResource


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    module = importlib.import_module("apps.guard.accessproof_guard.app")
    local_cache = PolicyCache(str(tmp_path / "isolated-adversarial-cache.db"))
    entries = [
        {"subject_id": "alice", "source_id": "src-alpha", "resource_id": "finance", "scope": "read", "decision": "allow"},
        {"subject_id": "bob", "source_id": "src-alpha", "resource_id": "finance", "scope": "read", "decision": "deny"},
        {"subject_id": "bob", "source_id": "src-alpha", "resource_id": "handbook", "scope": "read", "decision": "allow"},
        {"subject_id": "bob", "source_id": "src-beta", "resource_id": "beta-secret", "scope": "read", "decision": "deny"},
    ]
    local_cache.install(1, entries, full_snapshot=True)
    local_cache.set_application_bindings([
        {"application_id": "alpha-rag", "source_id": "src-alpha", "mode": "protect", "source_acl_healthy": True}
    ])
    local_cache.mark_sync_success()
    monkeypatch.setattr(module, "cache", local_cache)
    monkeypatch.setattr(module, "identity_mode", "static")
    monkeypatch.setattr(module, "verification_key", "isolated-adversarial-HS256-signing-key")
    monkeypatch.setattr(module, "issuer", "local-issuer")
    monkeypatch.setattr(module, "audience", "local-audience")
    monkeypatch.setattr(module, "expected_tenant", "alpha")
    monkeypatch.setattr(module, "subject_claim", "sub")

    def token(subject: str, *, tenant: str = "alpha") -> str:
        return jwt.encode({
            "iss": "local-issuer", "aud": "local-audience", "sub": subject,
            "tid": tenant, "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        }, "isolated-adversarial-HS256-signing-key", algorithm="HS256")

    return module, local_cache, TestClient(module.app), token


def _filter(client, token, resources, *, request_id="attack-r1", extra_headers=None):
    return client.post("/guard/v1/filter-resources", headers={
        "Authorization": f"Bearer {token}", **(extra_headers or {}),
    }, json={"application_id": "alpha-rag", "request_id": request_id, "resources": [
        {"source_id": source, "resource_id": resource} for source, resource in resources
    ]})


def test_t1_bob_finance_denied_before_llm_while_handbook_works(sandbox):
    _, _, client, token = sandbox
    response = _filter(client, token("bob"), [
        ("src-alpha", "finance"), ("src-alpha", "handbook")
    ])
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "allow"
    assert {(x["source_id"], x["resource_id"]) for x in body["allowed"]} == {
        ("src-alpha", "handbook")
    }
    assert {x["resource_id"] for x in body["denied"]} == {"finance"}


def test_t2_bob_cannot_spoof_alice_with_headers_or_body(sandbox):
    _, _, client, token = sandbox
    forged = _filter(client, token("bob"), [("src-alpha", "finance")],
                     extra_headers={"X-User-Id": "alice", "X-Email": "alice@example.com",
                                    "X-Organization-ID": "alpha", "X-Principal": "alice"})
    assert forged.status_code == 200
    assert forged.json()["allowed"] == []
    assert forged.json()["decision"] == "block"
    # The machine-facing Guard contract rejects attacker-supplied identity or
    # bypass fields.  It never accepts an alternative principal alongside the
    # verified bearer token.
    forged_body = client.post("/guard/v1/filter-resources", headers={
        "Authorization": f"Bearer {token('bob')}",
    }, json={
        "application_id": "alpha-rag", "request_id": "forged-body",
        "principal": "alice", "email": "alice@example.com",
        "tenant_id": "alpha", "bypass_auth": True,
        "resources": [{"source_id": "src-alpha", "resource_id": "finance"}],
    })
    assert forged_body.status_code == 422
    valid = _filter(client, token("alice"), [("src-alpha", "finance")])
    assert valid.status_code == 200
    assert valid.json()["decision"] == "allow"


def test_static_identity_refuses_a_short_hmac_secret(monkeypatch, tmp_path):
    """A weak shared JWT key is not an acceptable production identity boundary."""
    import jwt
    from datetime import datetime, timedelta, timezone
    from fastapi.testclient import TestClient
    from apps.guard.accessproof_guard import app as guard_app
    from apps.guard.accessproof_guard.cache import PolicyCache

    monkeypatch.setattr(guard_app, "cache", PolicyCache(str(tmp_path / "weak-key.db")))
    monkeypatch.setattr(guard_app, "identity_mode", "static")
    monkeypatch.setattr(guard_app, "issuer", "https://issuer.test")
    monkeypatch.setattr(guard_app, "audience", "rag")
    monkeypatch.setattr(guard_app, "verification_key", "too-short")
    monkeypatch.setattr(guard_app, "subject_claim", "sub")
    token = jwt.encode({
        "sub": "alice", "iss": "https://issuer.test", "aud": "rag",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }, "too-short", algorithm="HS256")
    with TestClient(guard_app.app) as client:
        response = client.post("/guard/v1/filter-resources", headers={
            "Authorization": f"Bearer {token}",
        }, json={"application_id": "rag", "request_id": "weak-key", "resources": []})
    assert response.status_code == 503
    assert response.json()["detail"] == "IDENTITY_STATIC_KEY_UNSAFE"


def test_t3_cross_tenant_source_metadata_and_identity_rejected(sandbox):
    _, _, client, token = sandbox
    wrong_source = _filter(client, token("bob"), [("src-beta", "beta-secret")])
    assert wrong_source.status_code == 403
    assert "beta-secret" not in wrong_source.text
    wrong_tenant = _filter(client, token("bob", tenant="beta"), [("src-alpha", "handbook")])
    assert wrong_tenant.status_code == 401
    assert _filter(client, token("bob"), [("src-alpha", "handbook")]).json()["decision"] == "allow"


def test_t4_protect_stale_policy_fails_closed(sandbox, monkeypatch):
    _, local_cache, client, token = sandbox
    assert _filter(client, token("alice"), [("src-alpha", "finance")]).json()["decision"] == "allow"
    monkeypatch.setattr(local_cache, "sync_age_seconds", lambda: 99999.0)
    response = _filter(client, token("alice"), [("src-alpha", "finance")])
    assert response.status_code == 503
    assert "POLICY_SYNC_STALE" in response.text


def test_t5_buffered_stream_with_untrusted_late_source_releases_no_canary(sandbox):
    _, _, client, token = sandbox

    def transport(request: httpx.Request) -> httpx.Response:
        reply = client.request(request.method, str(request.url),
                               headers=dict(request.headers), content=request.content)
        return httpx.Response(reply.status_code, content=reply.content, headers=reply.headers)

    guard = GuardClient("http://testserver",
                        client=httpx.Client(transport=httpx.MockTransport(transport)))
    canary = "SYNTHETIC_BETA_SECRET_NOT_FOR_BOB"
    emitted = []

    def model(resources):
        assert [r.resource_id for r in resources] == ["handbook"]
        yield canary[:12]
        yield canary[12:]

    protected = ProtectedRAG(guard, allow_unattested_metadata=True).run(
        employee_token=token("bob"), application_id="alpha-rag",
        retrieved=[RetrievedResource("src-alpha", "handbook", content="Public handbook")],
        generate=model,
        source_trace=lambda: [
            RetrievedResource("src-alpha", "handbook"),
            RetrievedResource("src-beta", "beta-secret"),
        ],
    )
    if protected.response is not None:
        emitted.append(protected.response)
    assert canary not in "".join(emitted)
    assert protected.response is None
    assert protected.decision == "block"


def test_h01_revocation_between_layer2_recheck_and_release_must_deny(sandbox, monkeypatch):
    """A policy effective before final context consumption must never be ignored."""
    _, local_cache, client, token = sandbox
    bearer = token("alice")
    response = _filter(client, bearer, [("src-alpha", "finance")], request_id="revocation-race")
    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
    decision_id = response.json()["decision_id"]
    original_decide = local_cache.decide
    revoked = False

    def revoke_immediately_after_first_layer2_allow(subject, source, resource, scope):
        nonlocal revoked
        decision = original_decide(subject, source, resource, scope)
        if (not revoked and subject == "alice" and resource == "finance"
                and decision[0] == "allow"):
            revoked = True
            local_cache.install(2, [{
                "subject_id": "alice", "source_id": "src-alpha",
                "resource_id": "finance", "scope": "read", "decision": "deny"
            }])
        return decision

    monkeypatch.setattr(local_cache, "decide", revoke_immediately_after_first_layer2_allow)
    checked = client.post("/guard/v1/check-output",
        headers={"Authorization": f"Bearer {bearer}"},
        json={"decision_id": decision_id, "request_id": "revocation-race",
              "application_id": "alpha-rag", "used_resource_ids": ["finance"],
              "provenance": [{"derived_id": "chunk-1", "source_resource_ids": ["finance"]}]})
    assert revoked
    assert checked.status_code == 200
    assert checked.json()["decision"] == "block", checked.json()
    assert original_decide("alice", "src-alpha", "finance", "read")[0] == "deny"


def test_d06_mode_switch_during_final_verification_cannot_release(sandbox, monkeypatch):
    """A new authoritative Shadow binding must not release an in-flight Protect response."""
    _, local_cache, client, token = sandbox
    bearer = token("alice")
    initial = _filter(client, bearer, [("src-alpha", "finance")], request_id="mode-race")
    assert initial.json()["decision"] == "allow"
    original_decide = local_cache.decide
    switched = False

    def switch_mode_after_first_check(subject, source, resource, scope):
        nonlocal switched
        decision = original_decide(subject, source, resource, scope)
        if not switched:
            switched = True
            local_cache.set_application_bindings([{
                "application_id": "alpha-rag", "source_id": "src-alpha",
                "mode": "shadow", "source_acl_healthy": True
            }])
        return decision

    monkeypatch.setattr(local_cache, "decide", switch_mode_after_first_check)
    checked = client.post("/guard/v1/check-output",
        headers={"Authorization": f"Bearer {bearer}"},
        json={"decision_id": initial.json()["decision_id"], "request_id": "mode-race",
              "application_id": "alpha-rag", "used_resource_ids": ["finance"],
              "provenance": [{"source_resource_ids": ["finance"]}]})
    assert checked.status_code == 200
    assert switched
    assert checked.json()["decision"] == "block", checked.json()


def test_c06_forged_provenance_is_blocked_and_context_cannot_be_replayed(sandbox):
    """Unapproved document IDs cannot piggyback on legitimate authorization."""
    _, _, client, token = sandbox
    bearer = token("alice")
    first = _filter(client, bearer, [("src-alpha", "finance")], request_id="citation-r1")
    decision_id = first.json()["decision_id"]
    fake = client.post("/guard/v1/check-output",
        headers={"Authorization": f"Bearer {bearer}"},
        json={"decision_id": decision_id, "request_id": "citation-r1",
              "application_id": "alpha-rag", "used_resource_ids": ["finance", "beta-secret"],
              "provenance": [{"derived_id": "fake-citation", "source_resource_ids": [
                  "finance", "beta-secret"
              ]}]})
    assert fake.status_code == 200
    assert fake.json()["decision"] == "block"
    replay = client.post("/guard/v1/check-output",
        headers={"Authorization": f"Bearer {bearer}"},
        json={"decision_id": decision_id, "request_id": "citation-r1",
              "application_id": "alpha-rag", "used_resource_ids": ["finance"],
              "provenance": [{"source_resource_ids": ["finance"]}]})
    assert replay.json()["decision"] == "block"


def test_h04_source_acl_unhealthy_during_layer2_blocks_release(sandbox, monkeypatch):
    _, local_cache, client, token = sandbox
    bearer = token("alice")
    first = _filter(client, bearer, [("src-alpha", "finance")], request_id="unhealthy-r1")
    assert first.json()["decision"] == "allow"
    monkeypatch.setattr(local_cache, "source_acl_healthy", lambda app: False)
    response = client.post("/guard/v1/check-output",
        headers={"Authorization": f"Bearer {bearer}"},
        json={"decision_id": first.json()["decision_id"], "request_id": "unhealthy-r1",
              "application_id": "alpha-rag", "used_resource_ids": ["finance"],
              "provenance": [{"source_resource_ids": ["finance"]}]})
    assert response.status_code == 503
    assert "SOURCE_ACL_STALE" in response.text


def test_b01_end_to_end_sdk_never_passes_bobs_denied_finance_to_model(sandbox):
    """The public Guard HTTP API and real SDK filter before the model callback."""
    _, _, client, token = sandbox

    def transport(request: httpx.Request) -> httpx.Response:
        reply = client.request(request.method, str(request.url),
                               headers=dict(request.headers), content=request.content)
        return httpx.Response(reply.status_code, content=reply.content, headers=reply.headers)

    rag = ProtectedRAG(GuardClient("http://testserver",
        client=httpx.Client(transport=httpx.MockTransport(transport))),
        allow_unattested_metadata=True)
    forbidden = "ALPHA_FINANCE_SECRET_CANARY_8439"
    seen_model_context = []

    def model(authorized):
        seen_model_context.extend(authorized)
        return "Approved public handbook summary"

    answer = rag.run(employee_token=token("bob"), application_id="alpha-rag",
        retrieved=[
            RetrievedResource("src-alpha", "finance", content=forbidden),
            RetrievedResource("src-alpha", "handbook", content="Public handbook"),
        ],
        generate=model,
        source_trace=lambda: list(seen_model_context),
    )
    assert [r.resource_id for r in seen_model_context] == ["handbook"]
    assert forbidden not in repr(seen_model_context)
    assert answer.decision == "allow"
    assert answer.response == "Approved public handbook summary"
    assert forbidden not in answer.response


def test_a01_invalid_bearer_token_stops_before_model(sandbox):
    _, _, client, _ = sandbox

    def transport(request: httpx.Request) -> httpx.Response:
        reply = client.request(request.method, str(request.url),
                               headers=dict(request.headers), content=request.content)
        return httpx.Response(reply.status_code, content=reply.content)

    rag = ProtectedRAG(GuardClient("http://testserver",
        client=httpx.Client(transport=httpx.MockTransport(transport))),
        allow_unattested_metadata=True)
    called = []
    answer = rag.run(employee_token="spoofed-not-a-signed-jwt", application_id="alpha-rag",
        retrieved=[RetrievedResource("src-alpha", "handbook", content="Public")],
        generate=lambda r: called.append(r) or "MUST_NOT_GENERATE",
    )
    assert answer.decision == "block"
    assert answer.response is None
    assert called == []
