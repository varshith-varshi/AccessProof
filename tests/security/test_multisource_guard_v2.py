"""Multi-source Guard V2 security regression tests with the actual HTTP routes.

All content is synthetic, with no real Microsoft or Google credentials.
"""
from __future__ import annotations

import time
import importlib

import jwt
from fastapi.testclient import TestClient

from apps.guard.accessproof_guard.cache import PolicyCache

APP = "synthetic-multi-app"
KEY = "synthetic-testing-secret-" + "x" * 48
GOOGLE = "google-synthetic"
SHAREPOINT = "sharepoint-synthetic"
DOC = "same-identifier-in-both-sources"


def _token(subject: str, *, tenant="tenant-a"):
    return jwt.encode({
        "iss": "https://issuer.synthetic",
        "aud": "accessproof-test",
        "sub": subject, "tid": tenant,
        "iat": int(time.time()) - 1,
        "exp": int(time.time()) + 1200,
    }, KEY, algorithm="HS256")


def _ready(tmp_path, monkeypatch):
    app = importlib.import_module("apps.guard.accessproof_guard.app")
    store = PolicyCache(str(tmp_path / "policy.db"))
    store.install(1, [
        {"subject_id": "alice-g", "source_id": GOOGLE, "resource_id": DOC,
         "scope": "read", "decision": "allow"},
        {"subject_id": "alice-m", "source_id": SHAREPOINT, "resource_id": DOC,
         "scope": "read", "decision": "allow"},
        {"subject_id": "bob-g", "source_id": GOOGLE, "resource_id": DOC,
         "scope": "read", "decision": "allow"},
        {"subject_id": "bob-m", "source_id": SHAREPOINT, "resource_id": DOC,
         "scope": "read", "decision": "deny"},
    ])
    store.set_application_bindings([{
        "application_id": APP, "source_id": GOOGLE,
        "source_ids": [GOOGLE, SHAREPOINT], "mode": "protect",
        "source_acl_healthy": True,
        "source_health": {GOOGLE: True, SHAREPOINT: True},
    }])
    store.set_identity_mappings([
        {"source_id": src, "issuer": "https://issuer.synthetic", "tenant_id": "tenant-a",
         "subject": subject, "source_subject_id": mapped}
        for src, subject, mapped in (
            (GOOGLE, "alice", "alice-g"),
            (SHAREPOINT, "alice", "alice-m"),
            (GOOGLE, "bob", "bob-g"),
            (SHAREPOINT, "bob", "bob-m"),
        )
    ])
    store.set_authorization_revisions([{
        "application_id": APP, "revision": 1, "revision_hash": "a" * 64,
        "generated_at": "2026-10-27T00:00:00Z",
    }])
    store.mark_sync_success()
    monkeypatch.setattr(app, "cache", store)
    monkeypatch.setattr(app, "identity_mode", "static")
    monkeypatch.setattr(app, "issuer", "https://issuer.synthetic")
    monkeypatch.setattr(app, "audience", "accessproof-test")
    monkeypatch.setattr(app, "verification_key", KEY)
    monkeypatch.setattr(app, "expected_tenant", "tenant-a")
    monkeypatch.setattr(app, "subject_claim", "sub")
    monkeypatch.setattr(app, "guard_id", None)
    monkeypatch.setattr(app, "guard_credential", None)
    monkeypatch.setenv("ACCESSPROOF_ENV", "development")
    return TestClient(app.app), store


def _filter(client, subject, request_id="r1"):
    return client.post("/guard/v2/filter-resources", headers={
        "Authorization": "Bearer " + _token(subject),
    }, json={
        "application_id": APP, "request_id": request_id,
        "resources": [
            {"source_id": GOOGLE, "resource_id": DOC, "chunk_ids": ["g1"], "content_version": "etag1"},
            {"source_id": SHAREPOINT, "resource_id": DOC, "chunk_ids": ["m1"], "content_version": "etag1"},
        ],
    })


def test_binding_removed_after_mode_check_returns_denial(tmp_path, monkeypatch):
    client, store = _ready(tmp_path, monkeypatch)
    original = store.application_binding
    calls = 0

    def disappearing_binding(application_id):
        nonlocal calls
        calls += 1
        return original(application_id) if calls == 1 else None

    monkeypatch.setattr(store, "application_binding", disappearing_binding)
    try:
        response = _filter(client, "alice")
        assert response.status_code == 403
        assert response.json()["detail"] == "APPLICATION_NOT_BOUND"
    finally:
        client.close()
        store.db.close()


def _release(client, subject, decision_id, request_id="r1", sources=(GOOGLE, SHAREPOINT)):
    deps = [
        {"source_id": src, "resource_id": DOC,
         "chunk_id": "g1" if src == GOOGLE else "m1",
         "content_version": "etag1"}
        for src in sources
    ]
    return client.post("/guard/v2/check-output", headers={
        "Authorization": "Bearer " + _token(subject),
    }, json={
        "application_id": APP, "request_id": request_id,
        "decision_id": decision_id,
        "used_resources": deps, "provenance": deps,
    })


def test_both_sources_same_document_id_are_separately_authorized(tmp_path, monkeypatch):
    client, _ = _ready(tmp_path, monkeypatch)
    r = _filter(client, "alice")
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "allow"
    assert len(r.json()["allowed"]) == 2
    decision = r.json()["decision_id"]
    finish = _release(client, "alice", decision)
    assert finish.status_code == 200, finish.text
    assert finish.json()["decision"] == "allow"
    assert finish.json()["authorization_revision_hash"] == "a" * 64
    assert _release(client, "alice", decision).json()["decision"] == "block"
    # V1 is not allowed to interpret mixed-source application contexts.
    assert client.post("/guard/v1/filter-resources", headers={
        "Authorization": "Bearer " + _token("alice"),
    }, json={"application_id": APP, "request_id": "old", "resources": [
        {"source_id": GOOGLE, "resource_id": DOC},
    ]}).status_code == 403


def test_bob_cannot_access_sharepoint_from_google_allow(tmp_path, monkeypatch):
    client, _ = _ready(tmp_path, monkeypatch)
    first = _filter(client, "bob", "r2").json()
    assert first["decision"] == "allow"
    assert [(r["source_id"], r["resource_id"]) for r in first["allowed"]] == [(GOOGLE, DOC)]
    assert _release(client, "bob", first["decision_id"], "r2").json()["decision"] == "block"
    allowed_only = _release(client, "bob", _filter(client, "bob", "r3").json()["decision_id"],
                            "r3", sources=(GOOGLE,))
    assert allowed_only.json()["decision"] == "allow"


def test_cross_user_wrong_tenant_and_replayed_contexts_fail(tmp_path, monkeypatch):
    client, _ = _ready(tmp_path, monkeypatch)
    decision = _filter(client, "alice", "r4").json()["decision_id"]
    assert _release(client, "bob", decision, "r4").json()["decision"] == "block"
    assert _release(client, "alice", decision, "wrong-request").json()["decision"] == "block"
    wrong_tenant = client.post("/guard/v2/filter-resources", headers={
        "Authorization": "Bearer " + _token("alice", tenant="other"),
    }, json={
        "application_id": APP, "request_id": "r5",
        "resources": [{"source_id": GOOGLE, "resource_id": DOC, "content_version": "etag1"}],
    })
    assert wrong_tenant.status_code == 401
    assert _release(client, "alice", decision, "r4").json()["decision"] == "allow"


def test_revocation_identity_change_and_source_outage_fail_at_release(tmp_path, monkeypatch):
    client, cache = _ready(tmp_path, monkeypatch)
    d1 = _filter(client, "alice", "r6").json()["decision_id"]
    cache.install(2, [{"subject_id": "alice-m", "source_id": SHAREPOINT,
                       "resource_id": DOC, "scope": "read", "decision": "deny"}])
    assert _release(client, "alice", d1, "r6").json()["decision"] == "block"
    # Restore grant with a newer revision for a distinct identity mapping check.
    cache.install(3, [{"subject_id": "alice-m", "source_id": SHAREPOINT,
                       "resource_id": DOC, "scope": "read", "decision": "allow"}])
    d2 = _filter(client, "alice", "r7").json()["decision_id"]
    cache.set_identity_mappings([
        {"source_id": GOOGLE, "issuer": "https://issuer.synthetic",
         "tenant_id": "tenant-a", "subject": "alice", "source_subject_id": "alice-g"},
        {"source_id": SHAREPOINT, "issuer": "https://issuer.synthetic",
         "tenant_id": "tenant-a", "subject": "alice", "source_subject_id": "different-id"},
    ])
    assert _release(client, "alice", d2, "r7").json()["decision"] == "block"
    cache.set_identity_mappings([
        {"source_id": GOOGLE, "issuer": "https://issuer.synthetic",
         "tenant_id": "tenant-a", "subject": "alice", "source_subject_id": "alice-g"},
        {"source_id": SHAREPOINT, "issuer": "https://issuer.synthetic",
         "tenant_id": "tenant-a", "subject": "alice", "source_subject_id": "alice-m"},
    ])
    d3 = _filter(client, "alice", "r8").json()["decision_id"]
    cache.set_application_bindings([{
        "application_id": APP, "source_id": GOOGLE, "source_ids": [GOOGLE, SHAREPOINT],
        "mode": "protect", "source_acl_healthy": False,
        "source_health": {GOOGLE: True, SHAREPOINT: False},
    }])
    assert _release(client, "alice", d3, "r8").status_code == 503


def test_revision_change_and_unapproved_source_fail_closed(tmp_path, monkeypatch):
    client, cache = _ready(tmp_path, monkeypatch)
    d = _filter(client, "alice", "r9").json()["decision_id"]
    cache.set_authorization_revisions([{
        "application_id": APP, "revision": 2, "revision_hash": "b" * 64,
        "generated_at": "2026-10-27T00:00:00Z",
    }])
    result = _release(client, "alice", d, "r9")
    assert result.json()["decision"] == "block"
    assert result.json()["reason"] == "AUTHORIZATION_REVISION_CHANGED"
    invalid = client.post("/guard/v2/filter-resources", headers={
        "Authorization": "Bearer " + _token("alice"),
    }, json={
        "application_id": APP, "request_id": "r10",
        "resources": [{"source_id": "unbound-source", "resource_id": DOC, "content_version": "etag1"}],
    })
    assert invalid.status_code == 403

def test_v2_rejects_substituted_content_version_chunk_and_source(tmp_path, monkeypatch):
    client, _ = _ready(tmp_path, monkeypatch)
    for altered in (
        {"source_id": GOOGLE, "resource_id": DOC, "chunk_id": "g1", "content_version": "etag2"},
        {"source_id": GOOGLE, "resource_id": DOC, "chunk_id": "different", "content_version": "etag1"},
        {"source_id": "different-source", "resource_id": DOC, "chunk_id": "g1", "content_version": "etag1"},
    ):
        decision = _filter(client, "alice", "version-test").json()["decision_id"]
        original = [
            {"source_id": GOOGLE, "resource_id": DOC, "chunk_id": "g1", "content_version": "etag1"},
            {"source_id": SHAREPOINT, "resource_id": DOC, "chunk_id": "m1", "content_version": "etag1"},
        ]
        original[0] = altered
        result = client.post("/guard/v2/check-output", headers={
            "Authorization": "Bearer " + _token("alice"),
        }, json={
            "application_id": APP, "request_id": "version-test", "decision_id": decision,
            "used_resources": original, "provenance": original,
        })
        assert result.status_code == 403 or result.json()["decision"] == "block"


def test_v2_scoped_ann_retrieval_is_source_qualified(tmp_path, monkeypatch):
    client, _ = _ready(tmp_path, monkeypatch)
    for employee, expected in (
        ("alice", [DOC]),
        ("bob", []),
    ):
        response = client.post("/guard/v2/authorization-scope", headers={
            "Authorization": "Bearer " + _token(employee),
        }, json={
            "application_id": APP, "request_id": "ann-"+employee,
            "source_ids": [GOOGLE, SHAREPOINT],
        })
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["decision"] == "allow"
        assert data["scope_complete"] is True
        assert data["sources"][0] == {"source_id": GOOGLE, "allowed_resource_ids": [DOC]}
        assert data["sources"][1] == {"source_id": SHAREPOINT, "allowed_resource_ids": expected}
        assert data["authorization_revision_hash"] == "a" * 64


def test_v2_ann_scope_rejects_duplicate_and_unbound_sources(tmp_path, monkeypatch):
    client, _ = _ready(tmp_path, monkeypatch)
    def query(sources):
        return client.post("/guard/v2/authorization-scope", headers={
            "Authorization": "Bearer " + _token("alice"),
        }, json={"application_id": APP, "request_id": "ann-invalid", "source_ids": sources})
    assert query([GOOGLE, GOOGLE]).status_code == 422
    assert query([GOOGLE, "not-enrolled"]).status_code == 403


def test_v2_rejects_unsupported_scope_and_ambiguous_versions(tmp_path, monkeypatch):
    client, _ = _ready(tmp_path, monkeypatch)
    def query(resources):
        return client.post("/guard/v2/filter-resources", headers={
            "Authorization": "Bearer " + _token("alice"),
        }, json={"application_id": APP, "request_id": "resource-invalid", "resources": resources})
    good = {"source_id": GOOGLE, "resource_id": DOC,
            "content_version": "etag1", "chunk_ids": ["g1"], "scope": "read"}
    assert query([{**good, "scope": "write"}]).status_code == 422
    assert query([{key: val for key, val in good.items() if key != "content_version"}]).status_code == 422
    mixed = query([good, {**good, "content_version": "etag2"}])
    assert mixed.status_code == 200
    assert mixed.json()["decision"] == "block"
    assert mixed.json()["reason"] == "DUPLICATE_RESOURCE"
