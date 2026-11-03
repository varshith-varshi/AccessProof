"""D-19: the certification window lets a never-activated Microsoft app serve
real, mapping-bound Guard decisions so the certifier can observe the live
route, without ever reporting the Guard ready or loosening activated apps."""
from __future__ import annotations

import importlib
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient

from apps.guard.accessproof_guard.cache import PolicyCache

KEY = "isolated-certification-window-HS256-key"
ENTRIES = [
    {"subject_id": "alice", "source_id": "src-ms", "resource_id": "finance", "scope": "read", "decision": "allow"},
    {"subject_id": "bob", "source_id": "src-ms", "resource_id": "finance", "scope": "read", "decision": "deny"},
]


def _binding(**over):
    b = {"application_id": "ms-rag", "source_id": "src-ms", "mode": "protect",
         "source_acl_healthy": False, "certification_window": True}
    b.update(over)
    return b


@pytest.fixture
def guard(tmp_path, monkeypatch):
    module = importlib.import_module("apps.guard.accessproof_guard.app")
    cache = PolicyCache(str(tmp_path / "window.db"))
    cache.install(1, ENTRIES, full_snapshot=True)
    cache.mark_sync_success()
    monkeypatch.setattr(module, "cache", cache)
    monkeypatch.setattr(module, "identity_mode", "static")
    monkeypatch.setattr(module, "verification_key", KEY)
    monkeypatch.setattr(module, "issuer", "local-issuer")
    monkeypatch.setattr(module, "audience", "local-audience")
    monkeypatch.setattr(module, "expected_tenant", "t")
    monkeypatch.setattr(module, "subject_claim", "sub")

    def token(sub):
        return jwt.encode({"iss": "local-issuer", "aud": "local-audience", "sub": sub, "tid": "t",
                           "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}, KEY, algorithm="HS256")
    return module, cache, TestClient(module.app), token


def _filter(client, tok, request_id="r1"):
    return client.post("/guard/v1/filter-resources", headers={"Authorization": f"Bearer {tok}"},
                       json={"application_id": "ms-rag", "request_id": request_id,
                             "resources": [{"source_id": "src-ms", "resource_id": "finance"}]})


def test_window_serves_real_allow_and_deny_but_never_ready(guard):
    module, cache, client, token = guard
    cache.set_application_bindings([_binding()])
    allowed = _filter(client, token("alice"))
    assert allowed.status_code == 200 and allowed.json()["decision"] == "allow"
    denied = _filter(client, token("bob"), "r2")
    assert denied.status_code == 200 and denied.json()["decision"] == "block"
    health = client.get("/health", params={"application_id": "ms-rag"}).json()
    assert health["ready"] is False and health["certification_window"] is True


def test_without_window_uncertified_source_still_fails_closed(guard):
    _, cache, client, token = guard
    cache.set_application_bindings([_binding(certification_window=False)])
    r = _filter(client, token("alice"))
    assert r.status_code == 503 and r.json()["detail"] == "SOURCE_ACL_STALE"
    cache.set_application_bindings([{k: v for k, v in _binding().items() if k != "certification_window"}])
    assert _filter(client, token("alice")).status_code == 503   # older control plane: no flag = no window


@pytest.mark.parametrize("bad", [
    {"mode": "shadow"}, {"source_acl_healthy": True},
    {"source_ids": ["src-ms", "src-2"], "source_health": {"src-ms": False, "src-2": False}},
    {"certification_window": "yes"},
])
def test_malformed_window_is_rejected(guard, bad):
    _, cache, _, _ = guard
    with pytest.raises(ValueError):
        cache.set_application_bindings([_binding(**bad)])


def test_restart_clears_the_window(guard, tmp_path):
    _, cache, _, _ = guard
    cache.set_application_bindings([_binding()])
    assert cache.certification_window("ms-rag")
    assert not PolicyCache(cache.path).certification_window("ms-rag")


def test_window_still_requires_fresh_policy(guard):
    module, cache, client, token = guard
    cache.set_application_bindings([_binding()])
    cache.db.execute("UPDATE metadata SET value='2000-01-01T00:00:00+00:00' WHERE key='last_policy_sync'")
    cache.db.commit()
    r = _filter(client, token("alice"))
    assert r.status_code == 503 and r.json()["detail"] == "POLICY_SYNC_STALE"


def _layer2(client, tok, decision_id, request_id, used):
    return client.post("/guard/v1/check-output", headers={"Authorization": f"Bearer {tok}"}, json={
        "decision_id": decision_id, "application_id": "ms-rag", "request_id": request_id,
        "used_resource_ids": used, "provenance": [{"source_resource_ids": used}]})


def test_d22_window_releases_authorized_answer_at_layer2(guard):
    _, cache, client, token = guard
    cache.set_application_bindings([_binding()])
    l1 = _filter(client, token("alice"), "rel-1").json()
    assert l1["decision"] == "allow"
    l2 = _layer2(client, token("alice"), l1["decision_id"], "rel-1", ["finance"])
    assert l2.status_code == 200 and l2.json()["decision"] == "allow", l2.json()


def test_d22_window_still_blocks_revocation_between_layers(guard):
    _, cache, client, token = guard
    cache.set_application_bindings([_binding()])
    l1 = _filter(client, token("alice"), "rel-2").json()
    assert l1["decision"] == "allow"
    cache.install(2, [{"subject_id": "alice", "source_id": "src-ms", "resource_id": "finance",
                       "scope": "read", "decision": "deny"}], full_snapshot=True)
    cache.mark_sync_success()
    l2 = _layer2(client, token("alice"), l1["decision_id"], "rel-2", ["finance"]).json()
    assert l2["decision"] == "block" and l2["reason"] == "LAYER2_ACCESS_REVOKED"


def test_d22_window_closing_between_layers_blocks_release(guard):
    _, cache, client, token = guard
    cache.set_application_bindings([_binding()])
    l1 = _filter(client, token("alice"), "rel-3").json()
    cache.set_application_bindings([_binding(certification_window=False)])
    l2 = _layer2(client, token("alice"), l1["decision_id"], "rel-3", ["finance"])
    # Without the window an uncertified source fails closed (503 at the mode check, or a block).
    assert l2.status_code == 503 or l2.json()["decision"] == "block"
