"""Conversation memory and tool results enter model context ONLY as signed,
currently re-authorized manifests (TrustedContextItem); never as free text."""
from __future__ import annotations

from tests.security.test_cached_chunk_version_freshness import _versions
from tests.security.test_gateway_all_response_routes import _answer_body, _gateway
from tests.security.test_multisource_guard_v2 import DOC, SHAREPOINT, _token

ROUTE = "/v1/chat/completions"


def _memory(cached, signature, kind="memory"):
    return {"kind": kind, "tenant_id": cached.tenant_id, "application_id": cached.application_id,
            "content": cached.answer, "producer_id": cached.producer_id,
            "dependencies": [vars(d) for d in cached.dependencies], "manifest_token": signature,
            "authorization_revision": cached.authorization_revision,
            "authorization_revision_hash": cached.authorization_revision_hash}


def _post(gateway, who, body):
    return gateway.post(ROUTE, headers={"Authorization": "Bearer " + _token(who)}, json=body)


def _with(chunk, *items):
    body = _answer_body(chunk, stream=False)
    body["trusted_context"] = list(items)
    return body


def test_signed_memory_and_tool_result_are_admitted_for_authorized_employee(tmp_path, monkeypatch):
    gateway, _p, observed, chunk, cached, sig, *_ = _gateway(tmp_path, monkeypatch)
    with gateway:
        r = _post(gateway, "alice", _with(chunk, _memory(cached, sig), _memory(cached, sig, "tool")))
    assert r.status_code == 200, r.text
    assert observed["llm_count"] == 1


def test_bob_cannot_replay_alices_memory(tmp_path, monkeypatch):
    gateway, _p, observed, chunk, cached, sig, *_ = _gateway(tmp_path, monkeypatch)
    with gateway:
        r = _post(gateway, "bob", _with(chunk, _memory(cached, sig)))
    assert r.status_code in {403, 503}
    assert "SYNTHETIC_MIXED_SOURCE_ANSWER" not in r.text
    assert observed["llm_count"] == 0


def test_memory_is_refused_after_revocation(tmp_path, monkeypatch):
    gateway, policy, observed, chunk, cached, sig, *_ = _gateway(tmp_path, monkeypatch)
    policy.install(2, [{"subject_id": "alice-m", "source_id": SHAREPOINT, "resource_id": DOC,
                        "scope": "read", "decision": "deny"}])
    with gateway:
        r = _post(gateway, "alice", _with(chunk, _memory(cached, sig)))
    assert r.status_code in {403, 503}
    assert observed["llm_count"] == 0


def test_memory_derived_from_previous_document_version_is_refused(tmp_path, monkeypatch):
    gateway, policy, observed, chunk, cached, sig, *_ = _gateway(tmp_path, monkeypatch)
    _versions(policy, {DOC: ["etag2"]})
    with gateway:
        r = _post(gateway, "alice", _with(chunk, _memory(cached, sig)))
    assert r.status_code in {403, 503}
    assert observed["llm_count"] == 0


def test_tampered_or_unsigned_memory_is_refused(tmp_path, monkeypatch):
    gateway, _p, observed, chunk, cached, sig, *_ = _gateway(tmp_path, monkeypatch)
    tampered = _memory(cached, sig)
    tampered["content"] = cached.answer + " and Bob's salary"
    unsigned = _memory(cached, sig)
    del unsigned["manifest_token"]
    other_tenant = _memory(cached, sig)
    other_tenant["tenant_id"] = "tenant-b"
    with gateway:
        assert _post(gateway, "alice", _with(chunk, tampered)).status_code in {403, 503}
        assert _post(gateway, "alice", _with(chunk, unsigned)).status_code == 422
        assert _post(gateway, "alice", _with(chunk, other_tenant)).status_code == 403
    assert observed["llm_count"] == 0


def test_memory_without_cache_verifier_fails_closed(tmp_path, monkeypatch):
    gateway, _p, observed, chunk, cached, sig, *_ = _gateway(tmp_path, monkeypatch)
    from apps.gateway.accessproof_gateway import app as gw
    original = gw.GatewayService._authorize_trusted_context

    import dataclasses

    def no_keys(self, *args, **kwargs):
        self.settings = dataclasses.replace(self.settings, cache_verifier=None)
        return original(self, *args, **kwargs)
    monkeypatch.setattr(gw.GatewayService, "_authorize_trusted_context", no_keys)
    with gateway:
        r = _post(gateway, "alice", _with(chunk, _memory(cached, sig)))
    assert r.status_code == 503 and "TRUSTED_CONTEXT_SIGNING_KEYS_NOT_CONFIGURED" in r.text
    assert observed["llm_count"] == 0


def test_free_text_assistant_memory_still_rejected(tmp_path, monkeypatch):
    gateway, _p, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)
    body = _answer_body(chunk, stream=False)
    body["employee_conversation"] = [{"role": "assistant", "content": "remembered"}]
    with gateway:
        assert _post(gateway, "alice", body).status_code == 422
    assert observed["llm_count"] == 0
