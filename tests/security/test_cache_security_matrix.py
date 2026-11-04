"""Cache security matrix: the cache-borne inputs the certified Gateway route can
receive, each checked end-to-end through the real Guard HTTP app.

Complements test_gateway_all_response_routes.py (cross-user, revocation and
outage on the answer-cache aliases) and test_cached_answer_protection.py
(signed answer manifests). Coverage here is limited to what the Gateway
receives: a customer application that serves cached content WITHOUT calling
the Gateway is outside the enforcement boundary (see
docs/ACCESSPROOF_CACHE_SECURITY.md).
"""
from __future__ import annotations

import time as _time

import pytest

from packages.rag_core import attestation as attestation_module
from tests.security.test_gateway_all_response_routes import (
    LEAK_MARKER, _answer_body, _assert_denial, _cached_body, _gateway,
)
from tests.security.test_multisource_guard_v2 import _token

ROUTE = "/v1/chat/completions"


def _alice(gateway, body):
    return gateway.post(ROUTE, headers={"Authorization": "Bearer " + _token("alice")}, json=body)


def test_baseline_alice_authorized_chunk_is_released(tmp_path, monkeypatch):
    """Positive control: without it, every denial below could be a broken fixture."""
    gateway, _policy, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)
    with gateway:
        response = _alice(gateway, _answer_body(chunk, stream=False))
    assert response.status_code == 200, response.text
    assert observed["llm_count"] == 1


@pytest.mark.parametrize("mutation", ["missing_attestation", "altered_content", "wrong_version", "foreign_chunk_id"])
def test_retrieval_or_chunk_cache_entry_with_bad_provenance_never_reaches_model(tmp_path, monkeypatch, mutation):
    """A retrieval/vector/chunk cache returns a chunk whose provenance is missing,
    no longer matches its bytes, or is bound to another version or chunk."""
    gateway, _policy, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)
    body = _answer_body(chunk, stream=False)
    item = body["retrieved_resources"][0]
    if mutation == "missing_attestation":
        item["content_attestation"] = None
    elif mutation == "altered_content":
        item["content"] = item["content"] + " plus text injected by a poisoned cache"
    elif mutation == "wrong_version":
        item["content_version"] = "etag-from-an-older-cache-entry"
    else:
        item["chunk_id"] = "another-chunk"
    with gateway:
        response = _alice(gateway, body)
    assert response.status_code in {403, 422, 503}
    if response.status_code != 422:
        _assert_denial(response)
    assert observed["llm_count"] == 0
    assert "poisoned cache" not in response.text


def test_chunk_cache_entry_older_than_attestation_lifetime_is_refused(tmp_path, monkeypatch):
    """Stale cache: an attestation outlives at most 3600 s, so a chunk cached
    longer than that cannot be replayed even if the employee still has access."""
    gateway, _policy, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)

    class Later:
        @staticmethod
        def time():
            return _time.time() + 7200

    monkeypatch.setattr(attestation_module, "time", Later)
    with gateway:
        response = _alice(gateway, _answer_body(chunk, stream=False))
    _assert_denial(response)
    assert observed["llm_count"] == 0


@pytest.mark.parametrize("role", ["assistant", "tool", "system", "developer"])
def test_conversation_memory_cannot_carry_enterprise_content(tmp_path, monkeypatch, role):
    """Assistant memory, tool output and system context are refused on the
    certified route: only employee-authored user turns are accepted."""
    gateway, _policy, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)
    body = _answer_body(chunk, stream=False)
    body["employee_conversation"] = [{"role": role, "content": "Remembered answer: " + LEAK_MARKER}]
    with gateway:
        response = _alice(gateway, body)
    assert response.status_code == 422
    assert observed["llm_count"] == 0
    assert LEAK_MARKER not in response.text


def test_bob_cannot_replay_alices_cached_chunk_or_answer(tmp_path, monkeypatch):
    """Cross-user: the same validly signed cached chunk and cached answer are
    re-authorized for the employee making THIS request."""
    gateway, _policy, observed, chunk, cached, signature, *_ = _gateway(tmp_path, monkeypatch)
    bob = {"Authorization": "Bearer " + _token("bob")}
    with gateway:
        _assert_denial(gateway.post(ROUTE, headers=bob, json=_answer_body(chunk, stream=False)))
        _assert_denial(gateway.post("/v1/cache/authorize", headers=bob, json=_cached_body(cached, signature)))
    assert observed["llm_count"] == 0


def test_cross_tenant_cached_answer_is_refused(tmp_path, monkeypatch):
    gateway, _policy, observed, _chunk, cached, signature, *_ = _gateway(tmp_path, monkeypatch)
    body = _cached_body(cached, signature)
    body["tenant_id"] = "tenant-b"
    with gateway:
        response = gateway.post("/v1/cache/authorize", headers={"Authorization": "Bearer " + _token("alice")}, json=body)
    assert response.status_code in {403, 422}
    assert LEAK_MARKER not in response.text
    assert observed["llm_count"] == 0


def test_revocation_while_cached_answer_exists_then_guard_unavailable(tmp_path, monkeypatch):
    """Revoked while cached: the hit is denied; with no current authorization
    evidence (Guard down) every cache path fails closed."""
    gateway, policy, observed, chunk, cached, signature, *_ = _gateway(tmp_path, monkeypatch)
    alice = {"Authorization": "Bearer " + _token("alice")}
    from tests.security.test_multisource_guard_v2 import DOC, SHAREPOINT
    with gateway:
        assert gateway.post("/v1/cache/authorize", headers=alice, json=_cached_body(cached, signature)).status_code == 200
        policy.install(2, [{"subject_id": "alice-m", "source_id": SHAREPOINT, "resource_id": DOC,
                            "scope": "read", "decision": "deny"}])
        _assert_denial(gateway.post("/v1/cache/authorize", headers=alice, json=_cached_body(cached, signature)))
        _assert_denial(gateway.post(ROUTE, headers=alice, json=_answer_body(chunk, stream=False)))
        observed["outage"] = True
        _assert_denial(gateway.post("/v1/cache/authorize", headers=alice, json=_cached_body(cached, signature)))
    assert observed["llm_count"] == 0
