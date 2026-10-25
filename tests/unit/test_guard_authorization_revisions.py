"""Guard-local revision installation, readiness and Layer 2 recheck semantics."""
from __future__ import annotations

import pytest

from apps.guard.accessproof_guard.cache import PolicyCache

REVISION_ONE = "a" * 64
REVISION_TWO = "b" * 64


def _revision(revision: int, revision_hash: str) -> dict[str, object]:
    return {
        "application_id": "rag",
        "revision": revision,
        "revision_hash": revision_hash,
        "generated_at": "2026-10-24T00:00:00Z",
    }


def _protect_cache(tmp_path) -> PolicyCache:
    cache = PolicyCache(str(tmp_path / "guard-revisions.db"))
    cache.install(3, [{
        "subject_id": "alice", "source_id": "drive",
        "resource_id": "doc", "decision": "allow",
    }])
    cache.set_application_bindings([{
        "application_id": "rag", "source_id": "drive",
        "mode": "protect", "source_acl_healthy": True,
    }])
    return cache


def test_revisions_are_monotonic_and_forks_are_rejected(tmp_path):
    cache = _protect_cache(tmp_path)
    assert cache.authorization_revisions_received() is False
    cache.set_authorization_revisions([_revision(1, REVISION_ONE)])
    assert cache.authorization_revisions_received() is True
    assert cache.all_protect_revisions_present() is True
    assert cache.authorization_revision("rag") == (1, REVISION_ONE)

    cache.set_authorization_revisions([_revision(2, REVISION_TWO)])
    assert cache.authorization_revision("rag") == (2, REVISION_TWO)

    with pytest.raises(ValueError, match="STALE_AUTHORIZATION_REVISION"):
        cache.set_authorization_revisions([_revision(1, REVISION_ONE)])
    with pytest.raises(ValueError, match="AUTHORIZATION_REVISION_FORK"):
        cache.set_authorization_revisions([_revision(2, REVISION_ONE)])
    with pytest.raises(ValueError, match="DUPLICATE_AUTHORIZATION_REVISION"):
        cache.set_authorization_revisions([_revision(3, REVISION_ONE)] * 2)
    with pytest.raises(ValueError, match="INVALID_AUTHORIZATION_REVISION"):
        cache.set_authorization_revisions([_revision(3, "not-a-digest")])
    # A rejected snapshot must not partially replace the installed revision.
    assert cache.authorization_revision("rag") == (2, REVISION_TWO)


def test_protect_binding_without_current_revision_is_not_ready(tmp_path):
    cache = _protect_cache(tmp_path)
    cache.set_application_bindings([
        {"application_id": "rag", "source_id": "drive",
         "mode": "protect", "source_acl_healthy": True},
        {"application_id": "rag-2", "source_id": "drive-2",
         "mode": "protect", "source_acl_healthy": True},
    ])
    cache.set_authorization_revisions([_revision(1, REVISION_ONE)])
    assert cache.all_protect_revisions_present() is False
    cache.set_authorization_revisions([
        _revision(1, REVISION_ONE),
        {**_revision(1, REVISION_TWO), "application_id": "rag-2"},
    ])
    assert cache.all_protect_revisions_present() is True


def test_layer2_rejects_context_created_under_an_older_revision(tmp_path):
    cache = _protect_cache(tmp_path)
    cache.set_authorization_revisions([_revision(1, REVISION_ONE)])
    cache.save_context(
        "decision-1", "rag", "alice", ["doc"], request_id="request-1",
        source_id="drive", revision_hash=REVISION_ONE,
    )
    assert cache.consume_contexts_with_recheck(
        ["decision-1"], "rag", "alice", "request-1",
        source_id="drive", expected_mode="protect",
    ) == "ok"

    cache.save_context(
        "decision-2", "rag", "alice", ["doc"], request_id="request-2",
        source_id="drive", revision_hash=REVISION_ONE,
    )
    cache.set_authorization_revisions([_revision(2, REVISION_TWO)])
    assert cache.consume_contexts_with_recheck(
        ["decision-2"], "rag", "alice", "request-2",
        source_id="drive", expected_mode="protect",
    ) == "revision_changed"
    assert cache.load_context("decision-2", "rag", "alice", "request-2") == {"doc"}


def test_audit_buffer_carries_revision_and_occurred_at_only_when_bound(tmp_path):
    cache = _protect_cache(tmp_path)
    cache.buffer_audit(
        "event-legacy", application_id="rag", subject_id="alice",
        request_id="request-1", result="allow", reason="ALLOW", policy_version=3,
    )
    cache.buffer_audit(
        "event-bound", application_id="rag", subject_id="alice",
        request_id="request-2", result="block", reason="AUTHORIZATION_REVISION_CHANGED",
        policy_version=3, authorization_revision=2,
        authorization_revision_hash=REVISION_TWO,
    )
    pending = {item["event_id"]: item for item in cache.pending_audit()}
    assert "occurred_at" not in pending["event-legacy"]
    assert pending["event-bound"]["authorization_revision"] == 2
    assert pending["event-bound"]["authorization_revision_hash"] == REVISION_TWO
    assert pending["event-bound"]["occurred_at"]
