"""Adversarial Guard audit durability tests: purely synthetic SQLite state."""
from __future__ import annotations

import pytest

from apps.guard.accessproof_guard.cache import PolicyCache


def _record(cache: PolicyCache, event_id: str) -> bool:
    return cache.buffer_audit(
        event_id,
        application_id="synthetic-rag",
        subject_id="alice",
        request_id=event_id,
        result="allow",
        reason="TEST_ONLY",
        policy_version=1,
    )


def test_audit_outage_must_not_silently_erase_unuploaded_security_evidence(tmp_path):
    cache = PolicyCache(str(tmp_path / "audit-backlog.db"), max_audit_records=2)
    assert _record(cache, "event-1")
    assert _record(cache, "event-2")

    # Simulate a failed control-plane upload; events remain undelivered.
    # A full buffer must force a safe error, not silently delete evidence.
    with pytest.raises(RuntimeError, match="AUDIT_BUFFER_FULL"):
        _record(cache, "event-3")
    assert [row["event_id"] for row in cache.pending_audit()] == ["event-1", "event-2"]


def test_delivered_audit_records_can_be_evicted_without_loss(tmp_path):
    cache = PolicyCache(str(tmp_path / "audit-delivered.db"), max_audit_records=2)
    _record(cache, "event-1")
    _record(cache, "event-2")
    cache.mark_audit_delivered(["event-1"])
    assert _record(cache, "event-3")
    assert [row["event_id"] for row in cache.pending_audit()] == ["event-2", "event-3"]


def test_audit_overflow_rolls_back_new_event_and_preserves_oldest(tmp_path):
    cache = PolicyCache(str(tmp_path / "audit-rollback.db"), max_audit_records=1)
    _record(cache, "event-first")
    with pytest.raises(RuntimeError, match="AUDIT_BUFFER_FULL"):
        _record(cache, "event-second")
    assert [row["event_id"] for row in cache.pending_audit()] == ["event-first"]
    cache.mark_audit_delivered(["event-first"])
    assert _record(cache, "event-second")
