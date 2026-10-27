"""Independent ordering/replay attacks against the durable Guard policy cache."""
from itertools import permutations

import pytest

from apps.guard.accessproof_guard.cache import PolicyCache


def row(version, decision, *, resource="finance"):
    return {"subject_id": "alice", "source_id": "synthetic-drive",
            "resource_id": resource, "scope": "read", "decision": decision,
            "reason": "SYNTHETIC", "version": version}


def test_e03_out_of_order_incremental_events_cannot_resurrect_old_grant(tmp_path):
    cache = PolicyCache(str(tmp_path / "ordering.db"))
    assert cache.install(1, [row(1, "allow")])
    assert cache.install(3, [row(3, "deny"), row(2, "allow")])
    assert cache.version() == 3
    assert cache.decide("alice", "synthetic-drive", "finance", "read")[0] == "deny"


def test_e05_stale_allow_in_newer_envelope_cannot_override_deny(tmp_path):
    cache = PolicyCache(str(tmp_path / "ordering.db"))
    assert cache.install(4, [row(4, "deny")])
    assert cache.install(5, [row(3, "allow")])
    assert cache.decide("alice", "synthetic-drive", "finance", "read")[0] == "deny"
    # A genuinely newer authoritative grant still restores legitimate access.
    assert cache.install(6, [row(6, "allow")])
    assert cache.decide("alice", "synthetic-drive", "finance", "read")[0] == "allow"


def test_e03_same_epoch_conflicting_updates_choose_safe_deny(tmp_path):
    cache = PolicyCache(str(tmp_path / "ordering.db"))
    assert cache.install(3, [row(3, "deny"), row(3, "allow")])
    assert cache.decide("alice", "synthetic-drive", "finance", "read")[0] == "deny"


def test_e03_future_version_in_delta_is_not_trusted(tmp_path):
    cache = PolicyCache(str(tmp_path / "ordering.db"))
    cache.install(2, [row(2, "deny")])
    with pytest.raises(ValueError, match="INVALID_POLICY_VERSION"):
        cache.install(3, [row(999, "allow")])
    assert cache.version() == 2
    assert cache.decide("alice", "synthetic-drive", "finance", "read")[0] == "deny"


@pytest.mark.parametrize("order", tuple(permutations(range(4))))
def test_e03_policy_order_is_permutation_invariant(order, tmp_path):
    """Exhaustively permute four independent local policy change events."""
    history = [row(2, "allow"), row(3, "deny"), row(4, "allow"), row(5, "deny")]
    cache = PolicyCache(str(tmp_path / "permuted-policy.db"))
    assert cache.install(5, [history[i] for i in order])
    assert cache.decide("alice", "synthetic-drive", "finance", "read")[0] == "deny"
    # Restriction must not block a genuinely newer positive control.
    assert cache.install(6, [row(6, "allow")])
    assert cache.decide("alice", "synthetic-drive", "finance", "read")[0] == "allow"
