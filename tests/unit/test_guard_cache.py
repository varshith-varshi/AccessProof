from apps.guard.accessproof_guard.cache import PolicyCache


def test_policy_cache_persists_deny_across_reopen(tmp_path):
    path = tmp_path / "guard.db"
    cache = PolicyCache(str(path))
    cache.install(7, [{"subject_id": "alice", "source_id": "drive", "resource_id": "finance", "decision": "deny", "reason": "NO_ACTIVE_GRANT_PATH"}])
    assert cache.decide("alice", "drive", "finance", "read")[0] == "deny"
    reopened = PolicyCache(str(path))
    assert reopened.version() == 7
    assert reopened.decide("alice", "drive", "finance", "read")[0] == "deny"
    assert reopened.decide("alice", "drive", "other", "read") == ("unknown", "POLICY_MISSING")


def test_install_rejects_rollback_and_preserves_previous_policy_on_failure(tmp_path):
    cache = PolicyCache(str(tmp_path / "guard.db"))
    cache.install(41, [{"subject_id": "bob", "source_id": "drive", "resource_id": "finance", "decision": "deny", "reason": "DENY"}])
    try:
        cache.install(42, [{"subject_id": "bob"}])
    except KeyError:
        pass
    else:
        raise AssertionError("malformed policy installed")
    assert cache.version() == 41
    assert cache.decide("bob", "drive", "finance", "read")[0] == "deny"
    assert cache.install(42, [{"subject_id": "bob", "source_id": "drive", "resource_id": "finance", "decision": "deny", "reason": "DENY"}])
    assert cache.install(42, []) is False
    try:
        cache.install(41, [])
    except ValueError as exc:
        assert str(exc) == "STALE_POLICY"
    else:
        raise AssertionError("rollback accepted")
