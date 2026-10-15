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
