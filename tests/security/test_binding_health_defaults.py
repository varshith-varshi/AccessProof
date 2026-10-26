"""Local adversarial tests for unknown source-health state on Guard bindings."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache


def test_missing_acl_health_never_implicitly_authorizes_protect(tmp_path, monkeypatch):
    cache = PolicyCache(str(tmp_path / "missing-health.db"))
    cache.install(1, [{
        "subject_id": "alice", "source_id": "drive",
        "resource_id": "doc", "decision": "allow",
    }])
    # Future adapters may call the cache API directly. Missing explicit
    # source-health evidence must not be interpreted as a healthy ACL sync.
    cache.set_application_bindings([
        {"application_id": "rag", "source_id": "drive", "mode": "protect"},
    ])
    cache.mark_sync_success()
    monkeypatch.setattr(guard_app, "cache", cache)
    assert cache.source_acl_healthy("rag") is False
    with pytest.raises(HTTPException) as exc:
        guard_app._application_mode("rag")
    assert exc.value.status_code == 503
    assert exc.value.detail == "SOURCE_ACL_STALE"


def test_explicit_healthy_source_allows_bound_protect(tmp_path, monkeypatch):
    cache = PolicyCache(str(tmp_path / "healthy.db"))
    cache.install(1, [{
        "subject_id": "alice", "source_id": "drive",
        "resource_id": "doc", "decision": "allow",
    }])
    cache.set_application_bindings([{
        "application_id": "rag", "source_id": "drive",
        "mode": "protect", "source_acl_healthy": True,
    }])
    cache.mark_sync_success()
    monkeypatch.setattr(guard_app, "cache", cache)
    assert guard_app._application_mode("rag") == ("protect", "drive")
