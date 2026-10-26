"""Integration-edge regressions: safe policy sync and bounded model responses."""
import httpx
import pytest

from apps.guard.accessproof_guard.cache import PolicyCache
from apps.guard.accessproof_guard.sync import GuardMachineCredentials, GuardSyncClient
from packages.rag_sdk.protection import GuardClient, ProtectedRAG


def test_protect_sync_rejects_missing_source_health(tmp_path):
    """A malformed control-plane snapshot must not declare stale ACLs healthy."""
    def response(request):
        if request.method == "GET":
            return httpx.Response(200, json={
                "kind": "incremental", "version": 1,
                "applications": [{"application_id": "rag", "source_id": "drive", "mode": "protect"}],
                "policies": [{"version": 1, "subject_id": "alice", "source_id": "drive",
                              "resource_id": "file-1", "scope": "read", "decision": "allow"}],
            })
        return httpx.Response(200, json={"ok": True})

    cache = PolicyCache(str(tmp_path / "guard-cache.db"))
    client = GuardSyncClient(
        cache,
        GuardMachineCredentials("https://control.example", "g1", "machine-token", "1"),
        httpx.Client(transport=httpx.MockTransport(response)),
    )
    with pytest.raises(ValueError, match="SOURCE_ACL_HEALTH_REQUIRED"):
        client.sync_once()
    assert not cache.application_bindings_received()


def test_response_buffer_handles_unicode_byte_boundary():
    rag = ProtectedRAG(GuardClient("https://guard.example"), max_response_bytes=6)
    assert rag._buffer(part for part in ["é", "ab", "é"]) == "éabé"
    with pytest.raises(ValueError, match="buffer limit"):
        rag._buffer(part for part in ["é", "ab", "é", "!"])


def test_response_buffer_rejects_non_text_chunks():
    rag = ProtectedRAG(GuardClient("https://guard.example"))
    with pytest.raises(TypeError, match="must produce text"):
        rag._buffer(iter(["ok", 5]))


def test_buffer_many_small_chunks_without_quadratic_processing():
    rag = ProtectedRAG(GuardClient("https://guard.example"), max_response_bytes=25000)
    assert len(rag._buffer("x" for _ in range(20000))) == 20000


def test_destructive_recovery_validator_help_has_no_side_effects():
    import subprocess
    import sys

    command = [sys.executable, "scripts/validate_redis_durable_recovery.py"]
    help_result = subprocess.run(
        [*command, "--help"], capture_output=True, text=True, check=False
    )
    assert help_result.returncode == 0
    assert "--execute" in help_result.stdout
    default_result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert default_result.returncode != 0
    assert "Destructive validation disabled" in default_result.stderr


def test_legacy_guard_cache_migration_defaults_to_unhealthy(tmp_path):
    """Old Protect bindings cannot acquire trust merely by adding a new column."""
    import sqlite3

    db_path = tmp_path / "legacy-guard.db"
    with sqlite3.connect(db_path) as db:
        db.execute(
            "CREATE TABLE bound_applications ("
            "application_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, mode TEXT NOT NULL)"
        )
        db.execute(
            "INSERT INTO bound_applications VALUES (?, ?, ?)",
            ("rag", "drive", "protect"),
        )
    migrated = PolicyCache(str(db_path))
    assert migrated.application_binding("rag") == ("drive", "protect")
    assert not migrated.source_acl_healthy("rag")


def test_restarted_guard_requires_fresh_source_health_sync(tmp_path):
    """Source health is a runtime fact; stale disk state cannot prove freshness."""
    path = tmp_path / "restart-guard.db"
    old = PolicyCache(str(path))
    old.set_application_bindings([
        {"application_id": "rag", "source_id": "drive",
         "mode": "protect", "source_acl_healthy": True}
    ])
    assert old.source_acl_healthy("rag")
    restarted = PolicyCache(str(path))
    assert not restarted.source_acl_healthy("rag")
