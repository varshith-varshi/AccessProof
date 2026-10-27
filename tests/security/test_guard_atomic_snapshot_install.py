"""Guard policy, revisions, identities and app modes are one crash-atomic boundary."""
from __future__ import annotations

import httpx
import pytest

from apps.guard.accessproof_guard.cache import PolicyCache
from apps.guard.accessproof_guard.sync import GuardMachineCredentials, GuardSyncClient


def _snapshot(version: int):
    return dict(
        version=version,
        decisions=[{"version": version, "subject_id": "alice", "source_id": "drive",
                    "resource_id": "payroll", "scope": "read", "decision": "allow"}],
        full_snapshot=True,
        applications=[{"application_id": "rag", "source_id": "drive",
                       "mode": "protect", "source_acl_healthy": True}],
        mappings=[{"source_id": "drive", "issuer": "https://accounts.google.com",
                   "subject": "google-alice", "source_subject_id": "alice"}],
        revisions=[{"application_id": "rag", "revision": version,
                    "revision_hash": f"{version:064x}", "generated_at": "2026-10-26T00:00:00Z"}],
    )


@pytest.mark.parametrize("failure_method", [
    "install", "set_authorization_revisions", "set_application_bindings",
    "set_identity_mappings", "mark_sync_success",
])
def test_snapshot_rolls_back_every_stage(tmp_path, monkeypatch, failure_method):
    path = tmp_path / "guard.db"
    cache = PolicyCache(str(path))
    cache.apply_sync_snapshot(**_snapshot(1))
    assert cache.decide("alice", "drive", "payroll", "read")[0] == "allow"

    original = getattr(cache, failure_method)
    def fail_after_commit_attempt(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("simulated interrupted installation")
    monkeypatch.setattr(cache, failure_method, fail_after_commit_attempt)

    candidate = _snapshot(2)
    candidate["decisions"][0]["decision"] = "deny"
    with pytest.raises(RuntimeError, match="simulated interrupted installation"):
        cache.apply_sync_snapshot(**candidate)

    # Not even policy metadata or last-sync timestamp may be partially committed.
    reopened = PolicyCache(str(path))
    assert reopened.version() == 1
    assert reopened.decide("alice", "drive", "payroll", "read")[0] == "allow"
    assert reopened.authorization_revision("rag") == (1, "1".zfill(64))
    assert reopened.resolve_identity("drive", "https://accounts.google.com", "google-alice", None) == "alice"


def test_snapshot_rejects_malformed_binding_without_partial_allow(tmp_path):
    cache = PolicyCache(str(tmp_path / "guard.db"))
    payload = _snapshot(1)
    payload["applications"][0]["source_acl_healthy"] = "yes"
    with pytest.raises(ValueError, match="INVALID_SOURCE_ACL_HEALTH"):
        cache.apply_sync_snapshot(**payload)
    assert cache.version() == 0
    assert not cache.application_bindings_received()
    assert cache.resolve_identity("drive", "https://accounts.google.com", "google-alice", None) is None


def test_sync_installed_ack_only_after_atomic_commit(tmp_path, monkeypatch):
    cache = PolicyCache(str(tmp_path / "guard.db"))
    requests = []
    def handler(req: httpx.Request):
        requests.append(req)
        if req.method == "GET":
            snap = _snapshot(1)
            return httpx.Response(200, json={
                "kind": "full", "version": 1, "decisions": snap["decisions"],
                "applications": snap["applications"], "identity_mappings": snap["mappings"],
                "authorization_revisions": snap["revisions"],
            })
        return httpx.Response(200, json={"ok": True})
    client = GuardSyncClient(
        cache, GuardMachineCredentials("https://control.example", "guard", "machine", "1"),
        httpx.Client(transport=httpx.MockTransport(handler)),
    )
    original = cache.set_identity_mappings
    def interrupt(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("disk failure")
    monkeypatch.setattr(cache, "set_identity_mappings", interrupt)
    with pytest.raises(RuntimeError, match="disk failure"):
        client.sync_once()
    assert cache.version() == 0
    assert not cache.authorization_revisions_received()
    assert all(b'"installed"' not in req.content for req in requests if req.method == "POST")


def test_lost_installed_ack_survives_restart_and_retries(tmp_path):
    """The policy is committed, but a failed HTTP acknowledgement is durable."""
    path = tmp_path / "ack-retry.db"
    cache = PolicyCache(str(path))
    installed_attempts = []

    def handler(req: httpx.Request):
        if req.method == "GET":
            snap = _snapshot(1)
            return httpx.Response(200, json={
                "kind": "incremental", "version": 1, "policies": snap["decisions"],
                "applications": snap["applications"],
                "identity_mappings": snap["mappings"],
                "authorization_revisions": snap["revisions"],
            })
        if b'"installed"' in req.content:
            installed_attempts.append(req.content)
            if len(installed_attempts) == 1:
                return httpx.Response(503, json={"error": "network"})
        return httpx.Response(200, json={"ok": True})

    client = GuardSyncClient(
        cache, GuardMachineCredentials("https://control.example", "g", "machine", "1"),
        httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(httpx.HTTPStatusError):
        client.sync_once()
    assert cache.version() == 1
    assert cache.pending_installed_policy_acks() == [1]

    # Simulate an actual Guard process restart and a resynchronized identity
    # snapshot; the installed confirmation is retried without re-ALLOW.
    reopened = PolicyCache(str(path))
    retry = GuardSyncClient(
        reopened, GuardMachineCredentials("https://control.example", "g", "machine", "1"),
        httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert retry.sync_once() is False
    assert reopened.pending_installed_policy_acks() == []
    assert len(installed_attempts) == 2
