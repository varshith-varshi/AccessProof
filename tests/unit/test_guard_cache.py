from apps.guard.accessproof_guard.cache import PolicyCache
from apps.guard.accessproof_guard.sync import GuardMachineCredentials, GuardSyncClient
import httpx


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


def test_decision_context_is_bound_to_application_and_subject(tmp_path):
    cache = PolicyCache(str(tmp_path / "guard.db"))
    cache.save_context("decision", "rag", "alice", ["finance"])
    assert cache.load_context("decision", "rag", "alice") == {"finance"}
    assert cache.load_context("decision", "other-app", "alice") is None
    assert cache.load_context("decision", "rag", "bob") is None


def test_identity_mapping_is_exact_and_revocation_snapshot_removes_it(tmp_path):
    cache = PolicyCache(str(tmp_path / "guard.db"))
    cache.set_identity_mappings([{
        "source_id": "drive", "issuer": "https://tenant.example/", "subject": "employee-1",
        "tenant_id": "tenant-a", "source_subject_id": "google-opaque-id",
    }])
    assert cache.resolve_identity("drive", "https://tenant.example/", "employee-1", "tenant-a") == "google-opaque-id"
    assert cache.resolve_identity("drive", "https://tenant.example", "employee-1", "tenant-a") is None
    assert cache.resolve_identity("drive", "https://tenant.example/", "employee-1", "tenant-b") is None
    cache.set_identity_mappings([])
    assert cache.resolve_identity("drive", "https://tenant.example/", "employee-1", "tenant-a") is None


def test_decision_context_is_bound_to_request_and_is_one_time_use(tmp_path):
    cache = PolicyCache(str(tmp_path / "guard.db"))
    cache.save_context("decision", "rag", "bob", ["handbook"], request_id="request-1")
    assert cache.load_context("decision", "rag", "bob", "request-2") is None
    assert cache.consume_context("decision", "rag", "bob", "request-1")
    assert cache.load_context("decision", "rag", "bob", "request-1") is None
    assert not cache.consume_context("decision", "rag", "bob", "request-1")


def test_audit_buffer_is_idempotent_and_bounded_without_content(tmp_path):
    cache = PolicyCache(str(tmp_path / "guard.db"), max_audit_records=2)
    assert cache.buffer_audit("a", application_id="rag", subject_id="alice", request_id="r1", result="block", reason="DENY", policy_version=1)
    assert not cache.buffer_audit("a", application_id="rag", subject_id="alice", request_id="r1", result="block", reason="DENY", policy_version=1)
    cache.buffer_audit("b", application_id="rag", subject_id="alice", request_id="r2", result="allow", reason="ALLOW", policy_version=1)
    # While all records are undelivered, do not silently erase evidence.
    import pytest
    with pytest.raises(RuntimeError, match="AUDIT_BUFFER_FULL"):
        cache.buffer_audit("c", application_id="rag", subject_id="alice", request_id="r3", result="allow", reason="ALLOW", policy_version=1)
    assert {item["event_id"] for item in cache.pending_audit()} == {"a", "b"}
    cache.mark_audit_delivered(["a"])
    cache.buffer_audit("c", application_id="rag", subject_id="alice", request_id="r3", result="allow", reason="ALLOW", policy_version=1)
    pending = cache.pending_audit()
    assert len(pending) == 2
    assert {item["event_id"] for item in pending} == {"b", "c"}
    assert set(pending[0]) == {"event_id", "application_id", "subject_id", "request_id", "result", "reason", "policy_version"}


def test_sync_client_installs_then_acks_and_uploads_audit_idempotently(tmp_path):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, json={"kind": "incremental", "version": 3, "applications": [{"application_id": "rag", "source_id": "drive", "mode": "protect", "source_acl_healthy": True}], "policies": [{"version": 3, "subject_id": "alice", "source_id": "drive", "resource_id": "finance", "scope": "read", "decision": "deny", "reason": "REVOKED"}]})
        return httpx.Response(202 if request.url.path.endswith("audit-events") else 200, json={"ok": True})

    cache = PolicyCache(str(tmp_path / "guard.db"))
    cache.buffer_audit("audit-1", application_id="rag", subject_id="alice", request_id="r1", result="block", reason="DENY", policy_version=3)
    client = GuardSyncClient(cache, GuardMachineCredentials("https://control.example", "guard-1", "machine-secret", "1.0.0"), httpx.Client(transport=httpx.MockTransport(handler)))
    assert client.sync_once()
    assert cache.decide("alice", "drive", "finance", "read")[0] == "deny"
    assert client.upload_audit() == 1
    assert client.upload_audit() == 0
    ack_statuses = [request.content for request in requests if request.url.path.endswith("/ack")]
    assert len(ack_statuses) == 2 and b"received" in ack_statuses[0] and b"installed" in ack_statuses[1]


def test_guard_enrollment_cli_delegates_to_secure_onboarding(tmp_path, monkeypatch):
    from apps.guard.accessproof_guard import cli
    recorded = {}

    def exchange(**kwargs):
        recorded.update(kwargs)
        destination = kwargs["state_dir"] / "credentials.json"
        destination.write_text('{"guard_id":"guard-1"}')
        destination.chmod(0o600)
        return {"guard_id": "guard-1"}

    monkeypatch.setattr(cli, "enroll_guard", exchange)
    cli.enroll(server="https://control.example", token="one-time", version="1.2.3",
               state_dir=tmp_path, issuer="https://issuer.example", audience="rag")
    assert recorded["server"] == "https://control.example"
    assert recorded["issuer"] == "https://issuer.example"
    assert recorded["audience"] == "rag"
    assert (tmp_path / "credentials.json").stat().st_mode & 0o777 == 0o600



def test_stale_control_plane_policy_cannot_change_application_mode(tmp_path):
    import pytest

    cache = PolicyCache(str(tmp_path / "guard.db"))
    cache.install(9, [{"subject_id": "alice", "source_id": "drive",
                       "resource_id": "doc", "decision": "allow"}])
    cache.set_application_bindings([
        {"application_id": "rag", "source_id": "drive", "mode": "protect"}
    ])
    assert cache.application_binding("rag") == ("drive", "protect")

    def stale(request):
        return httpx.Response(200, json={
            "version": 8, "kind": "incremental", "policies": [],
            "applications": [{"application_id": "rag", "source_id": "drive", "mode": "shadow"}],
        })
    client = GuardSyncClient(
        cache, GuardMachineCredentials("https://control.example", "guard-1", "machine", "1"),
        httpx.Client(transport=httpx.MockTransport(stale)),
    )
    with pytest.raises(ValueError, match="STALE_POLICY"):
        client.sync_once()
    assert cache.application_binding("rag") == ("drive", "protect")
    assert cache.version() == 9



def test_machine_heartbeat_degraded_without_installed_policy(tmp_path):
    import json
    observed = []
    def receive(request: httpx.Request) -> httpx.Response:
        observed.append(json.loads(request.content))
        return httpx.Response(200, json={"ok": True})
    cache = PolicyCache(str(tmp_path / "empty-heartbeat.db"))
    client = GuardSyncClient(
        cache, GuardMachineCredentials("https://control.example", "g", "machine", "1"),
        httpx.Client(transport=httpx.MockTransport(receive)),
    )
    client.heartbeat()
    assert observed[-1]["cache_status"] == "degraded"
    assert "POLICY_NOT_INSTALLED" in observed[-1]["degraded_conditions"]
    cache.install(1, [{"subject_id": "alice", "source_id": "drive",
                       "resource_id": "test", "decision": "deny"}])
    cache.mark_sync_success()
    client.heartbeat()
    assert observed[-1]["cache_status"] == "healthy"
    assert observed[-1]["degraded_conditions"] == []


def test_guard_rejects_stale_revision_before_installing_allow_or_ack(tmp_path):
    """No new ALLOW may be committed if the revision envelope is rejected."""
    import pytest
    cache = PolicyCache(str(tmp_path / "guard-preflight.db"))
    cache.install(3, [{
        "subject_id": "alice", "source_id": "drive", "resource_id": "secret",
        "decision": "deny", "reason": "REVOKED",
    }])
    cache.set_authorization_revisions([{
        "application_id": "rag", "revision": 2, "revision_hash": "b" * 64,
        "generated_at": "2026-10-26T00:00:00Z",
    }])
    acks: list[httpx.Request] = []

    def stale_revision(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            acks.append(request)
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(200, json={
            "kind": "incremental", "version": 4,
            "applications": [{
                "application_id": "rag", "source_id": "drive",
                "mode": "protect", "source_acl_healthy": True,
            }],
            "authorization_revisions": [{
                "application_id": "rag", "revision": 1, "revision_hash": "a" * 64,
                "generated_at": "2026-10-26T00:00:00Z",
            }],
            "policies": [{
                "version": 4, "subject_id": "alice", "source_id": "drive",
                "resource_id": "secret", "scope": "read", "decision": "allow",
            }],
        })

    client = GuardSyncClient(
        cache, GuardMachineCredentials("https://control.example", "g", "machine", "1"),
        httpx.Client(transport=httpx.MockTransport(stale_revision)),
    )
    with pytest.raises(ValueError, match="STALE_AUTHORIZATION_REVISION"):
        client.sync_once()
    assert cache.version() == 3
    assert cache.decide("alice", "drive", "secret", "read")[0] == "deny"
    assert cache.authorization_revision("rag") == (2, "b" * 64)
    assert acks == []


def test_guard_rejects_invalid_identity_mapping_before_policy_install(tmp_path):
    """A malformed mapping cannot leave new ALLOW decisions installed."""
    import pytest
    cache = PolicyCache(str(tmp_path / "guard-mapping-preflight.db"))
    observed: list[httpx.Request] = []

    def malformed(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(200, json={
            "kind": "incremental", "version": 1,
            "applications": [{
                "application_id": "rag", "source_id": "drive",
                "mode": "protect", "source_acl_healthy": True,
            }],
            "identity_mappings": [{
                "source_id": "drive", "issuer": "https://issuer.example",
                "subject": "alice", "source_subject_id": "",
            }],
            "policies": [{
                "version": 1, "subject_id": "alice", "source_id": "drive",
                "resource_id": "secret", "scope": "read", "decision": "allow",
            }],
        })

    client = GuardSyncClient(
        cache, GuardMachineCredentials("https://control.example", "g", "machine", "1"),
        httpx.Client(transport=httpx.MockTransport(malformed)),
    )
    with pytest.raises(ValueError, match="INVALID_IDENTITY_MAPPINGS"):
        client.sync_once()
    assert cache.version() == 0
    assert cache.decide("alice", "drive", "secret", "read")[0] == "unknown"
    assert not cache.application_bindings_received()
    assert all(request.method == "GET" for request in observed)


def test_presence_sequence_survives_guard_process_restart(tmp_path):
    from apps.guard.accessproof_guard.cache import PolicyCache
    path = str(tmp_path / "persistent-presence.db")
    first = PolicyCache(path)
    assert first.next_presence_sequence() == 1
    assert first.next_presence_sequence() == 2
    first.db.close()
    second = PolicyCache(path)
    assert second.next_presence_sequence() == 3
    second.db.close()
