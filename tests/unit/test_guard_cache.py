from apps.guard.accessproof_guard.cache import PolicyCache
from apps.guard.accessproof_guard.sync import GuardMachineCredentials, GuardSyncClient
from apps.guard.accessproof_guard import cli
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
            return httpx.Response(200, json={"kind": "incremental", "version": 3, "policies": [{"version": 3, "subject_id": "alice", "source_id": "drive", "resource_id": "finance", "scope": "read", "decision": "deny", "reason": "REVOKED"}]})
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


def test_guard_enrollment_cli_persists_a_private_machine_credential(tmp_path, monkeypatch):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"guard_id": "guard-1", "guard_credential": "machine-credential"}

    monkeypatch.setattr(cli.httpx, "post", lambda *args, **kwargs: Response())
    cli.enroll(server="https://control.example/", token="one-time", version="1.2.3", state_dir=tmp_path)
    credentials = tmp_path / "credentials.json"
    assert credentials.stat().st_mode & 0o777 == 0o600
    assert credentials.read_text(encoding="utf-8") == (
        '{"control_plane_url": "https://control.example", "guard_id": "guard-1", "credential": "machine-credential"}'
    )
