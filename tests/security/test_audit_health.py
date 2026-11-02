"""Audit backpressure must be visible in Guard readiness and machine heartbeat."""
from __future__ import annotations

import json

import httpx

from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache
from apps.guard.accessproof_guard.sync import GuardMachineCredentials, GuardSyncClient


def test_full_audit_queue_is_reported_unready_and_in_heartbeat(tmp_path, monkeypatch):
    cache = PolicyCache(str(tmp_path / "audit-health.db"), max_audit_records=1)
    cache.install(1, [
        {"subject_id": "alice", "source_id": "drive",
         "resource_id": "handbook", "decision": "allow"},
    ])
    cache.set_application_bindings([{
        "application_id": "rag", "source_id": "drive",
        "mode": "protect", "source_acl_healthy": True,
    }])
    cache.mark_sync_success()
    monkeypatch.setattr(guard_app, "cache", cache)
    monkeypatch.setattr(guard_app, "control_plane_url", "https://example.invalid")
    monkeypatch.setattr(guard_app, "guard_id", "synthetic-guard")
    monkeypatch.setattr(guard_app, "guard_credential", "synthetic-machine-token")
    monkeypatch.setattr(guard_app, "_sync_error", None)
    monkeypatch.setattr(guard_app, "identity_mode", "oidc")
    monkeypatch.setattr(guard_app, "issuer", "https://idp.example")
    monkeypatch.setattr(guard_app, "audience", "api://accessproof-test")
    assert guard_app.health()["ready"] is True

    cache.buffer_audit(
        "pending-1", application_id="rag", subject_id="alice",
        request_id="r", result="allow", reason="TEST_ONLY", policy_version=1,
    )

    observed = guard_app.health()
    assert observed["ready"] is False
    assert observed["status"] == "degraded"
    assert observed["audit_buffer_ready"] is False

    sent = []
    def receive(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"ok": True})

    client = GuardSyncClient(cache, GuardMachineCredentials(
        "https://example.invalid", "synthetic-guard", "synthetic-machine-token", "1.0",
    ), httpx.Client(transport=httpx.MockTransport(receive)))
    client.heartbeat()
    assert sent[-1]["cache_status"] == "degraded"
    assert "AUDIT_BACKLOG_FULL" in sent[-1]["degraded_conditions"]

    cache.mark_audit_delivered(["pending-1"])
    assert guard_app.health()["ready"] is True
