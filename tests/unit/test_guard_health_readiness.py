"""Regression: an unenrolled Guard must not claim to be ready or healthy."""

from types import SimpleNamespace

import pytest

from apps.guard.accessproof_guard import app as guard_app


@pytest.mark.parametrize(
    ("policy_version", "sync_error", "expected_status"),
    [
        (0, None, "degraded"),
        (1, None, "ok"),
        (1, "SyncError", "degraded"),
    ],
)
def test_guard_health_tracks_policy_readiness(
    monkeypatch, policy_version: int, sync_error: str | None, expected_status: str
) -> None:
    fake_cache = SimpleNamespace(
        sync_age_seconds=lambda: 0.0,
        all_protect_sources_healthy=lambda: True,
        audit_has_capacity=lambda: True,
        application_bindings_received=lambda: True,
        application_modes=lambda: {"rag-test": "protect"},
        authorization_revisions_received=lambda: False,
        all_protect_revisions_present=lambda: True,
        version=lambda: policy_version,
    )
    monkeypatch.setattr(guard_app, "cache", fake_cache)
    monkeypatch.setattr(guard_app, "control_plane_url", "http://control-plane.invalid")
    monkeypatch.setattr(guard_app, "guard_id", "fake-machine")
    monkeypatch.setattr(guard_app, "guard_credential", "synthetic-test-only")
    monkeypatch.setattr(guard_app, "_sync_error", sync_error)

    response = guard_app.health()
    assert response["ready"] is (policy_version > 0)
    assert response["policy_version"] == policy_version
    assert response["status"] == expected_status


def test_enrolled_guard_with_zero_application_bindings_is_not_ready(tmp_path, monkeypatch) -> None:
    """A successful empty binding sync must not mark a customer Guard healthy."""
    from apps.guard.accessproof_guard.cache import PolicyCache

    state = PolicyCache(str(tmp_path / "guard-readiness.db"))
    state.install(5, [{"subject_id": "alice", "source_id": "drive",
                       "resource_id": "synthetic-doc", "decision": "allow"}])
    state.set_application_bindings([])
    state.mark_sync_success()
    monkeypatch.setattr(guard_app, "cache", state)
    monkeypatch.setattr(guard_app, "control_plane_url", "https://control.invalid")
    monkeypatch.setattr(guard_app, "guard_id", "guard-test")
    monkeypatch.setattr(guard_app, "guard_credential", "synthetic")
    monkeypatch.setattr(guard_app, "_sync_error", None)
    observed = guard_app.health()
    assert observed["ready"] is False
    assert observed["status"] == "degraded"
