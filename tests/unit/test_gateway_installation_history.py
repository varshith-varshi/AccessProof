"""Never lose an installation record when the *temporary* pairing key expires."""
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from apps.api.accessproof_api import app as accessproof


@pytest.fixture()
def binding():
    return SimpleNamespace(
        organization_id="org-customer-1",
        id="app-record-1",
        guard_id="guard-record-1",
        source_id="source-record-1",
    )


def _run(binding):
    return SimpleNamespace(
        created_at=datetime(2026, 11, 1, 18, 45, tzinfo=timezone.utc),
        state="WAITING_FOR_AUTHORIZATION",
        route_sha256="b" * 64,
        deployment_sha256="a" * 64,
    )


@pytest.mark.parametrize("old_state", ("not_started", "pairing_expired"))
def test_expired_redis_receipt_uses_durable_verification_run_without_claiming_liveness(
    monkeypatch, binding, old_state,
):
    monkeypatch.setattr(accessproof, "set_tenant_context", lambda db, org: None)
    db = Mock()
    db.scalar.return_value = _run(binding)
    result = accessproof._durable_gateway_installation_status(
        db, binding, {"state": old_state, "production_certification": False},
    )
    assert result["state"] == "installation_reported_historical"
    assert result["live_gateway_verified"] is False
    assert result["production_certification"] is False
    assert "2026-11-01" in result["received_at"]
    assert "does not prove" in result["message"]
    assert db.scalar.call_count == 1


@pytest.mark.parametrize("state", ["awaiting_customer_install", "installation_reported_unverified"])
def test_pending_or_current_pairing_never_overwritten_by_historical_run(monkeypatch, binding, state):
    monkeypatch.setattr(accessproof, "set_tenant_context", lambda db, org: pytest.fail("unexpected RLS query"))
    status = {"state": state, "received_at": "real"}
    assert accessproof._durable_gateway_installation_status(Mock(), binding, status) == status


def test_historical_receipt_does_not_create_installation_when_run_is_missing(monkeypatch, binding):
    monkeypatch.setattr(accessproof, "set_tenant_context", lambda db, org: None)
    db = Mock()
    db.scalar.return_value = None
    assert accessproof._durable_gateway_installation_status(
        db, binding, {"state": "not_started"},
    ) == {"state": "not_started"}


def test_missing_active_guard_or_source_must_not_inherit_historical_install(monkeypatch, binding):
    monkeypatch.setattr(accessproof, "set_tenant_context", lambda db, org: pytest.fail("unexpected RLS query"))
    binding.source_id = None
    assert accessproof._durable_gateway_installation_status(
        Mock(), binding, {"state": "not_started"},
    )["state"] == "not_started"
