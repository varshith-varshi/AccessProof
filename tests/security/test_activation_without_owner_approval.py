"""No separate owner approval is required; enforcement prerequisites remain.

These regression tests never mint source credentials or bypass Guard readiness.
"""
from __future__ import annotations

from apps.api.accessproof_api.app import _automatic_activation_checklist
from apps.api.accessproof_api.db import AIApplication, SessionLocal
from tests.integration.test_route_certificate_state import _setup


def test_unapproved_application_still_has_full_security_checklist():
    row_id, _guard_id = _setup()
    with SessionLocal() as db:
        row = db.get(AIApplication, row_id)
        checks = _automatic_activation_checklist(db, row)
    codes = {check["code"] for check in checks}
    assert "HUMAN_ACTIVATION_APPROVAL_REQUIRED" not in codes
    assert "GATEWAY_LIVE_AND_ENFORCEMENT_READY" in codes
    assert "PERMISSION_SOURCE_USABLE" in codes
    assert any(not check["ok"] for check in checks)


def test_unapproved_app_cannot_activate_without_live_gateway_and_source():
    row_id, _guard_id = _setup()
    with SessionLocal() as db:
        row = db.get(AIApplication, row_id)
        failed = [check["code"] for check in _automatic_activation_checklist(db, row)
                  if not check["ok"]]
        assert "GATEWAY_LIVE_AND_ENFORCEMENT_READY" in failed
        assert row.mode == "shadow"
