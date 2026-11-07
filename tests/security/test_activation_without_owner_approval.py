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


def test_reference_challenge_rejects_missing_live_gateway_before_issuing_nonce():
    from fastapi import HTTPException
    from types import SimpleNamespace
    from apps.api.accessproof_api.app import issue_current_reference_rag_challenge
    from apps.api.accessproof_api.schemas import RouteChallengeStart
    from apps.api.accessproof_api.db import RAGRouteChallenge
    from sqlalchemy import select, func

    row_id, guard_id = _setup()
    with SessionLocal() as db:
        row = db.get(AIApplication, row_id)
        # The guard is enrolled with a valid policy, but there is no Gateway
        # presence lease or deployment. A manifest digest is not liveness.
        guard = db.get(__import__("apps.api.accessproof_api.db", fromlist=["GuardRegistration"]).GuardRegistration, guard_id)
        guard.active_policy_version = 2
        db.flush()
        actor = SimpleNamespace(membership=SimpleNamespace(organization_id=row.organization_id))
        payload = RouteChallengeStart(deployment_sha256="a" * 64, route_sha256="b" * 64)
        with __import__("pytest").raises(HTTPException, match="LIVE_ENFORCEMENT_READY_GATEWAY_REQUIRED"):
            issue_current_reference_rag_challenge(row.application_id, payload, actor, db)
        assert db.scalar(select(func.count(RAGRouteChallenge.id))) == 0
