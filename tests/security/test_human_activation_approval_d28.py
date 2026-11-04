"""D-28: once every automatic check passed, a Guard heartbeat used to flip an
application to Protect with no human decision. Protect now also requires an
OWNER's explicit approval recorded after the latest verified cutover."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import _human_activation_approved, app
from apps.api.accessproof_api.db import AIApplication, AuditEvent, RAGRouteChallenge, SessionLocal, User
from apps.api.accessproof_api.route_certification import route_configuration_fingerprint
from tests.integration.test_route_certificate_state import _setup


def _certify(row_id, guard_id, cutover_at):
    with SessionLocal() as db:
        row = db.get(AIApplication, row_id)
        db.add(RAGRouteChallenge(
            organization_id="org-1", application_row_id=row_id, guard_id=guard_id, source_id="source-1",
            nonce_digest="9" * 64, configuration_fingerprint=route_configuration_fingerprint(row),
            status="cutover_verified", deployment_sha256="a" * 64, route_sha256="b" * 64,
            verified_at=cutover_at - timedelta(minutes=1), cutover_at=cutover_at,
            expires_at=cutover_at + timedelta(hours=1),
            result_json=json.dumps({"guard_policy_version_at_verification": 2}),
        ))
        db.commit()


def _approval(row_id, at, *, actor=True):
    with SessionLocal() as db:
        user_id = None
        if actor:
            user = User(email=f"owner-{at.timestamp()}@example.com", password_hash="x")
            db.add(user)
            db.flush()
            user_id = user.id
        db.add(AuditEvent(organization_id="org-1", actor_user_id=user_id, action="PROTECT_ACTIVATION_APPROVED",
                          target_type="ai_application", target_id=row_id, metadata_json="{}", created_at=at))
        db.commit()


def _approved(row_id):
    with SessionLocal() as db:
        return _human_activation_approved(db, db.get(AIApplication, row_id))


def test_certified_route_alone_is_not_activation_approval():
    row_id, guard_id = _setup()
    _certify(row_id, guard_id, datetime.now(timezone.utc) - timedelta(minutes=5))
    assert _approved(row_id) is False


def test_approval_before_the_latest_cutover_or_by_a_machine_does_not_count():
    row_id, guard_id = _setup()
    now = datetime.now(timezone.utc)
    _approval(row_id, now - timedelta(minutes=30))                  # stale: before the cutover
    _certify(row_id, guard_id, now - timedelta(minutes=5))
    assert _approved(row_id) is False
    _approval(row_id, now - timedelta(minutes=1), actor=False)     # no human actor
    assert _approved(row_id) is False
    _approval(row_id, now - timedelta(minutes=1))                  # owner, after cutover
    assert _approved(row_id) is True


def test_approval_without_a_certified_route_does_not_count():
    row_id, _guard_id = _setup()
    _approval(row_id, datetime.now(timezone.utc))
    assert _approved(row_id) is False


def test_approval_endpoint_requires_exact_confirmation_and_a_certified_route():
    from apps.api.accessproof_api.db import Base, engine
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        account = client.post("/api/v1/auth/signup", json={
            "email": "d28-owner@example.com", "password": "correct horse battery staple",
            "organization_name": "D28 organization"}).json()
        headers = {"Authorization": f"Bearer {account['session_token']}", "X-Organization-ID": account["organization_id"]}
        assert client.post("/api/v1/current/ai-applications", headers=headers,
                           json={"application_id": "rag", "name": "RAG"}).status_code == 201
        url = "/api/v1/current/ai-applications/rag/protection/approve"
        assert client.post(url, headers=headers, json={"confirm_text": "yes", "reviewer": "Reviewer"}).status_code == 422
        assert client.post(url, headers=headers, json={"confirm_text": "APPROVE PROTECT rag"}).status_code == 422
        refused = client.post(url, headers=headers, json={"confirm_text": "APPROVE PROTECT rag", "reviewer": "Reviewer"})
        assert refused.status_code == 409 and refused.json()["detail"] == "ROUTE_CERTIFICATE_REQUIRED_BEFORE_APPROVAL"
        assert client.post("/api/v1/current/ai-applications/other/protection/approve", headers=headers,
                           json={"confirm_text": "APPROVE PROTECT other", "reviewer": "Reviewer"}).status_code == 404
