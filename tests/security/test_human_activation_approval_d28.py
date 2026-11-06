"""Protect owner approval binds to the live installer, never old credentials.

Customer-specific allow/deny/tamper/revoke challenges are optional after
activation. Authorization, source and Gateway readiness checks remain mandatory.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import (
    _activation_approval_binding, _human_activation_approved, app,
)
from apps.api.accessproof_api.db import (
    AIApplication, AuditEvent, GatewayInstallation, RAGRouteChallenge, SessionLocal, User,
)
from tests.integration.test_route_certificate_state import _setup, _challenge
from apps.api.accessproof_api.route_certification import route_configuration_fingerprint


def _install(row_id: str, *, installation_id: str = "installed-1") -> None:
    with SessionLocal() as db:
        row = db.get(AIApplication, row_id)
        db.add(GatewayInstallation(
            id=installation_id, organization_id=row.organization_id,
            application_row_id=row.id, credential_hash="never-a-real-credential",
            guard_id=row.guard_id, source_id=row.source_id,
            deployment_sha256="a" * 64, route_sha256="b" * 64,
        ))
        db.commit()


def _approval(row_id: str, *, actor=True, signed_binding=True) -> None:
    with SessionLocal() as db:
        row = db.get(AIApplication, row_id)
        who = None
        if actor:
            user = User(email=f"owner-{datetime.now(timezone.utc).timestamp()}@example.com", password_hash="x")
            db.add(user)
            db.flush()
            who = user.id
        binding = _activation_approval_binding(db, row)
        metadata = binding if signed_binding and binding else {}
        db.add(AuditEvent(
            organization_id=row.organization_id, actor_user_id=who,
            action="PROTECT_ACTIVATION_APPROVED", target_type="ai_application",
            target_id=row.id, metadata_json=json.dumps(metadata),
        ))
        db.commit()


def _approved(row_id: str) -> bool:
    with SessionLocal() as db:
        return _human_activation_approved(db, db.get(AIApplication, row_id))


def test_no_installation_cannot_be_owner_approved():
    row_id, _guard_id = _setup()
    _approval(row_id)
    assert _approved(row_id) is False


def test_unbound_or_machine_approval_never_counts():
    row_id, _guard_id = _setup()
    _install(row_id)
    _approval(row_id, actor=False)
    _approval(row_id, signed_binding=False)
    assert _approved(row_id) is False
    _approval(row_id)
    assert _approved(row_id) is True


def test_new_installation_or_new_guard_binding_invalidates_approval():
    row_id, _guard_id = _setup()
    _install(row_id)
    _approval(row_id)
    assert _approved(row_id) is True
    with SessionLocal() as db:
        record = db.get(GatewayInstallation, "installed-1")
        record.id = "installed-2"
        db.commit()
    assert _approved(row_id) is False
    _approval(row_id)
    assert _approved(row_id) is True
    with SessionLocal() as db:
        row = db.get(AIApplication, row_id)
        row.source_id = "other-source"
        db.commit()
    assert _approved(row_id) is False


def test_approval_endpoint_rejects_wrong_confirmation_and_missing_gateway():
    from apps.api.accessproof_api.db import Base, engine
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        account = client.post("/api/v1/auth/signup", json={
            "email": "owner@example.com", "password": "correct horse battery staple",
            "organization_name": "Approval org",
        }).json()
        headers = {
            "Authorization": f"Bearer {account['session_token']}",
            "X-Organization-ID": account["organization_id"],
        }
        assert client.post("/api/v1/current/ai-applications", headers=headers,
                           json={"application_id": "rag", "name": "RAG"}).status_code == 201
        endpoint = "/api/v1/current/ai-applications/rag/protection/approve"
        assert client.post(endpoint, headers=headers,
                           json={"confirm_text": "yes", "reviewer": "Reviewer"}).status_code == 422
        assert client.post(endpoint, headers=headers,
                           json={"confirm_text": "APPROVE PROTECT rag"}).status_code == 422
        refused = client.post(endpoint, headers=headers, json={
            "confirm_text": "APPROVE PROTECT rag", "reviewer": "Reviewer",
        })
        assert refused.status_code == 409
        assert refused.json()["detail"] == "CURRENT_GATEWAY_INSTALLATION_REQUIRED"
        assert client.post("/api/v1/current/ai-applications/other/protection/approve",
                           headers=headers, json={
                               "confirm_text": "APPROVE PROTECT other", "reviewer": "Reviewer",
                           }).status_code == 404


def test_legacy_owner_approval_survives_release_only_while_route_certificate_valid():
    """The new installer-bound approval must not silently revoke old customers."""
    row_id, guard_id = _setup()
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        row = db.get(AIApplication, row_id)
        entry = _challenge(
            row_id, guard_id, status="cutover_verified",
            verified_at=now - timedelta(minutes=5),
            cutover_at=now - timedelta(minutes=4),
            fingerprint=route_configuration_fingerprint(row),
        )
        db.add(entry)
        db.flush()
        cert_id = entry.id
        user = User(email="legacy-owner@example.com", password_hash="x")
        db.add(user)
        db.flush()
        db.add(AuditEvent(
            organization_id=row.organization_id, actor_user_id=user.id,
            action="PROTECT_ACTIVATION_APPROVED", target_type="ai_application",
            target_id=row.id, metadata_json=json.dumps({"route_certificate": cert_id}),
            created_at=now - timedelta(minutes=1),
        ))
        db.commit()
    assert _approved(row_id) is True
    with SessionLocal() as db:
        cert = db.get(RAGRouteChallenge, cert_id)
        cert.verified_at = now - timedelta(hours=25)
        db.commit()
    assert _approved(row_id) is False
