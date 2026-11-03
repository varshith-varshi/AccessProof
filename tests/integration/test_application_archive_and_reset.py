"""O-05 application archive and O-04 owner-approved onboarding reset.

Both revoke and unbind; neither deletes users, memberships or audit history.
"""
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api import gateway_presence
from apps.api.accessproof_api import gateway_pairing
from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    AIApplication, AuditEvent, Base, GatewayInstallation, GuardRegistration, Membership,
    Project, SessionLocal, SourceConnection, User, engine,
)

PASSWORD = "correct horse battery staple"


def _signup(c, email, org):
    body = c.post("/api/v1/auth/signup", json={"email": email, "password": PASSWORD, "organization_name": org}).json()
    return {"Authorization": f"Bearer {body['session_token']}", "X-Organization-ID": body["organization_id"]}, body


def _seed(org_id: str) -> str:
    with SessionLocal() as db:
        project = Project(organization_id=org_id, name="p")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org_id, project_id=project.id, name="SharePoint",
                                  provider="sharepoint", boundary="root", status="connected",
                                  last_validated_at=datetime.now(timezone.utc), encrypted_credentials="secret")
        guard = GuardRegistration(organization_id=org_id, name="g", status="enrolled",
                                  enrolled_at=datetime.now(timezone.utc), credential_hash="h")
        db.add_all([source, guard])
        db.flush()
        app_row = AIApplication(organization_id=org_id, application_id="hr-bot", name="HR bot",
                                guard_id=guard.id, source_id=source.id, adapter_type="accessproof-gateway",
                                mode="protect")
        db.add(app_row)
        db.flush()
        gateway_presence.issue_installation(db, app_row, deployment_sha256="d" * 64, route_sha256="c" * 64)
        db.commit()
        return app_row.id


def test_archive_unbinds_hides_and_restores_without_losing_history(monkeypatch):
    monkeypatch.setattr(gateway_pairing, "clear", lambda **_: None)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        owner, body = _signup(c, "owner@example.com", "Northwind")
        other, _ = _signup(c, "other@example.com", "Contoso")
        row_id = _seed(body["organization_id"])
        url = "/api/v1/current/ai-applications/hr-bot/archive"
        assert c.post(url, headers=owner, json={}).status_code == 422
        assert c.post(url, headers=owner, json={"confirm_application_id": "wrong"}).status_code == 422
        assert c.post(url, headers=other, json={"confirm_application_id": "hr-bot"}).status_code == 404
        assert c.post(url, headers=owner, json={"confirm_application_id": "hr-bot"}).status_code == 200
        with SessionLocal() as db:
            row = db.get(AIApplication, row_id)
            assert row.archived_at and row.guard_id is None and row.source_id is None and row.mode == "shadow"
            assert db.scalar(select(GatewayInstallation.revoked_at)) is not None
            assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == "AI_APPLICATION_ARCHIVED"))
        assert all(a["application_id"] != "hr-bot" for a in c.get("/api/v1/current/ai-applications", headers=owner).json())
        assert c.post(url, headers=owner, json={"confirm_application_id": "hr-bot"}).status_code == 404
        # Re-registering restores the same row (history stays linked), never in Protect.
        restored = c.post("/api/v1/current/ai-applications", headers=owner, json={
            "application_id": "hr-bot", "name": "HR bot v2", "adapter_type": "accessproof-gateway",
            "adapter_contract_version": "accessproof.rag/v1"})
        assert restored.status_code == 201, restored.text
        assert restored.json()["id"] == row_id and restored.json()["mode"] == "shadow"


def test_onboarding_reset_requires_owner_preview_digest_and_confirmation(monkeypatch):
    monkeypatch.setattr(gateway_pairing, "clear", lambda **_: None)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        owner, body = _signup(c, "owner@example.com", "Northwind")
        org = body["organization_id"]
        _seed(org)
        preview = c.get("/api/v1/organization/onboarding-reset/preview", headers=owner).json()
        assert preview["will_archive_ai_applications"] == ["hr-bot"]
        assert preview["will_revoke_guards"] == 1 and preview["will_disconnect_sources"] == 1
        go = "/api/v1/organization/onboarding-reset"
        assert c.post(go, headers=owner, json={"scope_digest": "0" * 64, "confirm_text": preview["confirm_text"]}).status_code == 409
        assert c.post(go, headers=owner, json={"scope_digest": preview["scope_digest"], "confirm_text": "RESET"}).status_code == 422
        # A non-owner admin cannot reset.
        invite = c.post("/api/v1/organization/invitations", headers=owner, json={"email": "admin@example.com", "role": "ADMIN"}).json()
        admin, admin_body = _signup(c, "admin@example.com", "Admin personal")
        c.post("/api/v1/auth/invitations/accept", headers={"Authorization": admin["Authorization"]},
               json={"token": invite["development_invitation_token"]})
        admin_headers = {"Authorization": admin["Authorization"], "X-Organization-ID": org}
        assert c.get("/api/v1/organization/onboarding-reset/preview", headers=admin_headers).status_code == 403
        done = c.post(go, headers=owner, json={"scope_digest": preview["scope_digest"], "confirm_text": preview["confirm_text"]})
        assert done.status_code == 200, done.text
        with SessionLocal() as db:
            assert db.scalar(select(GuardRegistration.revoked_at)) is not None
            source = db.scalar(select(SourceConnection))
            assert source.status == "disconnected" and source.encrypted_credentials is None
            # Preserved: account, memberships, audit history.
            assert db.scalar(select(User.id).where(User.email == "owner@example.com"))
            assert db.scalar(select(Membership.id).where(Membership.organization_id == org))
            assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == "ONBOARDING_RESET"))
            assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == "AI_APPLICATION_ARCHIVED"))
        again = c.get("/api/v1/organization/onboarding-reset/preview", headers=owner).json()
        assert again["will_archive_ai_applications"] == [] and again["will_revoke_guards"] == 0
