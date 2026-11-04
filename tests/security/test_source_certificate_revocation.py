"""Owner-only immediate revocation of a source certificate."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import AuditEvent, Base, Project, SessionLocal, SourceConnection, SourceEffectiveCertification, engine


def _owner(client):
    a = client.post("/api/v1/auth/signup", json={"email": "cert-owner@example.com", "password": "correct horse battery staple",
                                                  "organization_name": "Cert org"}).json()
    return a, {"Authorization": f"Bearer {a['session_token']}", "X-Organization-ID": a["organization_id"]}


def test_owner_can_revoke_and_revocation_is_audited_and_scoped():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        account, headers = _owner(client)
        org = account["organization_id"]
        with SessionLocal() as db:
            project = Project(organization_id=org, name="p")
            db.add(project)
            db.flush()
            src = SourceConnection(organization_id=org, project_id=project.id, provider="sharepoint", boundary="root", name="s")
            db.add(src)
            db.flush()
            now = datetime.now(timezone.utc)
            db.add(SourceEffectiveCertification(organization_id=org, source_id=src.id, provider_profile="p", scope_digest="d" * 64,
                                                evidence_digest="e" * 64, verifier_version="v", certified_at=now,
                                                expires_at=now + timedelta(days=30), signature="s", status="verified"))
            db.commit()
            sid = src.id
        url = f"/api/v1/current/sources/{sid}/certificate/revoke"
        assert client.post(url, headers=headers, json={"confirm_text": "yes", "reason": "regression"}).status_code == 422
        assert client.post(url, headers=headers, json={"confirm_text": f"REVOKE CERTIFICATE {sid}"}).status_code == 422
        assert client.post("/api/v1/current/sources/other/certificate/revoke", headers=headers,
                           json={"confirm_text": "REVOKE CERTIFICATE other", "reason": "x" * 5}).status_code == 404
        ok = client.post(url, headers=headers, json={"confirm_text": f"REVOKE CERTIFICATE {sid}", "reason": "security regression"})
        assert ok.status_code == 200 and ok.json()["status"] == "revoked"
        with SessionLocal() as db:
            assert db.scalar(select(SourceEffectiveCertification.status)) == "revoked"
            assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == "SOURCE_CERTIFICATE_REVOKED")) is not None
