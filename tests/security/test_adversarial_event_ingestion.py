"""Adversarial regression: a human session is not a trusted ACL provider."""
from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    Base, GuardEffectiveAccess, GuardPermissionEvent, Membership, SessionLocal,
    SourceConnection, Project, engine,
)
from apps.api.accessproof_api.guard_pipeline import process_guard_event

_SYNTHETIC_KEY = "local-security-regression-ingest-secret-only-123456789"


def _setup(client: TestClient):
    acc = client.post("/api/v1/auth/signup", json={
        "email": "redteam-ingest@example.com",
        "password": "correct horse battery staple",
        "organization_name": "Redteam Ingestion",
    }).json()
    headers = {
        "Authorization": f"Bearer {acc['session_token']}",
        "X-Organization-ID": acc["organization_id"],
    }
    with SessionLocal() as db:
        project = Project(organization_id=acc["organization_id"], name="synthetic")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=acc["organization_id"], project_id=project.id,
            provider="google-drive", name="test", boundary="root",
        )
        db.add(source)
        db.commit()
        source_id = source.id
    return acc, headers, source_id


def _forged_allow(source_id: str):
    return {
        "source_id": source_id, "provider": "google-drive",
        "provider_revision": 99, "subject_id": "victim-subject",
        "resource_id": "highly-confidential-document",
        "change_type": "grant_upsert", "dedupe_key": "evil-permission-99",
        "grant_key": "evil-allow", "grant_effect": "allow",
        "principal_type": "subject", "scope": "read",
    }


def test_viewer_session_cannot_inject_an_allow_grant(monkeypatch):
    monkeypatch.setenv("ACCESSPROOF_PERMISSION_EVENT_INGEST_KEY", _SYNTHETIC_KEY)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        acc, headers, source_id = _setup(client)
        with SessionLocal() as db:
            member = db.scalar(select(Membership).where(
                Membership.organization_id == acc["organization_id"]))
            member.role = "VIEWER"
            db.commit()
        reply = client.post("/api/v1/guard/permission-events",
                            headers=headers, json=_forged_allow(source_id))
        assert reply.status_code in (401, 403), reply.text
        with SessionLocal() as db:
            assert db.scalar(select(GuardPermissionEvent).where(
                GuardPermissionEvent.organization_id == acc["organization_id"])) is None


def test_admin_session_cannot_mint_source_grants_without_machine_auth(monkeypatch):
    monkeypatch.setenv("ACCESSPROOF_PERMISSION_EVENT_INGEST_KEY", _SYNTHETIC_KEY)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        acc, headers, source_id = _setup(client)
        reply = client.post("/api/v1/guard/permission-events",
                            headers=headers, json=_forged_allow(source_id))
        assert reply.status_code in (401, 403), reply.text
        with SessionLocal() as db:
            assert db.scalar(select(GuardPermissionEvent).where(
                GuardPermissionEvent.organization_id == acc["organization_id"])) is None


def test_machine_authenticated_admin_cannot_assert_other_source_provider(monkeypatch):
    monkeypatch.setenv("ACCESSPROOF_PERMISSION_EVENT_INGEST_KEY", _SYNTHETIC_KEY)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        _, headers, source_id = _setup(client)
        headers = {**headers, "X-AccessProof-Ingest-Key": _SYNTHETIC_KEY}
        payload = _forged_allow(source_id)
        payload["provider"] = "microsoft365"
        reply = client.post("/api/v1/guard/permission-events",
                            headers=headers, json=payload)
        assert reply.status_code in (403, 404, 422), reply.text


def test_authenticated_ingestion_is_auditable_and_still_processed(monkeypatch):
    monkeypatch.setenv("ACCESSPROOF_PERMISSION_EVENT_INGEST_KEY", _SYNTHETIC_KEY)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        acc, headers, source_id = _setup(client)
        headers = {**headers, "X-AccessProof-Ingest-Key": _SYNTHETIC_KEY}
        reply = client.post("/api/v1/guard/permission-events",
                            headers=headers, json=_forged_allow(source_id))
        assert reply.status_code == 201, reply.text
        with SessionLocal() as db:
            outcome = process_guard_event(db, reply.json()["id"])
            assert outcome["status"] == "resolved"
            row = db.scalar(select(GuardEffectiveAccess).where(
                GuardEffectiveAccess.organization_id == acc["organization_id"]))
            assert row is not None and row.decision == "allow"
