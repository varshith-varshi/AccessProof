"""Trusted permission event ingestion must be provider-authenticated and tenant-scoped."""
from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, SessionLocal, Project, SourceConnection, engine


def signup(client, email):
    return client.post("/api/v1/auth/signup", json={
        "email": email, "password": "correct horse battery staple",
        "organization_name": email,
    }).json()


def headers(account):
    return {
        "Authorization": f"Bearer {account['session_token']}",
        "X-Organization-ID": account["organization_id"],
    }


def test_guard_event_api_is_authenticated_tenant_scoped_and_idempotent(monkeypatch):
    secret = "synthetic-provider-ingest-test-token-unique-0123456789"
    monkeypatch.setenv("ACCESSPROOF_PERMISSION_EVENT_INGEST_KEY", secret)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        org_a = signup(client, "guard-a@example.com")
        org_b = signup(client, "guard-b@example.com")
        with SessionLocal() as db:
            project = Project(organization_id=org_a["organization_id"], name="synthetic")
            db.add(project)
            db.flush()
            source = SourceConnection(
                organization_id=org_a["organization_id"], project_id=project.id,
                provider="google-drive", name="synthetic Drive", boundary="root",
            )
            db.add(source)
            db.commit()
            source_id = source.id
        payload = {
            "source_id": source_id, "provider": "google-drive",
            "provider_revision": 7, "subject_id": "stable-subject",
            "resource_id": "stable-file", "change_type": "revoke",
            "dedupe_key": "provider-event-7",
        }
        assert client.post("/api/v1/guard/permission-events", json=payload).status_code == 401
        assert client.post("/api/v1/guard/permission-events",
                           headers=headers(org_a), json=payload).status_code == 403
        authenticated = {**headers(org_a), "X-AccessProof-Ingest-Key": secret}
        first = client.post("/api/v1/guard/permission-events", headers=authenticated, json=payload)
        assert first.status_code == 201 and first.json()["deduplicated"] is False
        duplicate = client.post("/api/v1/guard/permission-events", headers=authenticated, json=payload)
        assert duplicate.status_code == 201 and duplicate.json()["deduplicated"] is True
        assert len(client.get("/api/v1/guard/permission-events", headers=headers(org_a)).json()) == 1
        assert client.get("/api/v1/guard/permission-events", headers=headers(org_b)).json() == []
