"""A failed customer-triggered directory read cannot commit partial ALLOW graph."""
from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api import app as api
from apps.api.accessproof_api.db import (
    Base, GuardSubject, ProviderSyncCursor, SessionLocal, SourceConnection, engine,
)
from connectors.directory import DirectorySyncError


def test_manual_directory_failure_rolls_back_partial_identity_graph(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    async def fail_after_partial_mutation(db, source, _creds):
        db.add(GuardSubject(
            organization_id=source.organization_id,
            provider="google-drive", provider_subject_id="MUST_NOT_COMMIT",
            status="active", drive_permission_id="SHOULD_NOT_COMMIT",
        ))
        db.flush()
        raise DirectorySyncError("GOOGLE_DRIVE_PERMISSION_ID_UNRESOLVED")

    monkeypatch.setattr(api, "synchronize_directory", fail_after_partial_mutation)
    with TestClient(api.app) as client:
        signup = client.post("/api/v1/auth/signup", json={
            "email": "atomic-dir-admin@example.com",
            "password": "synthetic-directory-password",
            "organization_name": "Manual Directory Fail Closed",
        })
        assert signup.status_code == 201, signup.text
        result = signup.json()
        headers = {
            "Authorization": f"Bearer {result['session_token']}",
            "X-Organization-ID": result["organization_id"],
        }
        source = client.post("/api/v1/current/sources", headers=headers, json={
            "provider": "google-drive", "name": "Drive",
            "boundary": "approved-root", "credentials": {"access_token": "synthetic-only"},
        })
        assert source.status_code == 201, source.text
        source_id = source.json()["id"]
        failed = client.post(
            f"/api/v1/current/sources/{source_id}/sync-directory",
            headers=headers,
        )
        assert failed.status_code == 424, failed.text
        with SessionLocal() as db:
            assert db.scalar(select(GuardSubject).where(
                GuardSubject.provider_subject_id == "MUST_NOT_COMMIT",
            )) is None
            connection = db.get(SourceConnection, source_id)
            assert connection.status == "degraded"
            assert connection.last_error == "GOOGLE_DRIVE_PERMISSION_ID_UNRESOLVED"
            cursor = db.scalar(select(ProviderSyncCursor).where(
                ProviderSyncCursor.source_id == source_id,
                ProviderSyncCursor.sync_kind == "directory",
            ))
            assert cursor is not None
            assert cursor.status == "degraded"
            assert cursor.last_error_code == "GOOGLE_DRIVE_PERMISSION_ID_UNRESOLVED"
            assert cursor.last_error_at is not None
