"""Server-owned bootstrap persists after OAuth browser return, retries safely."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from apps.api.accessproof_api.db import (
    Base, Organization, Project, ProviderSyncCursor, SessionLocal, SourceConnection, engine,
)
from apps.worker.accessproof_worker import main as worker


def _source_with_queued_jobs():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="durable-oauth-bootstrap")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="p")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id, provider="google-drive",
            name="workspace", boundary="approved-root", status="connected",
            encrypted_credentials=worker.box.encrypt(json.dumps({
                "access_token": "synthetic-oauth-token",
                "test_root_folder_id": "approved-root",
            })),
        )
        db.add(source)
        db.flush()
        for kind in ("directory", "acl"):
            db.add(ProviderSyncCursor(
                organization_id=org.id, source_id=source.id, provider="google-drive",
                sync_kind=kind, status="queued", last_success_at=None,
            ))
        source_id = source.id
        db.commit()
    return source_id


@pytest.mark.asyncio
async def test_background_worker_executes_both_durable_bootstraps(monkeypatch):
    source_id = _source_with_queued_jobs()
    seen = []

    async def fake_refresh(db, source, credentials):
        return credentials

    async def fake_directory(db, source, credentials):
        assert credentials["test_root_folder_id"] == "approved-root"
        seen.append(("directory", source.id))
        cursor = db.scalar(select(ProviderSyncCursor).where(
            ProviderSyncCursor.source_id == source.id, ProviderSyncCursor.sync_kind == "directory",
        ))
        cursor.status, cursor.last_success_at = "connected", datetime.now(timezone.utc)
        return {"users": 2, "groups": 1, "memberships": 1}

    async def fake_acl(db, source, credentials, **kwargs):
        seen.append(("acl", source.id))
        cursor = db.scalar(select(ProviderSyncCursor).where(
            ProviderSyncCursor.source_id == source.id, ProviderSyncCursor.sync_kind == "acl",
        ))
        cursor.status, cursor.last_success_at = "connected", datetime.now(timezone.utc)
        return {"pages": 0, "changes": 2, "events": 1}

    monkeypatch.setattr(worker, "refresh_source_credentials_if_needed", fake_refresh)
    monkeypatch.setattr(worker, "synchronize_directory", fake_directory)
    monkeypatch.setattr(worker, "synchronize_acls", fake_acl)

    assert await worker.synchronize_due_directories() == 1
    assert await worker.synchronize_due_acls() == 1
    assert set(seen) == {("directory", source_id), ("acl", source_id)}
    with SessionLocal() as db:
        cursors = list(db.scalars(select(ProviderSyncCursor).where(
            ProviderSyncCursor.source_id == source_id,
        )))
        assert {c.sync_kind: c.status for c in cursors} == {
            "acl": "connected", "directory": "connected",
        }


@pytest.mark.asyncio
async def test_directory_failure_rolls_back_partial_graph_and_backs_off(monkeypatch):
    from apps.api.accessproof_api.db import GuardSubject
    source_id = _source_with_queued_jobs()
    attempts = []
    async def fake_refresh(db, source, credentials):
        return credentials
    async def fail_after_partial_write(db, source, credentials):
        db.add(GuardSubject(
            organization_id=source.organization_id, provider="google-drive",
            provider_subject_id="must-never-commit", status="active",
        ))
        db.flush()
        attempts.append(source.id)
        raise RuntimeError("synthetic provider failure")

    monkeypatch.setattr(worker, "refresh_source_credentials_if_needed", fake_refresh)
    monkeypatch.setattr(worker, "synchronize_directory", fail_after_partial_write)
    assert await worker.synchronize_due_directories() == 0
    assert await worker.synchronize_due_directories() == 0
    assert attempts == [source_id]
    with SessionLocal() as db:
        assert db.scalar(select(GuardSubject).where(
            GuardSubject.provider_subject_id == "must-never-commit",
        )) is None
        source = db.get(SourceConnection, source_id)
        assert source.status == "degraded"
        cursor = db.scalar(select(ProviderSyncCursor).where(
            ProviderSyncCursor.source_id == source_id,
            ProviderSyncCursor.sync_kind == "directory",
        ))
        assert cursor.status == "degraded"
        assert cursor.last_success_at is None
        assert cursor.last_error_code == "DIRECTORY_SYNC_INCOMPLETE"
        assert cursor.last_error_at is not None


@pytest.mark.asyncio
async def test_degraded_retry_is_allowed_after_backoff(monkeypatch):
    source_id = _source_with_queued_jobs()
    with SessionLocal() as db:
        cursor = db.scalar(select(ProviderSyncCursor).where(
            ProviderSyncCursor.source_id == source_id,
            ProviderSyncCursor.sync_kind == "directory",
        ))
        cursor.status = "degraded"
        from datetime import timedelta
        cursor.last_error_at = datetime.now(timezone.utc) - timedelta(minutes=2)
        db.commit()
    calls = []
    async def fake_refresh(db, source, credentials):
        return credentials
    async def fake_sync(db, source, credentials):
        calls.append(source.id)
        cursor = db.scalar(select(ProviderSyncCursor).where(
            ProviderSyncCursor.source_id == source.id,
            ProviderSyncCursor.sync_kind == "directory",
        ))
        cursor.status, cursor.last_success_at = "connected", datetime.now(timezone.utc)
        cursor.last_error_code = None
        return {"users": 1}
    monkeypatch.setattr(worker, "refresh_source_credentials_if_needed", fake_refresh)
    monkeypatch.setattr(worker, "synchronize_directory", fake_sync)
    assert await worker.synchronize_due_directories() == 1
    assert calls == [source_id]
