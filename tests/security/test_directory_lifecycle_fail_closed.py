"""Regression: directory account lifecycle and ACL events must not preserve stale allows."""
from __future__ import annotations

import json
from sqlalchemy import select
import pytest

from apps.api.accessproof_api.db import (
    Base, engine, SessionLocal, Organization, Project, SourceConnection,
    GuardSubject, GuardResource, GuardPermissionEvent,
    GuardEffectiveAccess, GuardPolicy,
)
from apps.api.accessproof_api.directory_sync import synchronize_directory
from apps.api.accessproof_api.guard_pipeline import process_guard_event
from connectors.directory import DirectoryGroup, DirectoryUser


class DirectorySnapshot:
    users_data: list[DirectoryUser] = []
    groups_data: list[DirectoryGroup] = []
    members_data: dict[str, list[str]] = {}

    def __init__(self, token: str) -> None:
        assert token == "synthetic-token"

    async def users(self):
        return list(self.users_data)

    async def groups(self):
        return list(self.groups_data)

    async def members(self, group):
        return list(self.members_data.get(group, []))

    async def close(self):
        pass


def setup_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    db = SessionLocal()
    org = Organization(name="Synthetic tenant")
    db.add(org)
    db.flush()
    project = Project(organization_id=org.id, name="Synthetic RAG")
    db.add(project)
    db.flush()
    source = SourceConnection(
        organization_id=org.id, project_id=project.id, provider="google-drive",
        name="Synthetic Drive", boundary="root",
    )
    db.add(source)
    db.flush()
    resource = GuardResource(
        organization_id=org.id, source_id=source.id, provider_resource_id="file1"
    )
    db.add(resource)
    db.commit()
    return db, org, source, resource


def queue_event(db, org, source, resource, subject, kind, rev, **mutation):
    event = GuardPermissionEvent(
        organization_id=org.id, source_id=source.id, provider="google-drive",
        provider_revision=rev, subject_id=subject.id, resource_id=resource.id,
        change_type=kind, dedupe_key=f"{kind}:{rev}:{subject.id}:{resource.id}",
        processing_status="queued",
        mutation_json=json.dumps({"snapshot_complete": True, "scope": "read", **mutation}),
    )
    db.add(event)
    db.commit()
    process_guard_event(db, event.id)


def decision(db, org, source, resource, subject):
    row = db.scalar(select(GuardEffectiveAccess).where(
        GuardEffectiveAccess.organization_id == org.id,
        GuardEffectiveAccess.source_id == source.id,
        GuardEffectiveAccess.resource_id == resource.id,
        GuardEffectiveAccess.subject_id == subject.id,
    ))
    assert row is not None
    return row.decision


async def sync(db, source):
    await synchronize_directory(db, source, {"access_token": "synthetic-token"})
    db.commit()
    changes = list(db.scalars(select(GuardPermissionEvent).where(
        GuardPermissionEvent.change_type == "subject_status_refresh",
        GuardPermissionEvent.processing_status == "queued",
    )))
    for event in changes:
        process_guard_event(db, event.id)


@pytest.mark.asyncio
async def test_suspended_employee_is_denied_despite_existing_direct_document_grant(monkeypatch):
    monkeypatch.setattr("apps.api.accessproof_api.directory_sync.GoogleWorkspaceDirectoryAdapter", DirectorySnapshot)
    db, org, source, resource = setup_db()
    try:
        DirectorySnapshot.users_data = [DirectoryUser("alice", "Alice", "alice@example.test", "active")]
        DirectorySnapshot.groups_data = []
        DirectorySnapshot.members_data = {}
        await sync(db, source)
        subject = db.scalar(select(GuardSubject).where(GuardSubject.provider_subject_id == "alice"))
        queue_event(db, org, source, resource, subject, "grant_upsert", 1,
                    grant_key="google-drive:file1:perm", principal_type="subject", principal_id="alice")
        assert decision(db, org, source, resource, subject) == "allow"

        DirectorySnapshot.users_data = [DirectoryUser("alice", "Alice", "alice@example.test", "suspended")]
        await sync(db, source)
        assert decision(db, org, source, resource, subject) == "deny"
        assert db.scalar(select(GuardPolicy).order_by(GuardPolicy.version.desc())).decision == "deny"

        DirectorySnapshot.users_data = [DirectoryUser("alice", "Alice", "alice@example.test", "active")]
        await sync(db, source)
        assert decision(db, org, source, resource, subject) == "allow"
    finally:
        db.close()


@pytest.mark.asyncio
async def test_removed_employee_not_left_authorized_by_previous_snapshot(monkeypatch):
    monkeypatch.setattr("apps.api.accessproof_api.directory_sync.GoogleWorkspaceDirectoryAdapter", DirectorySnapshot)
    db, org, source, resource = setup_db()
    try:
        DirectorySnapshot.users_data = [DirectoryUser("alice", "Alice", "alice@example.test", "active")]
        DirectorySnapshot.groups_data = []
        DirectorySnapshot.members_data = {}
        await sync(db, source)
        subject = db.scalar(select(GuardSubject).where(GuardSubject.provider_subject_id == "alice"))
        queue_event(db, org, source, resource, subject, "grant_upsert", 1,
                    grant_key="google-drive:file1:perm", principal_type="subject", principal_id="alice")
        assert decision(db, org, source, resource, subject) == "allow"
        DirectorySnapshot.users_data = []
        await sync(db, source)
        assert subject.status != "active"
        assert decision(db, org, source, resource, subject) == "deny"
    finally:
        db.close()


@pytest.mark.asyncio
async def test_acl_revoke_after_group_membership_events_must_override_stale_allow(monkeypatch):
    monkeypatch.setattr("apps.api.accessproof_api.directory_sync.GoogleWorkspaceDirectoryAdapter", DirectorySnapshot)
    db, org, source, resource = setup_db()
    try:
        DirectorySnapshot.users_data = [DirectoryUser("alice", "Alice", "alice@example.test", "active")]
        DirectorySnapshot.groups_data = [DirectoryGroup("g1", "Team", "team@example.test")]
        DirectorySnapshot.members_data = {"g1": ["alice"]}
        await sync(db, source)
        subject = db.scalar(select(GuardSubject).where(GuardSubject.provider_subject_id == "alice"))
        queue_event(db, org, source, resource, subject, "grant_upsert", 1,
                    grant_key="google-drive:file1:group-perm", principal_type="group",
                    principal_id="g1", group_id="g1")
        assert decision(db, org, source, resource, subject) == "allow"
        DirectorySnapshot.members_data = {"g1": []}
        await sync(db, source)
        for event in list(db.scalars(select(GuardPermissionEvent).where(
            GuardPermissionEvent.change_type == "membership_revoke",
            GuardPermissionEvent.processing_status == "queued"
        ))):
            process_guard_event(db, event.id)
        assert decision(db, org, source, resource, subject) == "deny"
        DirectorySnapshot.members_data = {"g1": ["alice"]}
        await sync(db, source)
        for event in list(db.scalars(select(GuardPermissionEvent).where(
            GuardPermissionEvent.change_type == "membership_upsert",
            GuardPermissionEvent.processing_status == "queued"
        ))):
            process_guard_event(db, event.id)
        assert decision(db, org, source, resource, subject) == "allow"
        queue_event(db, org, source, resource, subject, "grant_revoke", 2,
                    grant_key="google-drive:file1:group-perm")
        assert decision(db, org, source, resource, subject) == "deny"
    finally:
        db.close()


@pytest.mark.asyncio
async def test_deleted_group_retires_memberships_and_denies_existing_group_grant(monkeypatch):
    monkeypatch.setattr("apps.api.accessproof_api.directory_sync.GoogleWorkspaceDirectoryAdapter", DirectorySnapshot)
    db, org, source, resource = setup_db()
    try:
        DirectorySnapshot.users_data = [DirectoryUser("alice", "Alice", "alice@example.test", "active")]
        DirectorySnapshot.groups_data = [DirectoryGroup("g1", "Team", "team@example.test")]
        DirectorySnapshot.members_data = {"g1": ["alice"]}
        await sync(db, source)
        subject = db.scalar(select(GuardSubject).where(GuardSubject.provider_subject_id == "alice"))
        queue_event(db, org, source, resource, subject, "grant_upsert", 1,
                    grant_key="google-drive:file1:group-perm", principal_type="group",
                    principal_id="g1", group_id="g1")
        assert decision(db, org, source, resource, subject) == "allow"
        DirectorySnapshot.groups_data = []
        DirectorySnapshot.members_data = {}
        await sync(db, source)
        for event in list(db.scalars(select(GuardPermissionEvent).where(
            GuardPermissionEvent.change_type == "membership_revoke",
            GuardPermissionEvent.processing_status == "queued"
        ))):
            process_guard_event(db, event.id)
        assert decision(db, org, source, resource, subject) == "deny"
    finally:
        db.close()


@pytest.mark.asyncio
async def test_drive_revoke_while_employee_suspended_reconciles_stored_grant(monkeypatch):
    from apps.api.accessproof_api.acl_sync import _subjects_for_principal
    from apps.api.accessproof_api.db import GuardPermissionGrant

    monkeypatch.setattr("apps.api.accessproof_api.directory_sync.GoogleWorkspaceDirectoryAdapter", DirectorySnapshot)
    db, org, source, resource = setup_db()
    try:
        DirectorySnapshot.users_data = [DirectoryUser("alice", "Alice", "alice@example.test", "active")]
        DirectorySnapshot.groups_data = []
        DirectorySnapshot.members_data = {}
        await sync(db, source)
        subject = db.scalar(select(GuardSubject).where(GuardSubject.provider_subject_id == "alice"))
        queue_event(db, org, source, resource, subject, "grant_upsert", 1,
                    grant_key="google-drive:file1:perm", principal_type="subject", principal_id="alice")
        assert decision(db, org, source, resource, subject) == "allow"
        DirectorySnapshot.users_data = [DirectoryUser("alice", "Alice", "alice@example.test", "suspended")]
        await sync(db, source)
        assert decision(db, org, source, resource, subject) == "deny"
        # Permission reconciliation still has to find suspended account's
        # prior grant so it can revoke it.
        assert _subjects_for_principal(db, source, "google-drive", "subject", "alice", "alice@example.test") == [(subject.id, None)]
        queue_event(db, org, source, resource, subject, "grant_revoke", 2,
                    grant_key="google-drive:file1:perm")
        grant = db.scalar(select(GuardPermissionGrant).where(
            GuardPermissionGrant.grant_key == "google-drive:file1:perm"
        ))
        assert not grant.active
        DirectorySnapshot.users_data = [DirectoryUser("alice", "Alice", "alice@example.test", "active")]
        await sync(db, source)
        assert decision(db, org, source, resource, subject) == "deny"
    finally:
        db.close()


@pytest.mark.asyncio
async def test_new_connected_source_directory_sync_is_due_even_when_validated_recently(monkeypatch):
    from datetime import datetime, timezone
    from apps.worker.accessproof_worker import main as worker

    db, _, source, _ = setup_db()
    try:
        source.encrypted_credentials = "synthetic-placeholder"
        source.last_validated_at = datetime.now(timezone.utc)
        source.status = "connected"
        db.commit()
        calls = []

        async def fake_refresh(_db, _source, credentials):
            return credentials

        async def fake_sync(_db, _source, _credentials):
            calls.append(_source.id)
            return {"users": 1, "groups": 0, "memberships": 0}

        monkeypatch.setattr(worker.box, "decrypt", lambda _: '{"access_token":"synthetic"}')
        monkeypatch.setattr(worker, "refresh_source_credentials_if_needed", fake_refresh)
        monkeypatch.setattr(worker, "synchronize_directory", fake_sync)
        assert await worker.synchronize_due_directories() == 1
        assert calls == [source.id]
    finally:
        db.close()


def test_protect_readiness_requires_fresh_directory_not_just_drive_acl():
    from datetime import datetime, timedelta, timezone
    from apps.api.accessproof_api.app import _application_checks
    from apps.api.accessproof_api.db import AIApplication, ProviderSyncCursor

    db, org, source, _ = setup_db()
    try:
        source.status = "connected"
        # Readiness also requires a decryptable, approved-root-bound Google
        # credential; an arbitrary placeholder must never activate Protect.
        from apps.api.accessproof_api import app as api_module
        import json
        source.encrypted_credentials = api_module._secret_box.encrypt(json.dumps({
            "access_token": "synthetic-provider-token",
            "test_root_folder_id": source.boundary,
        }))
        source.last_validated_at = datetime.now(timezone.utc)
        application = AIApplication(
            organization_id=org.id, application_id="demo-rag",
            name="Demo RAG", source_id=source.id, adapter_type="generic-python"
        )
        db.add(application)
        db.add(ProviderSyncCursor(
            organization_id=org.id, source_id=source.id,
            provider="google-drive", sync_kind="acl",
            status="connected", last_success_at=datetime.now(timezone.utc)
        ))
        db.commit()

        def checks():
            return {row["code"]: row["ok"] for row in _application_checks(db, application, org.id)}

        assert checks()["PERMISSION_SOURCE_SYNCED"] is True
        assert checks()["PERMISSION_DIRECTORY_SYNCED"] is False
        assert checks()["PERMISSION_SOURCE_USABLE"] is False

        directory = ProviderSyncCursor(
            organization_id=org.id, source_id=source.id,
            provider="google-drive", sync_kind="directory",
            status="connected",
            last_success_at=datetime.now(timezone.utc) - timedelta(hours=3),
        )
        db.add(directory)
        db.commit()
        assert checks()["PERMISSION_SOURCE_USABLE"] is False
        directory.last_success_at = datetime.now(timezone.utc)
        db.commit()
        assert checks()["PERMISSION_SOURCE_USABLE"] is True
    finally:
        db.close()
