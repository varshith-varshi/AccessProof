"""Production Directory subject IDs must be bridged to Drive permission IDs."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from apps.api.accessproof_api import acl_sync, directory_sync
from apps.api.accessproof_api.config import Settings
from apps.api.accessproof_api.db import (
    Base, GuardGroup, GuardGroupMembership, GuardSubject, Organization, Project,
    ProviderSyncCursor, SessionLocal, SourceConnection, engine,
)
from connectors.directory import DirectoryGroup, DirectorySyncError, DirectoryUser


class GoogleDirectory:
    lookup_calls: list[str] = []
    return_bad = False

    def __init__(self, _: str) -> None:
        pass

    async def users(self):
        return [DirectoryUser("workspace-alice", "Alice", "alice@example.test", "active"),
                DirectoryUser("workspace-bob", "Bob", "bob@example.test", "suspended")]

    async def groups(self):
        return [DirectoryGroup("workspace-finance", "Finance", "finance@example.test")]

    async def members(self, _group):
        return ["workspace-alice"]

    async def drive_permission_id(self, email):
        self.lookup_calls.append(email)
        if self.return_bad:
            raise DirectorySyncError("GOOGLE_DRIVE_PERMISSION_ID_UNRESOLVED")
        return {
            "alice@example.test": "drive-alice",
            "finance@example.test": "drive-finance",
        }[email]

    async def close(self):
        return None


def setup(monkeypatch):
    monkeypatch.setattr(directory_sync, "settings", Settings(env="production"))
    monkeypatch.setattr(acl_sync, "settings", Settings(env="production"))
    monkeypatch.setattr(directory_sync, "GoogleWorkspaceDirectoryAdapter", GoogleDirectory)
    GoogleDirectory.lookup_calls.clear()
    GoogleDirectory.return_bad = False
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    db = SessionLocal()
    org = Organization(name="permission-ids")
    db.add(org)
    db.flush()
    project = Project(organization_id=org.id, name="p")
    db.add(project)
    db.flush()
    source = SourceConnection(organization_id=org.id, project_id=project.id, provider="google-drive", name="Drive", boundary="root")
    db.add(source)
    db.flush()
    return db, source, org


@pytest.mark.asyncio
async def test_verified_drive_id_bridge_and_cached_resolution(monkeypatch):
    db, source, org = setup(monkeypatch)
    try:
        # ACL arrived before directory: it remains inactive and untrusted.
        provisional = acl_sync._group_for_principal(
            db, source, "google-drive", "drive-finance", "finance@example.test",
        )
        assert provisional.status == "unknown"
        assert provisional.drive_permission_id == "drive-finance"
        assert provisional.provider_group_id.startswith("drive-unresolved:")
        assert acl_sync._subjects_for_principal(
            db, source, "google-drive", "group", "drive-finance", "finance@example.test",
        ) == []

        result = await directory_sync.synchronize_directory(db, source, {"access_token": "synthetic"})
        db.commit()
        assert result == {"users": 2, "groups": 1, "memberships": 1}
        alice = db.scalar(select(GuardSubject).where(GuardSubject.provider_subject_id == "workspace-alice"))
        bob = db.scalar(select(GuardSubject).where(GuardSubject.provider_subject_id == "workspace-bob"))
        finance = db.scalar(select(GuardGroup).where(GuardGroup.provider_group_id == "workspace-finance"))
        assert finance.id == provisional.id
        assert finance.drive_permission_id == "drive-finance"
        assert alice.drive_permission_id == "drive-alice"
        assert bob.drive_permission_id is None
        assert alice.id != bob.id
        assert acl_sync._subjects_for_principal(
            db, source, "google-drive", "subject", "drive-alice", "alice@example.test",
        ) == [(alice.id, None)]
        assert acl_sync._subjects_for_principal(
            db, source, "google-drive", "subject", "workspace-alice", "alice@example.test",
        ) == []
        assert acl_sync._subjects_for_principal(
            db, source, "google-drive", "subject", "drive-bob", "bob@example.test",
        ) == []
        assert acl_sync._subjects_for_principal(
            db, source, "google-drive", "group", "drive-finance", "finance@example.test",
        ) == [(alice.id, finance.id)]
        acl_cursor = db.scalar(select(ProviderSyncCursor).where(
            ProviderSyncCursor.source_id == source.id, ProviderSyncCursor.sync_kind == "acl",
        ))
        assert acl_cursor.status == "queued" and acl_cursor.last_success_at is None
        assert len(GoogleDirectory.lookup_calls) == 2

        result = await directory_sync.synchronize_directory(db, source, {"access_token": "synthetic"})
        db.commit()
        assert result["users"] == 2
        assert len(GoogleDirectory.lookup_calls) == 2
        memberships = list(db.scalars(select(GuardGroupMembership).where(
            GuardGroupMembership.organization_id == org.id,
        )))
        assert len(memberships) == 1 and memberships[0].active
    finally:
        db.close()


@pytest.mark.asyncio
async def test_provider_id_failure_aborts_without_committing_allow(monkeypatch):
    db, source, org = setup(monkeypatch)
    try:
        GoogleDirectory.return_bad = True
        with pytest.raises(DirectorySyncError, match="GOOGLE_DRIVE_PERMISSION_ID_UNRESOLVED"):
            await directory_sync.synchronize_directory(db, source, {"access_token": "synthetic"})
        db.rollback()
        assert db.scalar(select(GuardSubject).where(GuardSubject.organization_id == org.id)) is None
        assert db.scalar(select(ProviderSyncCursor).where(
            ProviderSyncCursor.source_id == source.id,
        )) is None
    finally:
        GoogleDirectory.return_bad = False
        db.close()


@pytest.mark.asyncio
async def test_legacy_email_grants_are_revoked_during_verified_id_migration(monkeypatch):
    """An ALLOW from pre-bridge email matching must not survive identity remap."""
    from apps.api.accessproof_api.db import (
        GuardEffectiveAccess, GuardPermissionEvent, GuardPermissionGrant, GuardResource,
    )
    from apps.api.accessproof_api.guard_pipeline import process_guard_event
    db, source, org = setup(monkeypatch)
    try:
        former = GuardSubject(
            organization_id=org.id, provider="google-drive",
            provider_subject_id="former-user", primary_email="alice@example.test",
            status="active",
        )
        doc = GuardResource(
            organization_id=org.id, source_id=source.id, provider_resource_id="secret-file",
        )
        db.add_all([former, doc])
        db.flush()
        grant = GuardPermissionGrant(
            organization_id=org.id, source_id=source.id, resource_id=doc.id,
            grant_key="legacy-drive-grant", principal_type="subject",
            principal_id=former.id, active=True, provider_revision=12,
        )
        db.add(grant)
        db.add(GuardEffectiveAccess(
            organization_id=org.id, source_id=source.id, subject_id=former.id,
            resource_id=doc.id, decision="allow", state_version=1, source_revision=12,
        ))
        db.commit()

        await directory_sync.synchronize_directory(db, source, {"access_token": "synthetic"})
        db.commit()
        assert grant.active is False
        assert grant.provider_revision == 0
        assert former.status == "removed"
        acl_cursor = db.scalar(select(ProviderSyncCursor).where(
            ProviderSyncCursor.source_id == source.id,
            ProviderSyncCursor.sync_kind == "acl",
        ))
        assert acl_cursor.status == "queued"
        assert acl_cursor.last_success_at is None
        events = list(db.scalars(select(GuardPermissionEvent).where(
            GuardPermissionEvent.source_id == source.id,
            GuardPermissionEvent.processing_status == "queued",
        )))
        assert events, "A previous ALLOW requires an explicit policy transition"
        for event in events:
            process_guard_event(db, event.id)
        db.expire_all()
        access = db.scalar(select(GuardEffectiveAccess).where(
            GuardEffectiveAccess.subject_id == former.id,
            GuardEffectiveAccess.source_id == source.id,
        ))
        assert access.decision == "deny"
    finally:
        db.close()
