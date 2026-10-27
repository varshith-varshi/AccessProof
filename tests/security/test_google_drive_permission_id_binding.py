"""Production uses Drive permission IDs, not Workspace directory IDs or emails."""
from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from apps.api.accessproof_api import acl_sync, directory_sync
from apps.api.accessproof_api.config import Settings
from apps.api.accessproof_api.db import (
    Base, GuardGroup, GuardGroupMembership, GuardSubject,
    Organization, Project, SessionLocal, SourceConnection, engine,
)
from connectors.directory import (
    DirectoryGroup, DirectorySyncError, DirectoryUser,
    GoogleWorkspaceDirectoryAdapter,
)


def _setup():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="google-id-test")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="p")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id,
            provider="google-drive", name="Drive", boundary="root",
        )
        db.add(source)
        db.commit()
        return source.id


@pytest.mark.asyncio
async def test_resolved_permission_ids_authorize_but_directory_ids_and_emails_do_not(monkeypatch):
    source_id = _setup()
    production = Settings(env="production")
    monkeypatch.setattr(directory_sync, "settings", production)
    monkeypatch.setattr(acl_sync, "settings", production)

    class FakeDirectory:
        def __init__(self, token):
            assert token == "synthetic-access"
        async def users(self):
            return [DirectoryUser("workspace-user-42", "Alice", "alice@example.test", "active")]
        async def groups(self):
            return [DirectoryGroup("workspace-group-99", "Finance", "finance@example.test")]
        async def members(self, group_id):
            assert group_id == "workspace-group-99"
            return ["workspace-user-42"]
        async def drive_permission_id(self, email):
            return {"alice@example.test": "drive-user-800", "finance@example.test": "drive-group-500"}[email]
        async def close(self):
            pass

    monkeypatch.setattr(directory_sync, "GoogleWorkspaceDirectoryAdapter", FakeDirectory)
    with SessionLocal() as db:
        source = db.get(SourceConnection, source_id)
        # A Drive ACL can precede a full directory sync. Its group remains
        # unknown and non-authorizing until Google independently resolves it.
        provisional = acl_sync._group_for_principal(
            db, source, "google-drive", "drive-group-500", "finance@example.test",
        )
        prior_id = provisional.id
        assert provisional.status == "unknown"
        assert acl_sync._subjects_for_principal(
            db, source, "google-drive", "group", "drive-group-500", "finance@example.test",
        ) == []
        db.commit()

        outcome = await directory_sync.synchronize_directory(
            db, source, {"access_token": "synthetic-access"},
        )
        db.commit()
        assert outcome["users"] == 1 and outcome["groups"] == 1 and outcome["memberships"] == 1

        subject = db.scalar(select(GuardSubject).where(GuardSubject.provider_subject_id == "workspace-user-42"))
        group = db.scalar(select(GuardGroup).where(GuardGroup.provider_group_id == "workspace-group-99"))
        assert group.id == prior_id
        assert group.drive_permission_id == "drive-group-500"
        assert subject.drive_permission_id == "drive-user-800"
        assert db.scalar(select(GuardGroupMembership).where(
            GuardGroupMembership.subject_id == subject.id, GuardGroupMembership.group_id == group.id,
        )).active
        assert acl_sync._subjects_for_principal(
            db, source, "google-drive", "subject", "drive-user-800", None,
        ) == [(subject.id, None)]
        assert acl_sync._subjects_for_principal(
            db, source, "google-drive", "subject", "workspace-user-42", "alice@example.test",
        ) == []
        assert acl_sync._subjects_for_principal(
            db, source, "google-drive", "group", "drive-group-500", "finance@example.test",
        ) == [(subject.id, group.id)]
        assert acl_sync._subjects_for_principal(
            db, source, "google-drive", "group", "workspace-group-99", "finance@example.test",
        ) == []


@pytest.mark.asyncio
async def test_duplicate_drive_permission_ids_abort_directory_snapshot(monkeypatch):
    source_id = _setup()
    monkeypatch.setattr(directory_sync, "settings", Settings(env="production"))

    class DuplicateDirectory:
        def __init__(self, token):
            pass
        async def users(self):
            return [DirectoryUser("u1", "One", "one@example.test", "active"),
                    DirectoryUser("u2", "Two", "two@example.test", "active")]
        async def groups(self):
            return []
        async def members(self, group_id):
            return []
        async def drive_permission_id(self, email):
            return "duplicate-drive-permission-id"
        async def close(self):
            pass

    monkeypatch.setattr(directory_sync, "GoogleWorkspaceDirectoryAdapter", DuplicateDirectory)
    with SessionLocal() as db:
        source = db.get(SourceConnection, source_id)
        with pytest.raises(DirectorySyncError, match="DUPLICATE_GOOGLE_DRIVE_PERMISSION_ID"):
            await directory_sync.synchronize_directory(db, source, {"access_token": "synthetic"})
        db.rollback()
        assert db.scalars(select(GuardSubject)).first() is None


@pytest.mark.asyncio
async def test_provider_permission_id_lookup_handles_errors_and_blocks_redirects():
    response_type = [
        (200, {"kind": "drive#permissionId", "id": "p123"}, "p123"),
        (403, {}, "GOOGLE_DRIVE_PERMISSION_ID_FORBIDDEN"),
        (404, {}, "GOOGLE_DRIVE_PERMISSION_ID_UNRESOLVED"),
        (200, {"kind": "untrusted", "id": "p123"}, "GOOGLE_DRIVE_PERMISSION_ID_INVALID"),
    ]
    for status, payload, expected in response_type:
        def respond(req, code=status, body=payload):
            assert req.url.host == "www.googleapis.com"
            assert req.url.raw_path.decode().startswith("/drive/v2/permissionIds/alice%40example.test")
            return httpx.Response(code, json=body, headers={"location": "https://evil.example/steal"})
        client = httpx.AsyncClient(transport=httpx.MockTransport(respond), follow_redirects=False)
        adapter = GoogleWorkspaceDirectoryAdapter("synthetic-token", client)
        try:
            if status == 200 and payload["kind"] == "drive#permissionId":
                assert await adapter.drive_permission_id("alice@example.test") == expected
            else:
                with pytest.raises(DirectorySyncError, match=expected):
                    await adapter.drive_permission_id("alice@example.test")
        finally:
            await client.aclose()
