import json

import pytest
from sqlalchemy import select

from apps.api.accessproof_api import acl_sync
from apps.api.accessproof_api.acl_sync import synchronize_acls
from apps.api.accessproof_api.guard_pipeline import process_guard_event
from apps.api.accessproof_api.db import (
    Base,
    GuardPermissionEvent,
    GuardSubject,
    Organization,
    Project,
    SourceConnection,
    SessionLocal,
    engine,
    GuardPermissionGrant,
    GuardGroup,
    GuardGroupMembership,
)


class FakeDrive:
    pages = [
        {"changes": [{"fileId": "file-1", "file": {"id": "file-1", "name": "Policy"}}], "newStartPageToken": "rev-1"},
        {"changes": [{"fileId": "file-1", "file": {"id": "file-1", "name": "Policy"}}], "newStartPageToken": "rev-2"},
    ]

    def __init__(self, **_kwargs):
        self._client = self
        self.page_index = 0

    async def acl_change_page(self, token=None):
        if token is None:
            return {"startPageToken": "start"}
        return self.pages[min(self.page_index, len(self.pages) - 1)]

    async def permissions_snapshot(self, file_id):
        if file_id == "root":
            return []
        return ([{"id": "perm-1", "type": "user", "emailAddress": "alice@example.com", "role": "reader"}]
                if self.page_index == 0 else [])

    async def aclose(self):
        return None


@pytest.mark.asyncio
async def test_acl_sync_queues_idempotent_upsert_then_revoke(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", FakeDrive)
    with SessionLocal() as db:
        org = Organization(name="ACL org")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="ACL project")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id, provider="google-drive", name="Drive", boundary="root")
        db.add(source)
        db.add(GuardSubject(organization_id=org.id, provider="google-drive", provider_subject_id="alice", primary_email="alice@example.com", display_name="Alice"))
        db.flush()
        result = await synchronize_acls(db, source, {"access_token": "token", "test_root_folder_id": "root"})
        assert result == {"pages": 0, "changes": 1, "events": 0}
        db.commit()
        fake = FakeDrive()
        monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", lambda **kwargs: fake)
        result = await synchronize_acls(db, source, {"access_token": "token", "test_root_folder_id": "root"})
        assert result["events"] == 1
        db.commit()
        events = list(db.scalars(select(GuardPermissionEvent)))
        assert len(events) == 1
        assert json.loads(events[0].mutation_json)["grant_key"] == "google-drive:perm-1"
        process_guard_event(db, events[0].id)
        db.commit()
        assert len(list(db.scalars(select(GuardPermissionGrant)))) == 1
        fake.page_index = 1
        result = await synchronize_acls(db, source, {"access_token": "token", "test_root_folder_id": "root"})
        assert result["events"] == 1
        db.commit()
        events = list(db.scalars(select(GuardPermissionEvent).order_by(GuardPermissionEvent.received_at)))
        assert len(events) == 2
        assert {event.change_type for event in events} == {"grant_upsert", "grant_revoke"}


@pytest.mark.asyncio
async def test_group_acl_maps_to_existing_group_and_membership(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    class GroupDrive(FakeDrive):
        async def permissions_snapshot(self, file_id):
            if file_id == "root":
                return []
            return [{"id": "group-perm", "type": "group", "emailAddress": "finance@example.com", "role": "reader"}]

    monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", GroupDrive)
    with SessionLocal() as db:
        org = Organization(name="Group ACL org")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="Group project")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id, provider="google-drive", name="Drive", boundary="root")
        subject = GuardSubject(organization_id=org.id, provider="google-drive", provider_subject_id="alice", primary_email="alice@example.com")
        group = GuardGroup(organization_id=org.id, provider="google-drive", provider_group_id="group-1", provider_email="finance@example.com")
        db.add_all([source, subject, group])
        db.flush()
        db.add(GuardGroupMembership(organization_id=org.id, group_id=group.id, subject_id=subject.id, active=True))
        db.flush()
        await synchronize_acls(db, source, {"access_token": "token", "test_root_folder_id": "root"})
        db.commit()
        fake = GroupDrive()
        monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", lambda **kwargs: fake)
        result = await synchronize_acls(db, source, {"access_token": "token", "test_root_folder_id": "root"})
        assert result["events"] == 1
        db.flush()
        event = db.scalar(select(GuardPermissionEvent).where(GuardPermissionEvent.change_type == "grant_upsert"))
        process_guard_event(db, event.id)
        grant = db.scalar(select(GuardPermissionGrant))
        assert grant is not None and grant.principal_type == "group" and grant.principal_id == group.id
