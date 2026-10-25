"""Scheduled reconciliation must revoke a document moved outside SharePoint root."""
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from apps.api.accessproof_api import acl_sync
from apps.api.accessproof_api.db import (
    Base, SessionLocal, engine, Organization, Project, SourceConnection, GuardResource,
    GuardSubject, GuardGroup, GuardGroupMembership, GuardPermissionGrant,
    GuardPermissionEvent, ProviderSyncCursor,
)


class MovedOutsideGraph:
    def __init__(self, **kwargs):
        self._client = self
        self.permission_calls = 0

    async def aclose(self):
        return None

    async def is_inside_boundary(self, item_id):
        return item_id == "root"

    async def permissions_snapshot(self, item_id):
        self.permission_calls += 1
        return [{"id": "old-grant", "roles": ["read"], "grantedToV2": {"group": {"id": "group"}}}]


@pytest.mark.asyncio
async def test_reconcile_revokes_every_member_when_sharepoint_file_moved_out(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    fake = MovedOutsideGraph()
    monkeypatch.setattr(acl_sync, "Microsoft365Adapter", lambda **kwargs: fake)
    with SessionLocal() as db:
        org = Organization(name="Moved out source")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="Project")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id, provider="microsoft365", boundary="root", name="SharePoint")
        db.add(source)
        db.flush()
        file = GuardResource(organization_id=org.id, source_id=source.id, provider_resource_id="old-file", resource_type="document")
        group = GuardGroup(organization_id=org.id, provider="microsoft365", provider_group_id="group", status="active")
        alice = GuardSubject(organization_id=org.id, provider="microsoft365", provider_subject_id="a", status="active")
        bob = GuardSubject(organization_id=org.id, provider="microsoft365", provider_subject_id="b", status="active")
        db.add_all([file, group, alice, bob])
        db.flush()
        db.add_all([
            GuardGroupMembership(organization_id=org.id, group_id=group.id, subject_id=user.id, active=True)
            for user in (alice, bob)
        ])
        db.add(GuardPermissionGrant(
            organization_id=org.id, source_id=source.id, resource_id=file.id,
            grant_key="microsoft365:old-file:old-grant", principal_type="group",
            principal_id=group.id, effect="allow", scope="read", active=True,
            provider_revision=1,
        ))
        db.add(ProviderSyncCursor(
            organization_id=org.id, source_id=source.id, provider="microsoft365",
            sync_kind="acl", status="connected", last_provider_revision="1",
            cursor="https://graph.microsoft.com/v1.0/drives/drive/root/delta?$deltatoken=x",
            last_success_at=datetime.now(timezone.utc),
        ))
        db.flush()
        result = await acl_sync.reconcile_known_acls(db, source, {
            "access_token": "synthetic", "drive_id": "drive", "test_root_item_id": "root",
        })
        db.flush()
        assert result["events"] == 2
        events = list(db.scalars(select(GuardPermissionEvent)))
        assert {event.subject_id for event in events} == {alice.id, bob.id}
        assert fake.permission_calls == 0
        assert '"deleted": true' in file.metadata_json
