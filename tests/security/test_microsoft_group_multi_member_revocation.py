"""A removed SharePoint group grant must revoke every affected employee."""
import pytest
from sqlalchemy import select

from apps.api.accessproof_api import acl_sync
from apps.api.accessproof_api.db import (
    Base, SessionLocal, engine, Organization, Project, SourceConnection, GuardResource,
    GuardSubject, GuardGroup, GuardGroupMembership, GuardPermissionGrant,
    GuardPermissionEvent, ProviderSyncCursor,
)


class RemovedGraph:
    def __init__(self, **kwargs):
        self._client = self

    async def aclose(self):
        return None

    async def acl_delta_page(self, url):
        return {
            "value": [{"id": "doc", "@removed": {"reason": "deleted"}}],
            "@odata.deltaLink": (
                "https://graph.microsoft.com/v1.0/drives/drive/root/delta?$deltatoken=done"
            ),
        }


@pytest.mark.asyncio
async def test_microsoft_group_deleted_document_queues_revoke_for_each_member(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(acl_sync, "Microsoft365Adapter", RemovedGraph)
    with SessionLocal() as db:
        org = Organization(name="Group document revoke")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="Project")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id,
                                  provider="microsoft365", boundary="root", name="SharePoint")
        db.add(source)
        db.flush()
        resource = GuardResource(organization_id=org.id, source_id=source.id,
                                 provider_resource_id="doc", resource_type="document")
        group = GuardGroup(organization_id=org.id, provider="microsoft365",
                           provider_group_id="entra-group", status="active")
        a = GuardSubject(organization_id=org.id, provider="microsoft365",
                         provider_subject_id="a", status="active")
        b = GuardSubject(organization_id=org.id, provider="microsoft365",
                         provider_subject_id="b", status="active")
        db.add_all([resource, group, a, b])
        db.flush()
        db.add_all([
            GuardGroupMembership(organization_id=org.id, group_id=group.id,
                                 subject_id=user.id, active=True)
            for user in (a, b)
        ])
        db.add(GuardPermissionGrant(
            organization_id=org.id, source_id=source.id, resource_id=resource.id,
            grant_key="microsoft365:doc:group-grant", principal_type="group",
            principal_id=group.id, scope="read", effect="allow", active=True,
            provider_revision=1,
        ))
        db.add(ProviderSyncCursor(
            organization_id=org.id, source_id=source.id, provider="microsoft365",
            sync_kind="acl", status="connected",
            cursor="https://graph.microsoft.com/v1.0/drives/drive/root/delta?$deltatoken=start",
            last_provider_revision="1",
        ))
        db.flush()
        result = await acl_sync.synchronize_acls(db, source, {
            "access_token": "synthetic", "drive_id": "drive", "test_root_item_id": "root",
        }, max_pages=1)
        db.flush()
        assert result["events"] == 2
        revokes = list(db.scalars(select(GuardPermissionEvent).where(
            GuardPermissionEvent.change_type == "grant_revoke"
        )))
        assert {row.subject_id for row in revokes} == {a.id, b.id}
        assert len({row.dedupe_key for row in revokes}) == 2
