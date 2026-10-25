"""Drive-root initial inventory and tombstone revocation using fake Graph traffic."""
import pytest
from sqlalchemy import select

from apps.api.accessproof_api import acl_sync
from apps.api.accessproof_api.acl_sync import synchronize_acls, ACLSyncError
from apps.api.accessproof_api.db import (
    Base, SessionLocal, engine, Organization, Project, SourceConnection,
    GuardSubject, GuardPermissionEvent, GuardPermissionGrant,
)
from apps.api.accessproof_api.guard_pipeline import process_guard_event


class FakeGraph:
    def __init__(self, **kwargs):
        self._client = self
        self.events = [
            {"value": [{"id": "doc1", "@removed": {"reason": "deleted"}}],
             "@odata.deltaLink": "https://graph.microsoft.com/v1.0/drives/d1/root/delta?$deltatoken=t2"},
        ]
        self.calls = []
    async def aclose(self):
        return None
    async def acl_latest_delta_link(self):
        self.calls.append("initial-checkpoint")
        return "https://graph.microsoft.com/v1.0/drives/d1/root/delta?$deltatoken=t1"
    async def list_boundary_resources(self):
        self.calls.append("inventory")
        return [{"id": "doc1", "name": "policy", "parentReference": {"id": "root", "driveId": "d1"}}]
    async def permissions_snapshot(self, item_id):
        self.calls.append(("permissions", item_id))
        if item_id == "doc1":
            return [{"id": "perm1", "roles": ["read"], "grantedToV2": {"user": {"id": "entra-1"}}}]
        return []
    async def acl_delta_page(self, url):
        self.calls.append(("delta", url))
        return self.events.pop(0)
    async def is_inside_boundary(self, item_id):
        return item_id in {"doc1", "root"}


@pytest.mark.asyncio
async def test_microsoft_inventory_delta_tombstone_revoke_and_one_page_limit(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    fake = FakeGraph()
    monkeypatch.setattr(acl_sync, "Microsoft365Adapter", lambda **kwargs: fake)
    with SessionLocal() as db:
        org = Organization(name="M365 Lifecycle")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="Project")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id,
            provider="microsoft365", boundary="root", name="Microsoft")
        db.add(source)
        db.add(GuardSubject(
            organization_id=org.id, provider="microsoft365",
            provider_subject_id="entra-1", status="active"))
        db.flush()
        creds = {"access_token": "synthetic", "drive_id": "d1", "test_root_item_id": "root"}
        result = await synchronize_acls(db, source, creds, max_pages=1)
        assert result["changes"] == 2
        assert result["events"] == 1
        db.commit()
        assert fake.calls.index("initial-checkpoint") < fake.calls.index("inventory")
        event = db.scalar(select(GuardPermissionEvent))
        assert event is not None
        process_guard_event(db, event.id)
        db.commit()
        grant = db.scalar(select(GuardPermissionGrant))
        assert grant is not None and grant.active
        result = await synchronize_acls(db, source, creds, max_pages=1)
        assert result["events"] == 1
        db.commit()
        events = list(db.scalars(select(GuardPermissionEvent)))
        assert any(row.change_type == "grant_revoke" for row in events)
        assert fake.events == []
        assert fake.calls.count(("permissions", "doc1")) == 1


@pytest.mark.asyncio
async def test_microsoft_initial_inventory_failure_never_persists_partial_permission_graph(monkeypatch):
    """A partial Graph permissions read must leave ZERO new grants/events/resources."""
    from apps.api.accessproof_api.db import GuardResource, ProviderSyncCursor

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    class PartialFailureGraph(FakeGraph):
        async def list_boundary_resources(self):
            return [
                {"id": "doc1", "name": "Allowed", "parentReference": {"id": "root", "driveId": "d1"}},
                {"id": "doc2", "name": "Broken", "parentReference": {"id": "root", "driveId": "d1"}},
            ]
        async def permissions_snapshot(self, item_id):
            if item_id == "doc2":
                raise RuntimeError("Synthetic Graph permission page missing")
            return await super().permissions_snapshot(item_id)

    monkeypatch.setattr(acl_sync, "Microsoft365Adapter", lambda **kwargs: PartialFailureGraph())
    with SessionLocal() as db:
        org = Organization(name="Partial initial Microsoft inventory")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="Project")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id,
            provider="microsoft365", boundary="root", name="Microsoft")
        db.add(source)
        db.add(GuardSubject(
            organization_id=org.id, provider="microsoft365",
            provider_subject_id="entra-1", status="active"))
        db.flush()
        credentials = {"access_token": "synthetic", "drive_id": "d1", "test_root_item_id": "root"}
        with pytest.raises(ACLSyncError):
            await synchronize_acls(db, source, credentials)
        db.commit()  # Mimics a worker persisting the source's degraded status.
        assert list(db.scalars(select(GuardResource))) == []
        assert list(db.scalars(select(GuardPermissionEvent))) == []
        assert list(db.scalars(select(GuardPermissionGrant))) == []
        cursor = db.scalar(select(ProviderSyncCursor))
        assert cursor is not None and cursor.status == "degraded"


@pytest.mark.asyncio
async def test_microsoft_delta_discovers_descendants_when_folder_moves_into_root(monkeypatch):
    from apps.api.accessproof_api.db import GuardResource

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    class IncomingFolderGraph(FakeGraph):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.events = [{
                "value": [{"id": "incoming-folder", "folder": {},
                           "parentReference": {"id": "root", "driveId": "d1"}}],
                "@odata.deltaLink": "https://graph.microsoft.com/v1.0/drives/d1/root/delta?$deltatoken=t2",
            }]
        async def list_boundary_resources(self, *, root_id=None):
            if root_id == "incoming-folder":
                return [{"id": "nested-doc", "name": "Nested Policy",
                         "parentReference": {"id": "incoming-folder", "driveId": "d1"}}]
            return []
        async def is_inside_boundary(self, item_id):
            return item_id in {"root", "incoming-folder", "nested-doc"}
        async def permissions_snapshot(self, item_id):
            if item_id == "nested-doc":
                return [{"id": "p-nested", "roles": ["read"],
                         "grantedToV2": {"user": {"id": "entra-1"}}}]
            return []

    fake = IncomingFolderGraph()
    monkeypatch.setattr(acl_sync, "Microsoft365Adapter", lambda **kwargs: fake)
    with SessionLocal() as db:
        org = Organization(name="Graph moved-in folder")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="Project")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id, name="Graph",
            provider="microsoft365", boundary="root")
        db.add(source)
        db.add(GuardSubject(
            organization_id=org.id, provider="microsoft365",
            provider_subject_id="entra-1", status="active"))
        db.flush()
        creds = {"access_token": "synthetic", "drive_id": "d1", "test_root_item_id": "root"}
        await synchronize_acls(db, source, creds)
        db.commit()
        delta = await synchronize_acls(db, source, creds, max_pages=1)
        assert delta["events"] == 1
        assert delta["changes"] == 2
        db.commit()
        resources = list(db.scalars(select(GuardResource).where(GuardResource.source_id == source.id)))
        assert {r.provider_resource_id for r in resources} == {"root", "incoming-folder", "nested-doc"}
        nested = next(r for r in resources if r.provider_resource_id == "nested-doc")
        assert nested.parent_resource_id == next(r.id for r in resources if r.provider_resource_id == "incoming-folder")
