"""D-27: after a document is deleted in SharePoint, any later folder-level change
(e.g. a content edit) expanded the folder to its KNOWN descendants and re-read
the deleted one; Graph returned 404 and every ACL sync failed from then on
(production: degraded, Guard fail-closed outage). Deleted descendants are now
skipped and a 404 on an item is processed as a removal."""
import httpx
import pytest
from sqlalchemy import select

from apps.api.accessproof_api import acl_sync
from apps.api.accessproof_api.acl_sync import synchronize_acls
from apps.api.accessproof_api.db import (
    Base, GuardPermissionGrant, GuardResource, GuardSubject, Organization, Project, ProviderSyncCursor,
    SessionLocal, SourceConnection, engine,
)
from tests.security.test_microsoft_delta_resync_d24 import ALICE, FakeGraph, _active, _process


def _not_found(item_id):
    request = httpx.Request("GET", f"https://graph.microsoft.com/v1.0/drives/d1/items/{item_id}")
    return httpx.HTTPStatusError("404", request=request, response=httpx.Response(404, request=request))


class DeletingGraph(FakeGraph):
    def __init__(self):
        super().__init__()
        self.next_page = []

    async def is_inside_boundary(self, item_id):
        if item_id in self.gone:
            raise _not_found(item_id)
        return await super().is_inside_boundary(item_id)

    async def permissions_snapshot(self, item_id):
        if item_id in self.gone:
            raise _not_found(item_id)
        return await super().permissions_snapshot(item_id)

    async def acl_delta_page(self, url):
        page, self.next_page = self.next_page, []
        return {"value": page, "@odata.deltaLink": url}


def _setup(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    fake = DeletingGraph()
    monkeypatch.setattr(acl_sync, "Microsoft365Adapter", lambda **kwargs: fake)
    return fake


@pytest.mark.asyncio
async def test_folder_change_after_silent_deletion_revokes_instead_of_failing(monkeypatch):
    fake = _setup(monkeypatch)
    creds = {"access_token": "synthetic", "drive_id": "d1", "test_root_item_id": "root"}
    with SessionLocal() as db:
        org = Organization(name="D27")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="p")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id, provider="sharepoint", boundary="root", name="SP")
        db.add(source)
        db.add(GuardSubject(organization_id=org.id, provider="microsoft365", provider_subject_id=ALICE, status="active"))
        db.flush()
        await synchronize_acls(db, source, creds)
        db.commit()
        _process(db)
        assert len(_active(db)) == 2
        # doc2 vanishes WITHOUT its own delta record; then the folder changes.
        fake.gone = {"doc2"}
        fake.next_page = [{"id": "root", "folder": {}, "name": "root"}]
        await synchronize_acls(db, source, creds)            # used to raise ACL_SYNC_INCOMPLETE
        db.commit()
        _process(db)
        cursor = db.scalar(select(ProviderSyncCursor).where(ProviderSyncCursor.sync_kind == "acl"))
        assert cursor.status == "connected" and cursor.last_error_code is None
        doc2 = db.scalar(select(GuardResource).where(GuardResource.provider_resource_id == "doc2"))
        assert '"deleted": true' in doc2.metadata_json
        active_resources = {g.resource_id for g in db.scalars(select(GuardPermissionGrant).where(GuardPermissionGrant.active.is_(True)))}
        assert doc2.id not in active_resources                # its grant was revoked
        # And every later folder change keeps succeeding (deleted descendant skipped).
        fake.next_page = [{"id": "root", "folder": {}, "name": "root"}]
        await synchronize_acls(db, source, creds)
        db.commit()
        assert db.scalar(select(ProviderSyncCursor).where(ProviderSyncCursor.sync_kind == "acl")).status == "connected"


@pytest.mark.asyncio
async def test_other_provider_errors_still_fail_closed(monkeypatch):
    fake = _setup(monkeypatch)
    creds = {"access_token": "synthetic", "drive_id": "d1", "test_root_item_id": "root"}

    async def broken(item_id):
        request = httpx.Request("GET", "https://graph.microsoft.com/v1.0/x")
        raise httpx.HTTPStatusError("400", request=request, response=httpx.Response(400, request=request))
    with SessionLocal() as db:
        org = Organization(name="D27b")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="p")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id, provider="sharepoint", boundary="root", name="SP")
        db.add(source)
        db.flush()
        await synchronize_acls(db, source, creds)
        db.commit()
        fake.is_inside_boundary = broken
        fake.next_page = [{"id": "doc1", "file": {}, "name": "doc1"}]
        with pytest.raises(acl_sync.ACLSyncError):
            await synchronize_acls(db, source, creds)
