"""D-24: a 410 resyncRequired delta (expired or preference-incompatible token)
must resynchronize the whole approved subtree and REVOKE vanished grants,
not leave the ACL cursor degraded forever."""
import pytest
from sqlalchemy import select

from apps.api.accessproof_api import acl_sync
from apps.api.accessproof_api.acl_sync import synchronize_acls
from apps.api.accessproof_api.db import (
    Base, SessionLocal, engine, Organization, Project, SourceConnection,
    GuardSubject, GuardPermissionEvent, GuardPermissionGrant, ProviderSyncCursor,
)
from apps.api.accessproof_api.guard_pipeline import process_guard_event
from connectors.microsoft365.adapter import DeltaResyncRequired

ALICE = "entra-alice"


class FakeGraph:
    def __init__(self):
        self._client = self
        self.alice_can_read = True
        self.gone = set()
        self.resync_next = False
        self.calls = []

    async def aclose(self):
        return None

    async def acl_latest_delta_link(self):
        self.calls.append("checkpoint")
        return f"https://graph.microsoft.com/v1.0/drives/d1/root/delta?$deltatoken=t{len(self.calls)}"

    async def list_boundary_resources(self, root_id=None):
        self.calls.append("inventory")
        return [{"id": d, "name": d, "file": {}, "parentReference": {"id": "root", "driveId": "d1"}}
                for d in ("doc1", "doc2") if d not in self.gone]

    async def permissions_snapshot(self, item_id):
        if item_id in {"doc1", "doc2"} and self.alice_can_read and item_id not in self.gone:
            return [{"id": f"p-{item_id}", "roles": ["read"], "grantedToV2": {"user": {"id": ALICE}}}]
        return []

    async def acl_delta_page(self, url):
        self.calls.append("delta")
        if self.resync_next:
            self.resync_next = False
            raise DeltaResyncRequired("MICROSOFT_DELTA_RESYNC_REQUIRED")
        return {"value": [], "@odata.deltaLink": url}

    async def resync_delta_page(self):
        from connectors.microsoft365.adapter import Microsoft365Adapter
        return await Microsoft365Adapter.resync_delta_page(self)  # the real implementation

    @property
    def test_root_item_id(self):
        return "root"

    async def is_inside_boundary(self, item_id):
        return item_id in {"doc1", "doc2", "root"}


def _process(db):
    for event in db.scalars(select(GuardPermissionEvent).where(GuardPermissionEvent.processing_status != "resolved")):
        process_guard_event(db, event.id)
    db.commit()


def _active(db):
    return {g.grant_key for g in db.scalars(select(GuardPermissionGrant).where(GuardPermissionGrant.active.is_(True)))}


@pytest.mark.asyncio
async def test_resync_revokes_vanished_and_restores_fresh_cursor(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    fake = FakeGraph()
    monkeypatch.setattr(acl_sync, "Microsoft365Adapter", lambda **kwargs: fake)
    creds = {"access_token": "synthetic", "drive_id": "d1", "test_root_item_id": "root"}
    with SessionLocal() as db:
        org = Organization(name="Resync")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="p")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id, provider="sharepoint",
                                  boundary="root", name="SP")
        db.add(source)
        db.add(GuardSubject(organization_id=org.id, provider="microsoft365", provider_subject_id=ALICE, status="active"))
        db.flush()
        await synchronize_acls(db, source, creds)          # initial inventory
        db.commit()
        _process(db)
        assert len(_active(db)) == 2
        # Permission removed on doc1, doc2 deleted, and Graph now demands a resync.
        fake.alice_can_read = False
        fake.gone = {"doc2"}
        fake.resync_next = True
        await synchronize_acls(db, source, creds)
        db.commit()
        _process(db)
        assert _active(db) == set()                        # both grants revoked by the resync
        cursor = db.scalar(select(ProviderSyncCursor).where(ProviderSyncCursor.sync_kind == "acl"))
        assert cursor.status == "connected" and cursor.last_error_code is None
        assert "deltatoken" in cursor.cursor               # fresh checkpoint captured
        assert fake.calls.index("checkpoint", 2) < fake.calls.index("inventory", 2)  # checkpoint before re-read
        # The next ordinary delta works from the new cursor.
        await synchronize_acls(db, source, creds)
        db.commit()
        assert db.scalar(select(ProviderSyncCursor).where(ProviderSyncCursor.sync_kind == "acl")).status == "connected"
