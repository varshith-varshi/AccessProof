"""D-31: no-op ACL/directory syncs must NOT change the values that feed the
signed authorization revision (they caused false Layer 2 denials every few
minutes in production); real changes still must."""
from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select

from apps.api.accessproof_api import acl_sync, directory_sync
from apps.api.accessproof_api.acl_sync import synchronize_acls
from apps.api.accessproof_api.db import (
    Base, GuardSubject, Organization, Project, ProviderSyncCursor, SessionLocal, SourceConnection, engine,
)
from connectors.directory import DirectoryGroup, DirectoryUser
from tests.security.test_microsoft_delta_resync_d24 import ALICE, FakeGraph, _active, _process

TENANT = "6479e7ca-b256-4ebc-a408-871b9046547c"


def _source(db):
    org = Organization(name="D31")
    db.add(org)
    db.flush()
    project = Project(organization_id=org.id, name="p")
    db.add(project)
    db.flush()
    src = SourceConnection(organization_id=org.id, project_id=project.id, provider="sharepoint", boundary="root", name="SP")
    db.add(src)
    db.flush()
    return org, src


def _rev(db, kind):
    return db.scalar(select(ProviderSyncCursor.last_provider_revision).where(ProviderSyncCursor.sync_kind == kind))


@pytest.mark.asyncio
async def test_noop_acl_syncs_keep_revision_and_real_revoke_advances_it(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    fake = FakeGraph()
    monkeypatch.setattr(acl_sync, "Microsoft365Adapter", lambda **kw: fake)
    creds = {"access_token": "synthetic", "drive_id": "d1", "test_root_item_id": "root"}
    with SessionLocal() as db:
        org, src = _source(db)
        db.add(GuardSubject(organization_id=org.id, provider="microsoft365", provider_subject_id=ALICE, status="active"))
        db.flush()
        await synchronize_acls(db, src, creds)
        db.commit()
        _process(db)
        assert len(_active(db)) == 2
        base = _rev(db, "acl")
        for _ in range(3):                       # empty delta pages
            await synchronize_acls(db, src, creds)
            db.commit()
        assert _rev(db, "acl") == base
        fake.alice_can_read = False              # a real permission change arrives as a delta
        fake_page = [{"id": "doc1", "file": {}, "name": "doc1"}]
        orig = fake.acl_delta_page

        async def page_with_change(url):
            return {"value": fake_page, "@odata.deltaLink": url}
        fake.acl_delta_page = page_with_change
        await synchronize_acls(db, src, creds)
        db.commit()
        assert _rev(db, "acl") != base
        fake.acl_delta_page = orig


class FakeEntra:
    data = ([], [], {})

    def __init__(self, token):
        pass

    async def users(self):
        return self.data[0]

    async def groups(self):
        return self.data[1]

    async def members(self, group):
        return self.data[2].get(group, [])

    async def close(self):
        pass


def test_unchanged_directory_keeps_revision_and_membership_change_moves_it(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(directory_sync, "MicrosoftEntraDirectoryAdapter", FakeEntra)
    users = [DirectoryUser("u-alice", "alice", "alice@x.test", "active"), DirectoryUser("u-bob", "bob", "bob@x.test", "active")]
    groups = [DirectoryGroup("g1", "Finance", "fin@x.test")]
    creds = {"access_token": "synthetic", "tenant_id": TENANT}

    def sync(member_ids):
        FakeEntra.data = (users, groups, {"g1": member_ids})
        with SessionLocal() as db:
            src = db.scalar(select(SourceConnection))
            asyncio.run(directory_sync.synchronize_directory(db, src, creds))
            db.commit()
            return _rev(db, "directory")
    with SessionLocal() as db:
        _source(db)
        db.commit()
    first = sync(["u-alice"])
    assert first.startswith("fp:")
    assert sync(["u-alice"]) == first and sync(["u-alice"]) == first      # no content change
    assert sync([]) != first                                              # alice removed from group
