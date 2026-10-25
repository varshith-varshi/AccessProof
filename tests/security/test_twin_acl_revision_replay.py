"""Fake enterprise Drive: reconcile-before-revoke, group grants and event revisions.

The deterministic local provider never reaches a cloud service; it drives
production ACL/directory/event modules with provider-shaped replies.
"""
from __future__ import annotations


import pytest
from sqlalchemy import select

from apps.api.accessproof_api import acl_sync
from apps.api.accessproof_api.db import (
    Base, engine, SessionLocal, Organization, Project, SourceConnection, GuardSubject,
    GuardPermissionEvent, GuardPermissionGrant, GuardEffectiveAccess, ProviderSyncCursor,
)
from apps.api.accessproof_api.guard_pipeline import process_guard_event


class VirtualDrive:
    def __init__(self, **kwargs):
        self._client = self
        self.files = {
            "root": [],
            "protected-doc": [
                {"id": "drive-perm-alice", "type": "user", "emailAddress": "alice@example.test", "role": "reader"}
            ],
        }
        self.change_token = 0
        self.initialized = False

    async def aclose(self):
        pass

    async def acl_change_page(self, token=None):
        if token is None:
            return {"startPageToken": "t0", "changes": []}
        self.change_token += 1
        return {
            "changes": [{"fileId": "protected-doc", "file": {"id": "protected-doc", "name": "Confidential"}}],
            "newStartPageToken": f"t{self.change_token}",
        }

    async def list_boundary_resources(self, *args, **kwargs):
        return [{"id": "protected-doc", "name": "Confidential", "parents": ["root"]}]

    async def is_inside_boundary(self, file_id):
        return file_id in self.files

    async def permissions_snapshot(self, file_id):
        return list(self.files[file_id])


async def drain(db):
    # The real worker uses the same resolver on each queued event.
    for event in list(db.scalars(select(GuardPermissionEvent).where(
        GuardPermissionEvent.processing_status == "queued"
    ).order_by(GuardPermissionEvent.received_at.asc()))):
        process_guard_event(db, event.id)


def setup():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    db = SessionLocal()
    org = Organization(name="Test enterprise")
    db.add(org)
    db.flush()
    project = Project(organization_id=org.id, name="RAG")
    db.add(project)
    db.flush()
    src = SourceConnection(
        organization_id=org.id, project_id=project.id,
        provider="google-drive", name="Drive", boundary="root",
    )
    user = GuardSubject(
        organization_id=org.id, provider="google-drive",
        provider_subject_id="alice", primary_email="alice@example.test", status="active",
    )
    db.add_all([src, user])
    db.commit()
    return db, src, user


def effective(db, src, user):
    row = db.scalar(select(GuardEffectiveAccess).where(
        GuardEffectiveAccess.source_id == src.id,
        GuardEffectiveAccess.subject_id == user.id,
    ))
    return row.decision if row else "missing"


@pytest.mark.asyncio
async def test_fake_customer_reconcile_followed_by_drive_revoke_must_deny(monkeypatch):
    drive = VirtualDrive()
    monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", lambda **_: drive)
    db, src, alice = setup()
    credentials = {"access_token": "fake", "test_root_folder_id": "root"}
    try:
        await acl_sync.synchronize_acls(db, src, credentials)
        db.commit()
        await drain(db)
        assert effective(db, src, alice) == "allow"

        # No Drive change events, but reconciliation touches the grant.
        for _ in range(2):
            await acl_sync.reconcile_known_acls(db, src, credentials)
            db.commit()
            await drain(db)
        grant = db.scalar(select(GuardPermissionGrant).where(
            GuardPermissionGrant.grant_key == acl_sync._grant_key("google-drive", "protected-doc", {"id": "drive-perm-alice", "type": "user", "emailAddress": "alice@example.test", "role": "reader"})
        ))
        assert grant.active

        # The customer now revokes employee's access; incremental Drive feed
        # delivers an event with an independent sequence number.
        drive.files["protected-doc"] = []
        await acl_sync.synchronize_acls(db, src, credentials)
        db.commit()
        await drain(db)
        assert grant.active is False
        assert effective(db, src, alice) == "deny", (
            "Access must not survive real Drive revocation after periodic reconcile"
        )
    finally:
        db.close()


@pytest.mark.asyncio
async def test_fake_customer_reconciliation_discovers_grant_then_drive_revokes_it(monkeypatch):
    drive = VirtualDrive()
    drive.files["protected-doc"] = []
    monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", lambda **_: drive)
    db, src, alice = setup()
    credentials = {"access_token": "fake", "test_root_folder_id": "root"}
    try:
        await acl_sync.synchronize_acls(db, src, credentials)
        db.commit()
        await drain(db)

        # Permission first appears during periodic missed-change reconciliation.
        drive.files["protected-doc"] = [
            {"id": "drive-perm-alice", "type": "user",
             "emailAddress": "alice@example.test", "role": "reader"}
        ]
        queued = await acl_sync.reconcile_known_acls(db, src, credentials)
        db.commit()
        await drain(db)
        assert queued["events"] >= 1
        assert effective(db, src, alice) == "allow"

        # Later a Drive change notification must override the reconciled grant.
        drive.files["protected-doc"] = []
        await acl_sync.synchronize_acls(db, src, credentials)
        db.commit()
        await drain(db)
        grant = db.scalar(select(GuardPermissionGrant).where(
            GuardPermissionGrant.grant_key == acl_sync._grant_key("google-drive", "protected-doc", {"id": "drive-perm-alice", "type": "user", "emailAddress": "alice@example.test", "role": "reader"})
        ))
        assert grant.active is False
        assert effective(db, src, alice) == "deny"
    finally:
        db.close()


@pytest.mark.asyncio
async def test_fake_customer_80_random_acl_transitions_preserve_authoritative_decision(monkeypatch):
    import random
    randomizer = random.Random(20261021)
    drive = VirtualDrive()
    monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", lambda **_: drive)
    db, src, alice = setup()
    credentials = {"access_token": "fake", "test_root_folder_id": "root"}
    try:
        await acl_sync.synchronize_acls(db, src, credentials)
        db.commit()
        await drain(db)
        expected = True
        assert effective(db, src, alice) == "allow"
        for i in range(80):
            # Every state flip is a provider-side customer permission mutation.
            expected = not expected
            drive.files["protected-doc"] = (
                [{"id": "drive-perm-alice", "type": "user", "emailAddress": "alice@example.test", "role": "reader"}]
                if expected else []
            )
            # A delta may be missed, then discovered by hourly reconciliation.
            if randomizer.randrange(3) == 0:
                await acl_sync.reconcile_known_acls(db, src, credentials)
            else:
                await acl_sync.synchronize_acls(db, src, credentials)
            db.commit()
            await drain(db)
            actual = effective(db, src, alice)
            assert actual == ("allow" if expected else "deny"), (
                f"iteration {i}: expected {expected=}, actual={actual}"
            )
            # Reconciliation and Drive deltas use the same persisted revision
            # domain.  If the cursor lags an emitted event, the next
            # reconciliation can reuse that revision; revoke-wins-on-ties
            # would then (correctly) discard a genuine re-grant as stale.
            cursor = db.scalar(select(ProviderSyncCursor).where(
                ProviderSyncCursor.organization_id == src.organization_id,
                ProviderSyncCursor.source_id == src.id,
                ProviderSyncCursor.sync_kind == "acl",
            ))
            assert cursor is not None
            latest_event_revision = db.scalar(select(GuardPermissionEvent.provider_revision).where(
                GuardPermissionEvent.organization_id == src.organization_id,
                GuardPermissionEvent.source_id == src.id,
            ).order_by(GuardPermissionEvent.received_at.desc()).limit(1))
            assert latest_event_revision is not None
            assert int(cursor.last_provider_revision or "0") == latest_event_revision
    finally:
        db.close()
