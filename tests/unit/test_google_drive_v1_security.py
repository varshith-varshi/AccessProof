"""Security regression tests for Google Drive V1 permission ingestion."""
import json

import httpx
import pytest
from sqlalchemy import select

from connectors.google_drive.adapter import GoogleDriveAdapter
from apps.api.accessproof_api import acl_sync
from apps.api.accessproof_api.acl_sync import synchronize_acls
from apps.api.accessproof_api.db import (
    Base, SessionLocal, engine, Organization, Project, SourceConnection,
    GuardSubject, GuardResource, GuardPermissionEvent, GuardPermissionGrant,
)
from apps.api.accessproof_api.guard_pipeline import process_guard_event


@pytest.mark.asyncio
async def test_drive_permission_list_reads_all_pages_and_rejects_loops():
    seen = []

    def response(request):
        assert request.url.path == "/drive/v3/files/file-1/permissions"
        token = request.url.params.get("pageToken")
        seen.append(token)
        if not token:
            return httpx.Response(200, json={"permissions": [{"id": "a"}], "nextPageToken": "next"})
        return httpx.Response(200, json={"permissions": [{"id": "b"}]})

    adapter = GoogleDriveAdapter(access_token="fake", test_root_folder_id="root")
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(response))
    try:
        result = await adapter.permissions_snapshot("file-1")
        assert [row["id"] for row in result] == ["a", "b"]
        assert seen == [None, "next"]
    finally:
        await adapter._client.aclose()

    adapter = GoogleDriveAdapter(access_token="fake", test_root_folder_id="root")
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json={"permissions": [], "nextPageToken": "loop"})
    ))
    try:
        with pytest.raises(ValueError, match="PAGINATION"):
            await adapter.permissions_snapshot("file-1")
    finally:
        await adapter._client.aclose()


@pytest.mark.asyncio
async def test_drive_discovers_nested_existing_documents_and_pages():
    def response(request):
        query = request.url.params["q"]
        token = request.url.params.get("pageToken")
        if "'root' in parents" in query:
            if not token:
                return httpx.Response(200, json={"files": [
                    {"id": "folder", "mimeType": "application/vnd.google-apps.folder", "parents": ["root"]},
                ], "nextPageToken": "p2"})
            return httpx.Response(200, json={"files": [{"id": "file-A", "parents": ["root"]}]})
        if "'folder' in parents" in query:
            return httpx.Response(200, json={"files": [{"id": "file-B", "parents": ["folder"]}]})
        raise AssertionError(f"unexpected parent: {query}")

    adapter = GoogleDriveAdapter(access_token="fake", test_root_folder_id="root")
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(response))
    try:
        result = await adapter.list_boundary_resources()
        assert {r["id"] for r in result} == {"folder", "file-A", "file-B"}
    finally:
        await adapter._client.aclose()


@pytest.mark.asyncio
async def test_drive_inventory_excludes_shortcuts_that_can_target_outside_boundary():
    def response(request):
        assert "'root' in parents" in request.url.params["q"]
        return httpx.Response(200, json={"files": [
            {"id": "shortcut", "mimeType": GoogleDriveAdapter.SHORTCUT_MIME, "parents": ["root"],
             "shortcutDetails": {"targetId": "outside"}},
            {"id": "safe", "mimeType": "text/plain", "parents": ["root"]},
        ]})

    adapter = GoogleDriveAdapter(access_token="fake", test_root_folder_id="root")
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(response))
    try:
        assert [item["id"] for item in await adapter.list_boundary_resources()] == ["safe"]
    finally:
        await adapter._client.aclose()


@pytest.mark.asyncio
async def test_drive_boundary_ancestry_ignores_unrelated_files():
    def response(request):
        file_id = request.url.path.rsplit("/", 1)[-1]
        parents = {"inside": ["child"], "child": ["root"], "outside": ["other"], "other": []}
        return httpx.Response(200, json={"id": file_id, "parents": parents[file_id]})

    adapter = GoogleDriveAdapter(access_token="fake", test_root_folder_id="root")
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(response))
    try:
        assert await adapter.is_inside_boundary("inside")
        assert not await adapter.is_inside_boundary("outside")
    finally:
        await adapter._client.aclose()


def _db_rows():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    db = SessionLocal()
    org = Organization(name="Drive V1 security test")
    db.add(org)
    db.flush()
    project = Project(organization_id=org.id, name="test")
    db.add(project)
    db.flush()
    source = SourceConnection(
        organization_id=org.id, project_id=project.id, name="Drive",
        provider="google-drive", boundary="root",
    )
    db.add(source)
    db.add(GuardSubject(organization_id=org.id, provider="google-drive",
                        provider_subject_id="alice", primary_email="alice@example.com"))
    db.flush()
    return db, source


class InventoriedDrive:
    def __init__(self, **kwargs):
        self._client = self

    async def acl_change_page(self, page_token=None):
        if page_token is None:
            return {"startPageToken": "before-scan"}
        return {"changes": [], "newStartPageToken": "after-scan"}

    async def list_boundary_resources(self):
        return [
            {"id": "file-A", "name": "A", "parents": ["root"]},
            {"id": "file-B", "name": "B", "parents": ["root"]},
        ]

    async def permissions_snapshot(self, file_id):
        if file_id == "root":
            return []
        return [{"id": "shared-permission-id", "type": "user",
                 "emailAddress": "alice@example.com", "role": "reader"}]

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_bootstrap_discovers_all_files_and_does_not_merge_permissions(monkeypatch):
    monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", InventoriedDrive)
    db, source = _db_rows()
    try:
        result = await synchronize_acls(db, source, {"access_token": "fake", "test_root_folder_id": "root"})
        assert result["changes"] == 3
        assert result["events"] == 2
        db.commit()
        resource_ids = {row.provider_resource_id for row in db.scalars(select(GuardResource))}
        assert resource_ids == {"root", "file-A", "file-B"}
        events = list(db.scalars(select(GuardPermissionEvent)))
        assert len(events) == 2
        assert {json.loads(e.mutation_json)["grant_key"] for e in events} == {
            acl_sync._grant_key("google-drive", "file-A", {"id": "shared-permission-id", "type": "user", "emailAddress": "alice@example.com", "role": "reader"}),
            acl_sync._grant_key("google-drive", "file-B", {"id": "shared-permission-id", "type": "user", "emailAddress": "alice@example.com", "role": "reader"}),
        }
        for event in events:
            process_guard_event(db, event.id)
        db.commit()
        grants = list(db.scalars(select(GuardPermissionGrant)))
        assert len(grants) == 2
        assert len({g.resource_id for g in grants}) == 2
    finally:
        db.close()


@pytest.mark.asyncio
async def test_domain_and_anyone_grants_do_not_allow_all_tenant_employees(monkeypatch):
    class BroadDrive(InventoriedDrive):
        async def permissions_snapshot(self, file_id):
            if file_id == "root":
                return []
            return [
                {"id": "domain-123", "type": "domain", "domain": "otherdomain.com", "role": "reader"},
                {"id": "public-123", "type": "anyone", "role": "reader"},
            ]
    monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", BroadDrive)
    db, source = _db_rows()
    try:
        result = await synchronize_acls(db, source, {"access_token": "fake", "test_root_folder_id": "root"})
        assert result["events"] == 0
        assert list(db.scalars(select(GuardPermissionEvent))) == []
    finally:
        db.close()


@pytest.mark.asyncio
async def test_expired_deleted_and_non_reader_permissions_never_create_allow_events(monkeypatch):
    class InvalidGrantDrive(InventoriedDrive):
        async def permissions_snapshot(self, file_id):
            if file_id == "root":
                return []
            return [
                {"id": "expired", "type": "user", "emailAddress": "alice@example.com", "role": "reader", "expirationTime": "2000-01-01T00:00:00Z"},
                {"id": "deleted", "type": "user", "emailAddress": "alice@example.com", "role": "reader", "deleted": True},
                {"id": "none", "type": "user", "emailAddress": "alice@example.com", "role": "none"},
                {"id": "malformed", "type": "user", "emailAddress": "alice@example.com", "role": "reader", "expirationTime": "not-a-date"},
            ]

    monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", InvalidGrantDrive)
    db, source = _db_rows()
    try:
        result = await synchronize_acls(db, source, {"access_token": "fake", "test_root_folder_id": "root"})
        assert result["events"] == 0
        assert list(db.scalars(select(GuardPermissionEvent))) == []
    finally:
        db.close()


@pytest.mark.asyncio
async def test_capped_drive_change_sweep_marks_source_catching_up_not_healthy(monkeypatch):
    class BackloggedDrive(InventoriedDrive):
        async def acl_change_page(self, page_token=None):
            if page_token is None:
                return {"startPageToken": "bootstrap"}
            return {"changes": [], "nextPageToken": f"next-{page_token}"}

    fake = BackloggedDrive()
    monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", lambda **_: fake)
    db, source = _db_rows()
    try:
        await synchronize_acls(db, source, {"access_token": "fake", "test_root_folder_id": "root"})
        db.commit()
        with pytest.raises(acl_sync.ACLSyncError, match="ACL_SYNC_BACKLOG"):
            await synchronize_acls(db, source, {"access_token": "fake", "test_root_folder_id": "root"}, max_pages=1)
        cursor = db.scalar(select(acl_sync.ProviderSyncCursor).where(
            acl_sync.ProviderSyncCursor.source_id == source.id,
        ))
        assert cursor is not None
        assert cursor.status == "catching_up"
        assert cursor.last_error_code == "ACL_SYNC_BACKLOG"
    finally:
        db.close()


@pytest.mark.asyncio
async def test_partial_inventory_failure_never_sets_cursor_ready(monkeypatch):
    class FailingDrive(InventoriedDrive):
        async def list_boundary_resources(self):
            raise ValueError("incomplete search")
    monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", FailingDrive)
    db, source = _db_rows()
    try:
        with pytest.raises(acl_sync.ACLSyncError):
            await synchronize_acls(db, source, {"access_token": "fake", "test_root_folder_id": "root"})
        assert not list(db.scalars(select(GuardResource)))
    finally:
        db.close()



@pytest.mark.asyncio
async def test_folder_acl_change_rechecks_known_descendant_permissions(monkeypatch):
    class FolderDrive(InventoriedDrive):
        revised = False

        async def list_boundary_resources(self, **kwargs):
            return [
                {"id": "folder", "mimeType": "application/vnd.google-apps.folder", "parents": ["root"]},
                {"id": "file-child", "parents": ["folder"], "name": "Finance"},
            ]

        async def acl_change_page(self, page_token=None):
            if page_token is None:
                return {"startPageToken": "cursor-before"}
            return {"changes": [{
                "fileId": "folder", "file": {
                    "id": "folder", "mimeType": "application/vnd.google-apps.folder", "parents": ["root"]
                },
            }], "newStartPageToken": "cursor-after"}

        async def permissions_snapshot(self, file_id):
            if file_id == "root" or self.revised:
                return []
            return [{
                "id": "alice-grant", "type": "user",
                "emailAddress": "alice@example.com", "role": "reader",
            }]

        async def is_inside_boundary(self, file_id):
            return True

    fake = FolderDrive()
    monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", lambda **kw: fake)
    db, source = _db_rows()
    try:
        initial = await synchronize_acls(db, source, {"access_token": "fake", "test_root_folder_id": "root"})
        assert initial["events"] == 2
        db.commit()
        for event in list(db.scalars(select(GuardPermissionEvent))):
            process_guard_event(db, event.id)
        fake.revised = True
        updated = await synchronize_acls(db, source, {"access_token": "fake", "test_root_folder_id": "root"})
        db.commit()
        assert updated["changes"] == 2  # folder delta expands to child.
        revoked = list(db.scalars(select(GuardPermissionEvent).where(
            GuardPermissionEvent.change_type == "grant_revoke"
        )))
        assert len(revoked) == 2
        for event in revoked:
            process_guard_event(db, event.id)
        db.commit()
        assert all(not grant.active for grant in db.scalars(select(GuardPermissionGrant)))
    finally:
        db.close()


@pytest.mark.asyncio
async def test_shared_drive_change_rechecks_known_file_permissions(monkeypatch):
    class SharedDrive:
        phase = "seed"

        def __init__(self, **kwargs):
            self._client = self

        async def acl_change_page(self, page_token=None):
            return ({"startPageToken": "initial"} if page_token is None else {
                "changes": [{"changeType": "drive", "driveId": "shared-drive"}],
                "newStartPageToken": "advanced"})

        async def list_boundary_resources(self):
            return [{"id": "file-a", "parents": ["root"], "driveId": "shared-drive"}]

        async def is_inside_boundary(self, file_id):
            return file_id in {"root", "file-a"}

        async def permissions_snapshot(self, file_id):
            if file_id == "file-a" and self.phase == "seed":
                return [{"id": "p1", "type": "user", "emailAddress": "alice@example.com", "role": "reader"}]
            return []

        async def aclose(self):
            pass

    monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", SharedDrive)
    db, source = _db_rows()
    try:
        creds = {"access_token": "synthetic", "test_root_folder_id": "root"}
        assert (await synchronize_acls(db, source, creds))["events"] == 1
        db.commit()
        for event in list(db.scalars(select(GuardPermissionEvent))):
            process_guard_event(db, event.id)
        db.commit()
        assert db.scalar(select(GuardPermissionGrant).where(GuardPermissionGrant.active.is_(True))), (
            [(e.change_type, e.processing_status, e.error_code) for e in db.scalars(select(GuardPermissionEvent))],
            [(g.active, g.effect) for g in db.scalars(select(GuardPermissionGrant))],
        )
        SharedDrive.phase = "revoked"
        assert (await synchronize_acls(db, source, creds))["events"] >= 1
        db.commit()
        pending = list(db.scalars(select(GuardPermissionEvent).where(
            GuardPermissionEvent.processing_status == "queued")))
        assert any(row.change_type == "grant_revoke" for row in pending)
        for event in pending:
            process_guard_event(db, event.id)
        db.commit()
        assert db.scalar(select(GuardPermissionGrant).where(GuardPermissionGrant.active.is_(True))) is None
    finally:
        db.close()


@pytest.mark.asyncio
async def test_drive_permission_snapshot_requests_view_and_limited_access_fields():
    def response(request):
        fields = request.url.params["fields"]
        assert "view" in fields
        assert "inheritedPermissionsDisabled" in fields
        assert "permissionDetails" in fields
        return httpx.Response(200, json={"kind": "drive#permissionList", "permissions": [
            {"id": "p", "type": "user", "role": "reader", "view": "metadata",
             "inheritedPermissionsDisabled": True,
             "permissionDetails": [{"inherited": True}]},
        ]})

    adapter = GoogleDriveAdapter(access_token="fake", test_root_folder_id="root")
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(response))
    try:
        permissions = await adapter.permissions_snapshot("limited-folder")
        assert permissions[0]["view"] == "metadata"
    finally:
        await adapter._client.aclose()


@pytest.mark.parametrize(("facets", "expected"), [
    ({}, True),
    ({"view": "metadata", "inheritedPermissionsDisabled": True,
      "permissionDetails": [{"inherited": True}]}, False),
    ({"view": "published"}, False),
    ({"view": "unrecognized"}, False),
    ({"inheritedPermissionsDisabled": True,
      "permissionDetails": [{"inherited": True}, {"inherited": True}]}, False),
    ({"inheritedPermissionsDisabled": True,
      "permissionDetails": [{"inherited": True}, {"inherited": False}]}, True),
    # Direct My Drive permissions may not include permissionDetails.
    ({"inheritedPermissionsDisabled": True}, True),
    ({"inheritedPermissionsDisabled": "true"}, False),
    ({"inheritedPermissionsDisabled": True, "permissionDetails": [{"role": "reader"}]}, False),
])
def test_drive_content_read_denies_metadata_only_but_keeps_direct_grants(facets, expected):
    permission = {"id": "p", "type": "user", "role": "reader", **facets}
    assert acl_sync._google_permission_authorizes_read(permission, acl_sync._now()) is expected


def test_drive_limited_folder_organizer_exception_is_not_a_metadata_view():
    permission = {
        "id": "p", "type": "user", "role": "organizer",
        "inheritedPermissionsDisabled": True,
        "permissionDetails": [{"inherited": True}],
    }
    assert acl_sync._google_permission_authorizes_read(permission, acl_sync._now())
    permission["view"] = "metadata"
    assert not acl_sync._google_permission_authorizes_read(permission, acl_sync._now())


@pytest.mark.asyncio
async def test_drive_metadata_only_transition_revokes_old_allow_and_direct_regrant_restores_it(monkeypatch):
    class LimitedFolderDrive(InventoriedDrive):
        phase = "direct"

        async def list_boundary_resources(self):
            return [
                {"id": "folder-A", "mimeType": GoogleDriveAdapter.FOLDER_MIME, "parents": ["root"]},
                {"id": "file-B", "mimeType": "text/plain", "parents": ["root"]},
            ]

        async def acl_change_page(self, page_token=None):
            if page_token is None:
                return {"startPageToken": "before-scan"}
            return {"changes": [{"fileId": "folder-A", "file": {
                "id": "folder-A", "mimeType": GoogleDriveAdapter.FOLDER_MIME,
                "parents": ["root"],
            }}], "newStartPageToken": "after-scan"}

        async def is_inside_boundary(self, file_id):
            return True

        async def permissions_snapshot(self, file_id):
            if file_id == "root":
                return []
            permission = {
                "id": "grant-A" if file_id == "folder-A" else "grant-B",
                "type": "user", "emailAddress": "alice@example.com", "role": "reader",
            }
            if file_id == "folder-A" and self.phase == "metadata":
                permission.update({
                    "view": "metadata", "inheritedPermissionsDisabled": True,
                    "permissionDetails": [{"inherited": True}],
                })
            elif file_id == "folder-A" and self.phase == "direct-again":
                permission.update({
                    "inheritedPermissionsDisabled": True,
                    "permissionDetails": [{"inherited": True}, {"inherited": False}],
                })
            return [permission]

    fake = LimitedFolderDrive()
    monkeypatch.setattr(acl_sync, "GoogleDriveAdapter", lambda **_: fake)
    db, source = _db_rows()
    try:
        credentials = {"access_token": "fake", "test_root_folder_id": "root"}
        assert (await synchronize_acls(db, source, credentials))["events"] == 2
        db.commit()
        for event in list(db.scalars(select(GuardPermissionEvent))):
            process_guard_event(db, event.id)
        db.commit()

        folder = db.scalar(select(GuardResource).where(
            GuardResource.provider_resource_id == "folder-A"))
        other = db.scalar(select(GuardResource).where(
            GuardResource.provider_resource_id == "file-B"))

        def active(resource):
            return list(db.scalars(select(GuardPermissionGrant).where(
                GuardPermissionGrant.resource_id == resource.id,
                GuardPermissionGrant.active.is_(True),
            )))

        assert len(active(folder)) == len(active(other)) == 1
        fake.phase = "metadata"
        assert (await synchronize_acls(db, source, credentials))["events"] == 1
        db.commit()
        for event in list(db.scalars(select(GuardPermissionEvent).where(
            GuardPermissionEvent.processing_status == "queued",
        ))):
            process_guard_event(db, event.id)
        db.commit()
        assert not active(folder)
        assert len(active(other)) == 1

        fake.phase = "direct-again"
        assert (await synchronize_acls(db, source, credentials))["events"] == 1
        db.commit()
        for event in list(db.scalars(select(GuardPermissionEvent).where(
            GuardPermissionEvent.processing_status == "queued",
        ))):
            process_guard_event(db, event.id)
        db.commit()
        assert len(active(folder)) == len(active(other)) == 1
    finally:
        db.close()
