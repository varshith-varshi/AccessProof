import httpx
import pytest
from sqlalchemy import select

from apps.api.accessproof_api.db import (
    Base,
    Organization,
    Project,
    ProviderSyncCursor,
    SessionLocal,
    SourceConnection,
    engine,
)
from apps.api.accessproof_api.directory_sync import synchronize_directory
from connectors.directory import DirectoryGroup, DirectoryUser
from connectors.directory import DirectorySyncError, GoogleWorkspaceDirectoryAdapter, MicrosoftEntraDirectoryAdapter


@pytest.mark.asyncio
async def test_google_directory_paginates_users_and_expands_nested_groups_with_cycles():
    calls: list[str] = []
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path.endswith("/users") and "pageToken=second" not in str(request.url):
            return httpx.Response(200, json={"users": [{"id": "u1", "primaryEmail": "one@example.com", "name": {"fullName": "One"}}], "nextPageToken": "second"})
        if request.url.path.endswith("/users"):
            return httpx.Response(200, json={"users": [{"id": "u2", "primaryEmail": "two@example.com", "name": {"fullName": "Two"}, "suspended": True}]})
        if request.url.path.endswith("/groups"):
            return httpx.Response(200, json={"groups": [{"id": "g1", "name": "Engineering", "email": "eng@example.com"}]})
        if request.url.path.endswith("/groups/g1/members"):
            return httpx.Response(200, json={"members": [{"id": "u1", "type": "USER"}, {"id": "nested", "type": "GROUP"}]})
        if request.url.path.endswith("/groups/nested/members") and "pageToken=second" not in str(request.url):
            return httpx.Response(200, json={"members": [{"id": "g1", "type": "GROUP"}], "nextPageToken": "second"})
        if request.url.path.endswith("/groups/nested/members"):
            return httpx.Response(200, json={"members": [{"id": "u2", "type": "USER"}]})
        return httpx.Response(404)
    adapter = GoogleWorkspaceDirectoryAdapter("token", httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    users, groups, members = await adapter.users(), await adapter.groups(), await adapter.members("g1")
    assert [user.provider_id for user in users] == ["u1", "u2"]
    assert users[1].status == "suspended"
    assert groups[0].provider_id == "g1"
    assert members == ["u1", "u2"]
    assert any("pageToken=second" in url for url in calls)


@pytest.mark.asyncio
async def test_google_directory_rejects_incomplete_nested_member_record():
    adapter = GoogleWorkspaceDirectoryAdapter(
        "token",
        httpx.AsyncClient(transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"members": [{"type": "GROUP"}]})
        )),
    )
    with pytest.raises(DirectorySyncError, match="DIRECTORY_SYNC_INCOMPLETE"):
        await adapter.members("g1")


@pytest.mark.asyncio
async def test_graph_directory_maps_authorization_failure_without_leaking_details():
    adapter = MicrosoftEntraDirectoryAdapter("token", httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(403))))
    with pytest.raises(DirectorySyncError, match="INSUFFICIENT_DIRECTORY_PERMISSION"):
        await adapter.users()


@pytest.mark.asyncio
async def test_directory_sync_persists_a_source_scoped_recovery_cursor(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    class FakeDirectory:
        def __init__(self, _: str) -> None:
            pass

        async def users(self):
            return [DirectoryUser("stable-alice", "Alice", "alice@company.test", "active")]

        async def groups(self):
            return [DirectoryGroup("group-engineering", "Engineering", "eng@company.test")]

        async def members(self, _: str):
            return ["stable-alice"]

        async def close(self):
            return None

    monkeypatch.setattr("apps.api.accessproof_api.directory_sync.GoogleWorkspaceDirectoryAdapter", FakeDirectory)
    db = SessionLocal()
    try:
        org = Organization(name="Cursor organization")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="Current")
        db.add(project)
        db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id, provider="google-drive", name="Workspace", boundary="root")
        db.add(source)
        db.commit()
        result = await synchronize_directory(db, source, {"access_token": "test-token"})
        db.commit()
        assert result == {"users": 1, "groups": 1, "memberships": 1}
        cursor = db.scalar(select(ProviderSyncCursor))
        assert cursor is not None
        assert cursor.source_id == source.id and cursor.status == "connected"
        assert cursor.last_success_at is not None and cursor.last_provider_revision
        await synchronize_directory(db, source, {"access_token": "test-token"})
        db.commit()
        assert len(list(db.scalars(select(ProviderSyncCursor)))) == 1
    finally:
        db.close()


@pytest.mark.asyncio
async def test_graph_directory_reads_transitive_user_members_and_requires_complete_pages():
    requested = []
    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        if request.url.path == "/v1.0/users":
            return httpx.Response(200, json={"value": [
                {"id": "entra-user-1", "displayName": "Alice", "accountEnabled": True},
                {"id": "entra-user-2", "displayName": "Bob", "accountEnabled": False},
            ]})
        if request.url.path == "/v1.0/groups":
            return httpx.Response(200, json={"value": [
                {"id": "entra-group", "displayName": "Finance"}
            ]})
        if request.url.path == "/v1.0/groups/entra-group/transitiveMembers":
            if "$skiptoken" not in request.url.params:
                return httpx.Response(200, json={"value": [
                    {"@odata.type": "#microsoft.graph.user", "id": "entra-user-1"},
                    {"@odata.type": "#microsoft.graph.group", "id": "nested-group"},
                ], "@odata.nextLink":
                    "https://graph.microsoft.com/v1.0/groups/entra-group/transitiveMembers?$skiptoken=next"})
            return httpx.Response(200, json={"value": [
                {"@odata.type": "#microsoft.graph.user", "id": "entra-user-2"},
            ]})
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = MicrosoftEntraDirectoryAdapter("token", client)
    try:
        users = await adapter.users()
        groups = await adapter.groups()
        members = await adapter.members("entra-group")
        assert [u.status for u in users] == ["active", "disabled"]
        assert [g.provider_id for g in groups] == ["entra-group"]
        assert members == ["entra-user-1", "entra-user-2"]
        assert sum("/transitiveMembers" in x for x in requested) == 2
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_graph_directory_rejects_incomplete_permission_limited_responses():
    for response in [
        {"unrelated": "success"},
        {"value": [{"id": "user-without-account-enabled"}]},
        {"value": [{"id": "user", "accountEnabled": "false"}]},
    ]:
        client = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda _, result=response: httpx.Response(200, json=result)
        ))
        adapter = MicrosoftEntraDirectoryAdapter("token", client)
        try:
            with pytest.raises(DirectorySyncError, match="DIRECTORY_SYNC_INCOMPLETE"):
                await adapter.users()
        finally:
            await client.aclose()


@pytest.mark.asyncio
async def test_microsoft_directory_does_not_reassign_existing_group_by_reused_email(monkeypatch):
    """New Entra group with same email must not inherit old group's ACL or members."""
    from apps.api.accessproof_api.db import GuardGroup, GuardSubject, GuardGroupMembership

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    class FakeEntra:
        def __init__(self, _: str) -> None:
            pass
        async def users(self):
            return [DirectoryUser("entra-user-1", "Alice", "alice@example.com", "active")]
        async def groups(self):
            return [DirectoryGroup("new-immutable-group-id", "Finance replacement", "finance@example.com")]
        async def members(self, group_id: str):
            assert group_id == "new-immutable-group-id"
            return []
        async def close(self):
            return None
    monkeypatch.setattr(
        "apps.api.accessproof_api.directory_sync.MicrosoftEntraDirectoryAdapter", FakeEntra
    )
    with SessionLocal() as db:
        org = Organization(name="Entra group email reassignment")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="Test")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id,
            provider="microsoft365", boundary="root", name="SharePoint")
        old_group = GuardGroup(
            organization_id=org.id, provider="microsoft365",
            provider_group_id="old-immutable-group-id", provider_email="finance@example.com",
            status="active")
        old_user = GuardSubject(
            organization_id=org.id, provider="microsoft365",
            provider_subject_id="entra-user-1", status="active")
        db.add_all([source, old_group, old_user])
        db.flush()
        db.add(GuardGroupMembership(
            organization_id=org.id, group_id=old_group.id,
            subject_id=old_user.id, active=True))
        db.flush()
        old_id = old_group.id
        await synchronize_directory(db, source, {"access_token": "synthetic"})
        db.commit()
        groups = list(db.scalars(select(GuardGroup)))
        assert len(groups) == 2
        assert {g.provider_group_id for g in groups} == {
            "new-immutable-group-id", "old-immutable-group-id"
        }
        assert db.get(GuardGroup, old_id).status == "removed"
        assert next(g for g in groups if g.provider_group_id.startswith("new")).id != old_id
        assert all(not m.active for m in db.scalars(select(GuardGroupMembership)))
