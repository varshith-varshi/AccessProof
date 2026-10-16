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
async def test_google_directory_paginates_users_and_members():
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
        return httpx.Response(404)
    adapter = GoogleWorkspaceDirectoryAdapter("token", httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    users, groups, members = await adapter.users(), await adapter.groups(), await adapter.members("g1")
    assert [user.provider_id for user in users] == ["u1", "u2"]
    assert users[1].status == "suspended"
    assert groups[0].provider_id == "g1"
    assert members == ["u1"]
    assert any("pageToken=second" in url for url in calls)


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
