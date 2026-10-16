import httpx
import pytest

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
