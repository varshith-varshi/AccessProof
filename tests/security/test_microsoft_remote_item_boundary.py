"""SharePoint shortcuts and cross-drive remoteItem links must never grant access."""
import httpx
import pytest

from connectors.microsoft365.adapter import Microsoft365Adapter


@pytest.mark.asyncio
async def test_remote_item_excluded_from_initial_inventory_and_ancestry():
    calls = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        path = request.url.path
        if path.endswith("/root/children"):
            return httpx.Response(200, json={"value": [
                {"id": "remote-file", "remoteItem": {"id": "outside-drive-file"},
                 "parentReference": {"id": "root", "driveId": "d1"}},
                {"id": "remote-folder", "folder": {}, "remoteItem": {"id": "outside-folder"},
                 "parentReference": {"id": "root", "driveId": "d1"}},
                {"id": "local-file", "name": "Protected",
                 "parentReference": {"id": "root", "driveId": "d1"}},
            ]})
        if path.endswith("/remote-file"):
            return httpx.Response(200, json={
                "id": "remote-file", "remoteItem": {"id": "outside-drive-file"},
                "parentReference": {"id": "root", "driveId": "d1"},
            })
        return httpx.Response(404)

    adapter = Microsoft365Adapter(
        access_token="synthetic", drive_id="d1", test_root_item_id="root",
    )
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        assert [i["id"] for i in await adapter.list_boundary_resources()] == ["local-file"]
        assert not await adapter.is_inside_boundary("remote-file")
        assert all("/remote-folder/children" not in call for call in calls)
    finally:
        await adapter._client.aclose()
