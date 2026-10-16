import httpx
import pytest

from connectors.google_drive.adapter import GoogleDriveAdapter
from connectors.microsoft365.adapter import Microsoft365Adapter


@pytest.mark.asyncio
async def test_google_changes_api_returns_start_token_and_incremental_page():
    calls = []
    async def handler(request):
        calls.append(str(request.url))
        if request.url.path.endswith("startPageToken"):
            return httpx.Response(200, json={"startPageToken": "g-start"})
        return httpx.Response(200, json={"changes": [{"fileId": "F123", "file": {"id": "F123", "permissions": []}}], "newStartPageToken": "g-next"})
    adapter = GoogleDriveAdapter(access_token="token", test_root_folder_id="root")
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), headers={"Authorization": "Bearer token"})
    assert (await adapter.acl_change_page())["startPageToken"] == "g-start"
    assert (await adapter.acl_change_page("g-start"))["changes"][0]["fileId"] == "F123"
    await adapter._client.aclose()


@pytest.mark.asyncio
async def test_graph_delta_preserves_provider_delta_link():
    async def handler(request):
        return httpx.Response(200, json={"value": [{"id": "I123"}], "@odata.deltaLink": "https://graph.microsoft.com/delta/next"})
    adapter = Microsoft365Adapter(access_token="token", drive_id="drive", test_root_item_id="root")
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), headers={"Authorization": "Bearer token"})
    page = await adapter.acl_delta_page()
    assert page["@odata.deltaLink"].endswith("next")
    await adapter._client.aclose()
