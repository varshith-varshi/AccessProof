"""Synthetic ancestry checks for SharePoint / OneDrive approved source folders."""
import httpx
import pytest

from connectors.microsoft365.adapter import Microsoft365Adapter
from packages.connector_sdk.base import UnsafeBoundaryError


@pytest.mark.asyncio
async def test_microsoft_source_fails_closed_for_other_folders_and_cycles():
    parents = {
        "inside": "nested",
        "nested": "root",
        "outside": "elsewhere",
        "elsewhere": None,
        "cycle-a": "cycle-b",
        "cycle-b": "cycle-a",
        "external-drive": "root",
    }
    observed = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        ident = request.url.path.rsplit("/", 1)[-1]
        assert request.url.params["$select"] == "id,parentReference,remoteItem"
        parent = parents[ident]
        response = {"id": ident}
        if parent:
            response["parentReference"] = {
                "id": parent, "driveId": "different-drive" if ident == "external-drive" else "d1"
            }
        return httpx.Response(200, json=response)

    adapter = Microsoft365Adapter(access_token="synthetic", drive_id="d1", test_root_item_id="root")
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "Bearer synthetic"},
    )
    try:
        assert await adapter.is_inside_boundary("root")
        assert await adapter.is_inside_boundary("inside")
        assert not await adapter.is_inside_boundary("outside")
        assert not await adapter.is_inside_boundary("external-drive")
        with pytest.raises(UnsafeBoundaryError, match="cycle"):
            await adapter.is_inside_boundary("cycle-a")
        with pytest.raises(UnsafeBoundaryError):
            await adapter.is_inside_boundary("")
        assert all(r.url.host == "graph.microsoft.com" for r in observed)
    finally:
        await adapter._client.aclose()
