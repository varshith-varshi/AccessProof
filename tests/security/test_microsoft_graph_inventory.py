"""Synthetic Graph inventory and permission paging: complete or fail closed."""
from __future__ import annotations

import httpx
import pytest

from connectors.microsoft365.adapter import Microsoft365Adapter
from packages.connector_sdk.base import UnsafeBoundaryError


@pytest.mark.asyncio
async def test_graph_full_subtree_inventory_and_permission_pagination():
    requests = []

    def handler(req: httpx.Request) -> httpx.Response:
        requests.append(req)
        path = req.url.path
        if path.endswith("/root/children"):
            return httpx.Response(200, json={"value": [
                {"id": "folder", "folder": {}, "parentReference": {"id": "root", "driveId": "d1"}},
            ], "@odata.nextLink": "https://graph.microsoft.com/v1.0/drives/d1/items/root/children?$skiptoken=2"} if "$skiptoken" not in req.url.params else {
                "value": [{"id": "file-A", "parentReference": {"id": "root", "driveId": "d1"}}]})
        if path.endswith("/folder/children"):
            return httpx.Response(200, json={"value": [
                {"id": "file-B", "parentReference": {"id": "folder", "driveId": "d1"}}
            ]})
        if path.endswith("/file-A/permissions"):
            return httpx.Response(200, json={"value": [{"id": "p1"}], "@odata.nextLink":
                "https://graph.microsoft.com/v1.0/drives/d1/items/file-A/permissions?$skiptoken=2"} if "$skiptoken" not in req.url.params else {
                "value": [{"id": "p2"}]})
        if path.endswith("/root/delta"):
            return httpx.Response(200, json={"value": [], "@odata.deltaLink":
                "https://graph.microsoft.com/v1.0/drives/d1/root/delta?$deltatoken=abc"})
        return httpx.Response(404)

    adapter = Microsoft365Adapter(access_token="synthetic", drive_id="d1", test_root_item_id="root")
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                      headers={"Authorization": "Bearer synthetic"})
    try:
        assert [x["id"] for x in await adapter.list_boundary_resources()] == ["folder", "file-A", "file-B"]
        assert [x["id"] for x in await adapter.permissions_snapshot("file-A")] == ["p1", "p2"]
        assert (await adapter.acl_latest_delta_link()).endswith("abc")
        assert all(r.url.host == "graph.microsoft.com" for r in requests)
    finally:
        await adapter._client.aclose()


@pytest.mark.asyncio
async def test_graph_rejects_untrusted_paging_missing_pages_or_parent_escape():
    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path.endswith("/root/children"):
            return httpx.Response(200, json={"value": [{"id": "file", "parentReference": {
                "id": "wrong", "driveId": "d1"}}]})
        if path.endswith("/root/permissions"):
            return httpx.Response(200, json={"value": [{"id": "p"}], "@odata.nextLink":
                "https://attacker.invalid/steal"})
        return httpx.Response(404)
    a = Microsoft365Adapter(access_token="synthetic", drive_id="d1", test_root_item_id="root")
    await a._client.aclose()
    a._client = httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                 headers={"Authorization": "Bearer synthetic"})
    try:
        with pytest.raises(UnsafeBoundaryError):
            await a.list_boundary_resources()
        with pytest.raises(UnsafeBoundaryError):
            await a.permissions_snapshot("root")
    finally:
        await a._client.aclose()
