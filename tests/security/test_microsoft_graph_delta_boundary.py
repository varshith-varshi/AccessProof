"""Bearer token must never follow provider-supplied delta URLs outside Graph."""
import httpx
import pytest

from connectors.microsoft365.adapter import Microsoft365Adapter
from packages.connector_sdk.base import UnsafeBoundaryError


@pytest.mark.asyncio
async def test_graph_delta_accepts_only_same_drive_continuations():
    observed = []

    def response(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        assert request.url.host == "graph.microsoft.com"
        assert request.url.path == "/v1.0/drives/d1/root/delta"
        assert request.headers["authorization"] == "Bearer synthetic-token"
        return httpx.Response(200, json={"value": []})

    adapter = Microsoft365Adapter(access_token="synthetic-token", drive_id="d1", test_root_item_id="root")
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(
        transport=httpx.MockTransport(response),
        headers={"Authorization": "Bearer synthetic-token"},
    )
    try:
        await adapter.acl_delta_page()
        await adapter.acl_delta_page(
            "https://graph.microsoft.com/v1.0/drives/d1/root/delta?$skiptoken=next"
        )
        assert len(observed) == 2
        assert observed[-1].url.params["$skiptoken"] == "next"
        for url in [
            "https://attacker.example/capture",
            "https://graph.microsoft.com.attacker.example/v1.0/drives/d1/root/delta",
            "http://graph.microsoft.com/v1.0/drives/d1/root/delta",
            "https://graph.microsoft.com/v1.0/drives/another/root/delta",
            "https://graph.microsoft.com/v1.0/users?$skiptoken=next",
            "https://graph.microsoft.com:8443/v1.0/drives/d1/root/delta",
        ]:
            with pytest.raises(UnsafeBoundaryError):
                await adapter.acl_delta_page(url)
        assert len(observed) == 2
    finally:
        await adapter._client.aclose()
