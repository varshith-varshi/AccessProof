"""D-23: every Microsoft drive delta request asks Graph to report permission-only
(sharing) changes; otherwise a revoked grant is invisible to incremental sync."""
import asyncio

import httpx

from connectors.microsoft365.adapter import Microsoft365Adapter

REQUIRED = {"deltashowremovedasdeleted", "deltatraversepermissiongaps", "deltashowsharingchanges"}


def test_every_delta_call_sends_sharing_change_preferences():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append({p.strip() for p in request.headers.get("prefer", "").split(",") if p.strip()})
        return httpx.Response(200, json={
            "value": [],
            "@odata.deltaLink": "https://graph.microsoft.com/v1.0/drives/d1/root/delta?token=abc"})

    async def run():
        adapter = Microsoft365Adapter(access_token="t", drive_id="d1", test_root_item_id="root")
        adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        link = await adapter.acl_latest_delta_link()
        await adapter.acl_delta_page(link)
        await adapter.acl_delta_page(None)
        await adapter._client.aclose()
    asyncio.run(run())
    assert len(seen) == 3 and all(REQUIRED <= s for s in seen), seen
