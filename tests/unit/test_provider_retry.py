import httpx
import pytest

from connectors.http_utils import bounded_idempotent_request
from connectors.microsoft365.adapter import Microsoft365Adapter
from packages.connector_sdk.base import RateLimitError


@pytest.mark.asyncio
async def test_idempotent_provider_read_honors_retry_after_and_recovers(monkeypatch):
    calls = 0

    async def no_sleep(_):
        return None

    monkeypatch.setattr("connectors.http_utils.asyncio.sleep", no_sleep)

    async def send():
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                429,
                headers={"Retry-After": "0"},
                request=httpx.Request("GET", "https://provider.test/resource"),
            )
        return httpx.Response(
            200, json={"ok": True}, request=httpx.Request("GET", "https://provider.test/resource")
        )

    response = await bounded_idempotent_request(send)
    assert response.status_code == 200
    assert calls == 2


@pytest.mark.asyncio
async def test_microsoft_mutation_429_is_not_blindly_replayed():
    calls = 0

    def handler(req: httpx.Request):
        nonlocal calls
        calls += 1
        return httpx.Response(429, headers={"Retry-After": "1"})

    adapter = Microsoft365Adapter(access_token="t", drive_id="d", test_root_item_id="root")
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(RateLimitError):
        await adapter._request("DELETE", "/groups/G/members/U/$ref")
    assert calls == 1
    await adapter._client.aclose()
