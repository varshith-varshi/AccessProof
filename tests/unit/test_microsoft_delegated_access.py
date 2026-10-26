from __future__ import annotations

import httpx
import pytest

from connectors.microsoft365.adapter import Microsoft365Adapter
from packages.connector_sdk.base import ProviderUnavailableError
from packages.domain.models import Principal, SourceResource


class _DelegatedClient:
    def __init__(self, response: httpx.Response, **_: object):
        self.response = response

    async def __aenter__(self) -> "_DelegatedClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def get(self, _: str) -> httpx.Response:
        return self.response


def _resource() -> SourceResource:
    return SourceResource("item-1", "canary.txt", "accessproof-generated", "AP-CANARY")


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 302])
async def test_delegated_content_request_confirms_effective_access(monkeypatch, status: int):
    response = httpx.Response(status, request=httpx.Request("GET", "https://graph.microsoft.com"))
    monkeypatch.setattr(
        "connectors.microsoft365.adapter.httpx.AsyncClient",
        lambda **kwargs: _DelegatedClient(response, **kwargs),
    )
    adapter = Microsoft365Adapter(access_token="admin", drive_id="drive", test_root_item_id="root")

    assert await adapter.verify_user_can_access(_resource(), Principal("alice", access_token="alice-token"))


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 404])
async def test_delegated_content_request_confirms_effective_denial(monkeypatch, status: int):
    response = httpx.Response(status, request=httpx.Request("GET", "https://graph.microsoft.com"))
    monkeypatch.setattr(
        "connectors.microsoft365.adapter.httpx.AsyncClient",
        lambda **kwargs: _DelegatedClient(response, **kwargs),
    )
    adapter = Microsoft365Adapter(access_token="admin", drive_id="drive", test_root_item_id="root")

    assert not await adapter.verify_user_can_access(_resource(), Principal("alice", access_token="alice-token"))


@pytest.mark.asyncio
async def test_delegated_transient_error_is_not_misclassified_as_denial(monkeypatch):
    response = httpx.Response(503, request=httpx.Request("GET", "https://graph.microsoft.com"))
    monkeypatch.setattr(
        "connectors.microsoft365.adapter.httpx.AsyncClient",
        lambda **kwargs: _DelegatedClient(response, **kwargs),
    )
    adapter = Microsoft365Adapter(access_token="admin", drive_id="drive", test_root_item_id="root")

    with pytest.raises(ProviderUnavailableError):
        await adapter.verify_user_can_access(_resource(), Principal("alice", access_token="alice-token"))
