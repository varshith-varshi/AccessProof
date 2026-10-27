from __future__ import annotations

import httpx
import pytest

from connectors.microsoft365.adapter import Microsoft365Adapter
from packages.connector_sdk.base import AuthenticationError, ProviderUnavailableError, UnsupportedCapabilityError
from packages.domain.models import Principal, SourceResource


class _DelegatedClient:
    def __init__(self, response: httpx.Response, *, verified_id: str = "alice", **_: object):
        self.response = response
        self.verified_id = verified_id

    async def __aenter__(self) -> "_DelegatedClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def get(self, url: str) -> httpx.Response:
        if url.endswith("/me?$select=id"):
            return httpx.Response(200, json={"id": self.verified_id}, request=httpx.Request("GET", url))
        return self.response


def _resource() -> SourceResource:
    return SourceResource("item-1", "canary.txt", "accessproof-generated", "AP-CANARY")


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 302])
async def test_delegated_content_request_confirms_effective_access(monkeypatch, status: int):
    response = httpx.Response(
        status,
        headers={"Location": "https://tenant.sharepoint.com/download/canary"} if status == 302 else {},
        request=httpx.Request("GET", "https://graph.microsoft.com"),
    )
    monkeypatch.setattr(
        "connectors.microsoft365.adapter.httpx.AsyncClient",
        lambda **kwargs: _DelegatedClient(response, **kwargs),
    )
    adapter = Microsoft365Adapter(access_token="admin", drive_id="drive", test_root_item_id="root")

    assert await adapter.verify_user_can_access(_resource(), Principal("alice", access_token="alice-token"))


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [403, 404])
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


@pytest.mark.asyncio
async def test_delegated_unauthorized_token_is_inconclusive_not_revocation(monkeypatch):
    response = httpx.Response(401, request=httpx.Request("GET", "https://graph.microsoft.com"))
    monkeypatch.setattr(
        "connectors.microsoft365.adapter.httpx.AsyncClient",
        lambda **kwargs: _DelegatedClient(response, **kwargs),
    )
    adapter = Microsoft365Adapter(access_token="admin", drive_id="drive", test_root_item_id="root")
    with pytest.raises(AuthenticationError, match="rejected"):
        await adapter.verify_user_can_access(
            _resource(), Principal("alice", access_token="expired")
        )


@pytest.mark.asyncio
async def test_admin_permission_inventory_cannot_replace_delegated_ground_truth():
    adapter = Microsoft365Adapter(access_token="admin", drive_id="drive", test_root_item_id="root")
    try:
        with pytest.raises(UnsupportedCapabilityError, match="delegated token"):
            await adapter.verify_user_can_access(
                _resource(), Principal("alice", email="alice@example.com")
            )
    finally:
        await adapter._client.aclose()


@pytest.mark.asyncio
async def test_delegated_token_substitution_cannot_forge_employee_revocation(monkeypatch):
    from packages.connector_sdk.base import AuthorizationError

    response = httpx.Response(403, request=httpx.Request("GET", "https://graph.microsoft.com"))
    monkeypatch.setattr(
        "connectors.microsoft365.adapter.httpx.AsyncClient",
        lambda **kwargs: _DelegatedClient(response, verified_id="bob", **kwargs),
    )
    adapter = Microsoft365Adapter(access_token="admin", drive_id="drive", test_root_item_id="root")

    with pytest.raises(AuthorizationError, match="does not match tested employee"):
        await adapter.verify_user_can_access(_resource(), Principal("alice", access_token="bob-token"))
