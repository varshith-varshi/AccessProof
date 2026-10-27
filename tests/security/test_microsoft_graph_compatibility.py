"""Microsoft Graph compatibility regressions for real SharePoint tenant integration."""
from __future__ import annotations

import httpx
import pytest

from connectors.microsoft365.adapter import Microsoft365Adapter
from packages.connector_sdk.base import ProviderUnavailableError
from packages.domain.models import Principal, SourceResource


def _resource() -> SourceResource:
    return SourceResource("item-1", "canary.txt", "accessproof-generated", "AP-CANARY")


@pytest.mark.asyncio
async def test_microsoft_graph_license_error_has_safe_actionable_code() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        assert request.headers["Authorization"] == "Bearer admin-secret"
        return httpx.Response(
            400,
            json={"error": {"code": "BadRequest", "message": "Tenant does not have a SPO license."}},
        )

    adapter = Microsoft365Adapter(
        access_token="admin-secret", drive_id="drive", test_root_item_id="root"
    )
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "Bearer admin-secret"},
    )
    try:
        with pytest.raises(ProviderUnavailableError, match="MICROSOFT_SHAREPOINT_SERVICE_NOT_READY") as error:
            await adapter.validate_connection()
        assert "admin-secret" not in str(error.value)
        assert seen == ["graph.microsoft.com"]
    finally:
        await adapter._client.aclose()


@pytest.mark.asyncio
async def test_graph_app_token_does_not_follow_untrusted_redirect_from_injected_client() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        if request.url.host == "graph.microsoft.com":
            return httpx.Response(302, headers={"Location": "https://attacker.example/capture"})
        raise AssertionError("Bearer token crossed the Graph trust boundary")

    adapter = Microsoft365Adapter(
        access_token="admin-secret", drive_id="drive", test_root_item_id="root"
    )
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(
        headers={"Authorization": "Bearer admin-secret"},
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )
    try:
        with pytest.raises(httpx.HTTPStatusError):
            await adapter._request("GET", "/drives/drive/items/root")
        assert seen == ["graph.microsoft.com"]
    finally:
        await adapter._client.aclose()


class DelegatedClient:
    def __init__(self, response: httpx.Response, **_: object) -> None:
        self.response = response

    async def __aenter__(self) -> "DelegatedClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        pass

    async def get(self, url: str) -> httpx.Response:
        if url.endswith("/me?$select=id"):
            return httpx.Response(200, json={"id": "alice"}, request=httpx.Request("GET", url))
        return self.response


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "location"),
    [
        (302, ""),
        (302, "https://attacker.example/allow"),
        (302, "http://tenant.sharepoint.com/content"),
        (302, "https://tenant.sharepoint.com:444/content"),
        (302, "https://tenant.sharepoint.com:invalid/content"),
        (302, "https://tenant.sharepoint.com@attacker.example/content"),
        (301, "https://tenant.sharepoint.com/content"),
        (307, "https://tenant.sharepoint.com/content"),
    ],
)
async def test_delegated_access_does_not_count_untrusted_redirect_as_allowed(
    monkeypatch: pytest.MonkeyPatch, status: int, location: str,
) -> None:
    response = httpx.Response(
        status, headers={"Location": location} if location else {},
        request=httpx.Request("GET", "https://graph.microsoft.com/v1.0/drives/d/items/i/content"),
    )
    adapter = Microsoft365Adapter(
        access_token="admin-secret", drive_id="drive", test_root_item_id="root"
    )
    await adapter._client.aclose()
    monkeypatch.setattr(
        "connectors.microsoft365.adapter.httpx.AsyncClient",
        lambda **kwargs: DelegatedClient(response, **kwargs),
    )
    with pytest.raises(ProviderUnavailableError):
        await adapter.verify_user_can_access(
            _resource(), Principal("alice", access_token="valid-employee-token")
        )


def test_microsoft_token_secret_never_follows_redirect_even_with_injected_client() -> None:
    from packages.auth.microsoft_consent import MicrosoftConsentError, graph_app_token

    destinations: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        destinations.append(request.url.host)
        if request.url.host == "login.microsoftonline.com":
            assert b"private-app-secret" in request.content
            return httpx.Response(
                302, headers={"Location": "https://attacker.example/token-capture"}
            )
        raise AssertionError("Confidential Microsoft application secret left Microsoft authority")

    with httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as client:
        with pytest.raises(MicrosoftConsentError):
            graph_app_token(
                tenant_id="11111111-2222-3333-4444-555555555555",
                client_id="test-app", client_secret="private-app-secret", client=client,
            )
    assert destinations == ["login.microsoftonline.com"]
