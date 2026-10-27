"""Security regression coverage for SharePoint provider/client trust boundaries."""
from __future__ import annotations

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from connectors.microsoft365.sharepoint_effective import (
    SharePointEffectiveAccessProbe,
    SharePointPermissionError,
)
from connectors.microsoft365.trusted_ingestion import (
    SharePointIngestionSettings,
    SharePointTrustedIngestion,
)
from packages.rag_core.attestation import SourceAttestationSigner
from packages.rag_core.ingestion import IngestionError, TrustedSourceIngestor


class FakeSharePointAdapter:
    drive_id = "drive-1"
    tenant_hint = "tenant"
    sharepoint_site_id = "contoso.sharepoint.com,site-guid,web-guid"
    sharepoint_list_id = "list-guid"

    async def is_inside_boundary(self, item_id: str) -> bool:
        return item_id == "item-1"

    async def _request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "item-1",
                "file": {"mimeType": "text/plain"},
                "eTag": "{A},1",
                "lastModifiedDateTime": "2026-10-27T00:00:00Z",
                "parentReference": {"driveId": "drive-1", "id": "root"},
                "@microsoft.graph.downloadUrl": (
                    "https://tenant.sharepoint.com/download/item-1"
                ),
            },
            request=httpx.Request(method, "https://graph.microsoft.com" + path),
        )


def ingestion_with_client(client: httpx.AsyncClient) -> SharePointTrustedIngestion:
    signer = TrustedSourceIngestor(
        SourceAttestationSigner(
            key_id="test", private_key=Ed25519PrivateKey.generate()
        )
    )
    return SharePointTrustedIngestion(
        FakeSharePointAdapter(),  # type: ignore[arg-type]
        signer,
        SharePointIngestionSettings(
            tenant_id="tenant", application_id="app", source_id="source"
        ),
        download_client=client,
    )


@pytest.mark.asyncio
async def test_effective_permission_rejects_redirect_with_redirecting_client() -> None:
    visited: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        visited.append(request.url.host)
        if request.url.host == "tenant.sharepoint.com":
            return httpx.Response(302, headers={"Location": "https://evil.example/allow"})
        return httpx.Response(200, json={"High": "0", "Low": "1"})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as client:
        probe = SharePointEffectiveAccessProbe(
            site_url="https://tenant.sharepoint.com/sites/Test",
            sharepoint_access_token="synthetic",
            client=client,
        )
        with pytest.raises(
            SharePointPermissionError, match="PERMISSION_ENDPOINT_UNAVAILABLE"
        ):
            await probe.can_view_item(
                list_id="11111111-2222-3333-4444-555555555555",
                item_id=1,
                verified_login_name="verified",
            )
    assert visited == ["tenant.sharepoint.com"]


@pytest.mark.asyncio
async def test_ingestion_does_not_follow_download_redirect_to_untrusted_host() -> None:
    visited: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        visited.append(request.url.host)
        if request.url.host == "tenant.sharepoint.com":
            return httpx.Response(
                302, headers={"Location": "https://evil.example/fake-document"}
            )
        return httpx.Response(200, content=b"malicious unverified content")

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as client:
        with pytest.raises(IngestionError, match="download failed"):
            await ingestion_with_client(client).ingest("item-1")
    assert visited == ["tenant.sharepoint.com"]


@pytest.mark.asyncio
async def test_ingestion_rejects_preconfigured_authorization_header() -> None:
    async with httpx.AsyncClient(
        headers={"Authorization": "Bearer GRAPH_SECRET"},
        transport=httpx.MockTransport(lambda req: httpx.Response(200, content=b"data")),
    ) as client:
        with pytest.raises(IngestionError, match="must not have authentication"):
            ingestion_with_client(client)


@pytest.mark.asyncio
async def test_ingestion_rejects_preconfigured_auth_handler() -> None:
    async with httpx.AsyncClient(
        auth=httpx.BasicAuth("user", "password"),
        transport=httpx.MockTransport(lambda req: httpx.Response(200, content=b"data")),
    ) as client:
        with pytest.raises(IngestionError, match="must not have authentication"):
            ingestion_with_client(client)


@pytest.mark.parametrize(
    "bad_url",
    [
        "https://tenant.sharepoint.com:not-a-port/x",
        "https://tenant.sharepoint.com:99999/x",
    ],
)
def test_unparseable_sharepoint_download_port_raises_ingestion_error(bad_url: str) -> None:
    from connectors.microsoft365.trusted_ingestion import _trusted_download_url

    with pytest.raises(IngestionError):
        _trusted_download_url(bad_url)


@pytest.mark.parametrize(
    "bad_url",
    [
        "https://tenant.sharepoint.com:invalid/sites/Finance",
        "https://tenant.sharepoint.com:99999/sites/Finance",
    ],
)
def test_unparseable_sharepoint_site_port_raises_permission_error(bad_url: str) -> None:
    from connectors.microsoft365.sharepoint_effective import _trusted_site_url

    with pytest.raises(SharePointPermissionError):
        _trusted_site_url(bad_url)


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_id", ["../outside", "item/other", "item%2Fother", "other?id=1"])
async def test_sharepoint_ingestion_rejects_ambiguous_graph_item_ids(bad_id: str) -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, content=b"should not fetch")
        )
    ) as client:
        with pytest.raises(IngestionError, match="Invalid SharePoint item identifier"):
            await ingestion_with_client(client).ingest(bad_id)
