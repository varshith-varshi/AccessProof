from __future__ import annotations

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from connectors.microsoft365.trusted_ingestion import (
    SharePointIngestionSettings, SharePointTrustedIngestion,
)
from packages.rag_core.attestation import SourceAttestationSigner
from packages.rag_core.ingestion import IngestionError, TrustedSourceIngestor


class FakeAdapter:
    drive_id = "drive-1"
    tenant_hint = "tenant"
    sharepoint_site_id = "contoso.sharepoint.com,site-guid,web-guid"
    sharepoint_list_id = "list-guid"

    def __init__(self) -> None:
        self.inside = True
        self.metadata = {
            "id": "item-1", "file": {"mimeType": "text/plain"},
            "eTag": "{A},1", "lastModifiedDateTime": "2026-10-27T00:00:00Z",
            "parentReference": {"driveId": "drive-1", "id": "root"},
            "@microsoft.graph.downloadUrl": "https://tenant.sharepoint.com/download/item-1",
        }

    async def is_inside_boundary(self, item_id: str) -> bool:
        return self.inside and item_id == "item-1"

    async def _request(self, method: str, path: str, **kwargs):
        return httpx.Response(200, json=dict(self.metadata), request=httpx.Request(method, "https://graph.microsoft.com" + path))


def ingester(adapter: FakeAdapter, download_client: httpx.AsyncClient) -> SharePointTrustedIngestion:
    signer = TrustedSourceIngestor(SourceAttestationSigner(
        key_id="test", private_key=Ed25519PrivateKey.generate(),
    ))
    return SharePointTrustedIngestion(adapter, signer, SharePointIngestionSettings(
        tenant_id="tenant", application_id="sharepoint-rag", source_id="source",
    ), download_client=download_client)


@pytest.mark.asyncio
async def test_sharepoint_ingestion_attests_root_bound_graph_content_without_bearer_token():
    adapter = FakeAdapter()
    headers: list[httpx.Headers] = []

    def download(request: httpx.Request) -> httpx.Response:
        headers.append(request.headers)
        return httpx.Response(200, content=b"ACCESSPROOF_TEST_CANARY_FINANCE_2026", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(download)) as client:
        resources = await ingester(adapter, client).ingest("item-1")

    assert len(resources) == 1
    assert resources[0].resource_id == "item-1"
    assert resources[0].content_version == "{A},1"
    assert "ACCESSPROOF_TEST_CANARY" in resources[0].content
    assert "authorization" not in {key.lower() for key in headers[0]}


@pytest.mark.asyncio
async def test_sharepoint_ingestion_fails_closed_for_boundary_or_untrusted_download_url():
    adapter = FakeAdapter()
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"x", request=request))) as client:
        adapter.inside = False
        with pytest.raises(IngestionError, match="outside"):
            await ingester(adapter, client).ingest("item-1")
        adapter.inside = True
        adapter.metadata["@microsoft.graph.downloadUrl"] = "https://evil.example/download"
        with pytest.raises(IngestionError, match="untrusted"):
            await ingester(adapter, client).ingest("item-1")


@pytest.mark.asyncio
async def test_sharepoint_signer_rejects_wrong_tenant_or_incomplete_profile():
    adapter = FakeAdapter()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"test"))
    ) as client:
        adapter.tenant_hint = "another-tenant"
        with pytest.raises(IngestionError, match="tenant does not match"):
            ingester(adapter, client)
        adapter.tenant_hint = "tenant"
        adapter.sharepoint_site_id = None
        with pytest.raises(IngestionError, match="exact site and library"):
            ingester(adapter, client)
