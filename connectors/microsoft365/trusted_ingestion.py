"""Trusted SharePoint text ingestion for an independently controlled signer.

Only authenticated Microsoft Graph metadata and bytes fetched from Graph's
short-lived, preauthenticated download URL become attested retrieval context.
This module deliberately supports UTF-8 ``text/plain`` files only. It does
not infer SharePoint effective access from DriveItem permissions; Guard remains
the authorization authority at request and cache-release time.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from connectors.microsoft365.adapter import Microsoft365Adapter
from packages.rag_core.ingestion import IngestionError, TrustedSourceIngestor, VerifiedSourceDocument
from packages.rag_core.protection import RetrievedResource


@dataclass(frozen=True)
class SharePointIngestionSettings:
    tenant_id: str
    application_id: str
    source_id: str
    max_content_bytes: int = 2_000_000

    def __post_init__(self) -> None:
        if not all((self.tenant_id, self.application_id, self.source_id)):
            raise IngestionError("Tenant, application, and source bindings are required")
        if not 1 <= self.max_content_bytes <= 20_000_000:
            raise IngestionError("Invalid source-content size limit")


def _trusted_download_url(value: object) -> str:
    if not isinstance(value, str) or len(value) > 16_000:
        raise IngestionError("Microsoft download URL is missing or invalid")
    try:
        url = urlsplit(value)
        host = (url.hostname or "").lower()
        port = url.port  # Accessing .port can itself raise ValueError.
    except (TypeError, ValueError) as exc:
        raise IngestionError("Microsoft download URL is invalid") from exc
    # Microsoft documents a short-lived preauthenticated URL. Fetch it without
    # the Graph bearer token and only from documented OneDrive/SharePoint
    # delivery domains; never let Graph metadata redirect credentials elsewhere.
    trusted_host = host.endswith(".sharepoint.com") or host.endswith(".1drv.com") or host.endswith(".onedrive.com")
    if (url.scheme != "https" or not trusted_host or port not in (None, 443)
            or url.username or url.password or url.fragment):
        raise IngestionError("Microsoft download URL is untrusted")
    return value


class SharePointTrustedIngestion:
    """Root-bound provider fetcher for the customer-side attestation signer."""

    def __init__(
        self, adapter: Microsoft365Adapter, signer: TrustedSourceIngestor,
        settings: SharePointIngestionSettings, *,
        download_client: httpx.AsyncClient | None = None,
    ) -> None:
        # Content must never be signed as belonging to another tenant or as
        # SharePoint content when the underlying adapter uses an unscoped
        # Microsoft drive profile. The Graph app token alone is not a source
        # identity proof; the caller must configure the exact site and library.
        tenant_hint = getattr(adapter, "tenant_hint", None)
        if (not isinstance(tenant_hint, str)
                or tenant_hint.lower() != settings.tenant_id.lower()):
            raise IngestionError("SharePoint signer tenant does not match source tenant")
        if (not getattr(adapter, "sharepoint_site_id", None)
                or not getattr(adapter, "sharepoint_list_id", None)):
            raise IngestionError("SharePoint signer requires an exact site and library profile")
        self._adapter = adapter
        self._signer = signer
        self._settings = settings
        self._owned_download_client = download_client is None
        # Download URLs are preauthenticated. A shared HTTP client with
        # Authorization (including client-level auth) could accidentally send
        # an enterprise Graph credential to that content host.
        if download_client is not None and (
            download_client.headers.get("Authorization") or download_client.auth is not None
        ):
            raise IngestionError("SharePoint download client must not have authentication")
        self._download_client = download_client or httpx.AsyncClient(
            timeout=30, follow_redirects=False, trust_env=False,
        )

    async def close(self) -> None:
        if self._owned_download_client:
            await self._download_client.aclose()

    async def _metadata(self, item_id: str) -> dict[str, Any]:
        response = await self._adapter._request(
            "GET", f"/drives/{self._adapter.drive_id}/items/{item_id}",
            params={"$select": "id,file,eTag,lastModifiedDateTime,parentReference,deleted,@microsoft.graph.downloadUrl"},
        )
        payload = response.json()
        file = payload.get("file") if isinstance(payload, dict) else None
        parent = payload.get("parentReference") if isinstance(payload, dict) else None
        if (not isinstance(payload, dict) or payload.get("id") != item_id
                or payload.get("deleted") is not None or not isinstance(file, dict)
                or file.get("mimeType") != "text/plain" or not isinstance(payload.get("eTag"), str)
                or not payload["eTag"] or not isinstance(payload.get("lastModifiedDateTime"), str)
                or not isinstance(parent, dict) or parent.get("driveId", self._adapter.drive_id) != self._adapter.drive_id):
            raise IngestionError("Unverifiable or unsupported SharePoint document")
        _trusted_download_url(payload.get("@microsoft.graph.downloadUrl"))
        return payload

    async def _content(self, download_url: str) -> str:
        size = 0
        parts: list[bytes] = []
        try:
            # Never inherit redirect handling from a caller-provided client.
            # The attested bytes must come from the validated delivery origin.
            async with self._download_client.stream(
                "GET", download_url, follow_redirects=False
            ) as response:
                if response.status_code != 200:
                    raise IngestionError("SharePoint document download failed")
                async for part in response.aiter_bytes():
                    size += len(part)
                    if size > self._settings.max_content_bytes:
                        raise IngestionError("SharePoint document exceeds the configured size limit")
                    parts.append(part)
        except httpx.HTTPError as exc:
            raise IngestionError("SharePoint document download failed") from exc
        try:
            content = b"".join(parts).decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise IngestionError("SharePoint text is not valid UTF-8") from exc
        if not content:
            raise IngestionError("Empty source content cannot be attested")
        return content

    async def ingest(self, item_id: str) -> list[RetrievedResource]:
        if (not isinstance(item_id, str) or not item_id or len(item_id) > 1024
                or not item_id.isascii()
                or any(char in item_id for char in "/\\?#%")
                or any(ord(char) < 32 for char in item_id)):
            raise IngestionError("Invalid SharePoint item identifier")
        if not await self._adapter.is_inside_boundary(item_id):
            raise IngestionError("SharePoint item is outside the approved source boundary")
        initial = await self._metadata(item_id)
        content = await self._content(_trusted_download_url(initial.get("@microsoft.graph.downloadUrl")))
        final = await self._metadata(item_id)
        if (not await self._adapter.is_inside_boundary(item_id)
                or initial["eTag"] != final["eTag"]
                or initial["lastModifiedDateTime"] != final["lastModifiedDateTime"]
                or initial["parentReference"] != final["parentReference"]):
            raise IngestionError("SharePoint document changed during source verification")
        return self._signer.attest_document(VerifiedSourceDocument(
            tenant_id=self._settings.tenant_id,
            application_id=self._settings.application_id,
            source_id=self._settings.source_id,
            resource_id=item_id,
            content_version=final["eTag"],
            content=content,
            provider_identity_verified=True,
            deleted=False,
        ))
