"""Authenticated Google Drive text ingestion for the customer-controlled signer.

Only provider-fetched, stable-revision content within the configured source
boundary may be signed. V3 reference supports UTF-8 text/plain and native
Google Docs exported as text/plain; other file types remain unsupported.
Never make the signing private key available to a RAG client.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from connectors.google_drive.adapter import GoogleDriveAdapter
from packages.rag_core.ingestion import IngestionError, TrustedSourceIngestor, VerifiedSourceDocument
from packages.rag_core.protection import RetrievedResource


@dataclass(frozen=True)
class GoogleDriveIngestionSettings:
    tenant_id: str
    application_id: str
    source_id: str
    max_content_bytes: int = 2_000_000

    def __post_init__(self) -> None:
        if not all((self.tenant_id, self.application_id, self.source_id)):
            raise IngestionError("Tenant, application, and source bindings are required")
        if not 1 <= self.max_content_bytes <= 20_000_000:
            raise IngestionError("Invalid source-content size limit")


class GoogleDriveTrustedIngestion:
    """Provider-backed signer gateway; depends on an approved root-bound adapter."""

    def __init__(self, adapter: GoogleDriveAdapter, signer: TrustedSourceIngestor,
                 settings: GoogleDriveIngestionSettings) -> None:
        self._adapter = adapter
        self._signer = signer
        self._settings = settings

    async def _metadata(self, file_id: str) -> dict[str, Any]:
        response = await self._adapter._request(
            "GET", f"{self._adapter.API}/files/{quote(file_id, safe='')}",
            params={"fields": "id,mimeType,version,modifiedTime,trashed,parents,size",
                    "supportsAllDrives": "true"},
        )
        payload = response.json()
        if (not isinstance(payload, dict) or payload.get("id") != file_id or
            payload.get("trashed") is not False or
            payload.get("mimeType") not in {
                "text/plain", "application/vnd.google-apps.document",
            } or
            not isinstance(payload.get("version"), str) or not payload["version"].isdigit()
        ):
            raise IngestionError("Unverifiable or unsupported Google Drive document")
        size = payload.get("size")
        if size is not None and (not str(size).isdigit() or int(size) > self._settings.max_content_bytes):
            raise IngestionError("Google Drive document exceeds the configured size limit")
        return payload

    async def _content(self, file_id: str, mime_type: str) -> str:
        if mime_type == "application/vnd.google-apps.document":
            url = f"{self._adapter.API}/files/{quote(file_id, safe='')}/export"
            params = {"mimeType": "text/plain"}
        else:
            url = f"{self._adapter.API}/files/{quote(file_id, safe='')}"
            params = {"alt": "media", "supportsAllDrives": "true"}
        size = 0
        parts: list[bytes] = []
        # The existing adapter client carries the authenticated provider OAuth
        # credential. Streaming avoids unbounded provider response allocation.
        async with self._adapter._client.stream(
            "GET", url, params=params,
        ) as response:
            response.raise_for_status()
            async for part in response.aiter_bytes():
                size += len(part)
                if size > self._settings.max_content_bytes:
                    raise IngestionError("Google Drive document exceeds the configured size limit")
                parts.append(part)
        try:
            content = b"".join(parts).decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise IngestionError("Google Drive text is not valid UTF-8") from exc
        if not content:
            raise IngestionError("Empty source content cannot be attested")
        return content

    async def ingest(self, file_id: str) -> list[RetrievedResource]:
        if (not isinstance(file_id, str) or not file_id or len(file_id) > 1024
                or any(ord(ch) < 32 for ch in file_id)):
            raise IngestionError("Invalid provider file identifier")
        if not await self._adapter.is_inside_boundary(file_id):
            raise IngestionError("File is outside the authorized Google Drive root")
        initial = await self._metadata(file_id)
        content = await self._content(file_id, initial["mimeType"])
        final = await self._metadata(file_id)
        if (not await self._adapter.is_inside_boundary(file_id)
                or initial["version"] != final["version"]
                or initial.get("modifiedTime") != final.get("modifiedTime")
                or initial.get("parents") != final.get("parents")
                or initial.get("mimeType") != final.get("mimeType")):
            raise IngestionError("Google Drive file changed during source verification")
        return self._signer.attest_document(
            VerifiedSourceDocument(
                tenant_id=self._settings.tenant_id,
                application_id=self._settings.application_id,
                source_id=self._settings.source_id,
                resource_id=file_id,
                content_version=final["version"],
                content=content,
                provider_identity_verified=True,
                deleted=False,
            ),
        )
