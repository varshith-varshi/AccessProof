"""Trusted source-ingestion primitives for certified Gateway routes.

This module belongs in a customer-controlled ingestion service, never in a
browser, vector store, model process, or retrieval client.  Provider adapters
must set ``provider_identity_verified`` only after an authenticated provider
fetch tied to the configured source boundary.
"""
from __future__ import annotations

from dataclasses import dataclass

from .attestation import ContentBinding, SourceAttestationSigner
from .protection import RetrievedResource


class IngestionError(ValueError):
    """A provider object cannot become trusted retrieval context."""


@dataclass(frozen=True)
class VerifiedSourceDocument:
    tenant_id: str
    application_id: str
    source_id: str
    resource_id: str
    content_version: str
    content: str
    provider_identity_verified: bool
    deleted: bool = False

    def __post_init__(self) -> None:
        if not all((self.tenant_id, self.application_id, self.source_id, self.resource_id, self.content_version)):
            raise IngestionError("Complete source binding is required")
        if self.deleted or not self.provider_identity_verified:
            raise IngestionError("Provider source authenticity is not established")


class TrustedSourceIngestor:
    """Chunk authenticated provider content and issue short-lived attestations."""

    def __init__(self, signer: SourceAttestationSigner, *, chunk_bytes: int = 8_192) -> None:
        if not 1 <= chunk_bytes <= 100_000:
            raise IngestionError("Invalid chunk size")
        self._signer = signer
        self._chunk_bytes = chunk_bytes

    def attest_document(self, document: VerifiedSourceDocument, *, ttl_seconds: int = 300) -> list[RetrievedResource]:
        encoded = document.content.encode("utf-8")
        if not encoded:
            raise IngestionError("Empty source content cannot be attested")
        chunks: list[RetrievedResource] = []
        # Slice bytes then decode only at UTF-8 character boundaries.
        start = 0
        index = 0
        while start < len(encoded):
            end = min(len(encoded), start + self._chunk_bytes)
            # Extend at most three bytes to finish a UTF-8 codepoint. With a
            # small byte budget (e.g. 1), shrinking to an empty chunk would
            # reject perfectly valid Unicode; split only at character edges.
            while end < len(encoded) and (encoded[end] & 0xC0) == 0x80:
                end += 1
            text = encoded[start:end].decode("utf-8")
            chunk_id = f"{document.resource_id}:v{document.content_version}:c{index}"
            binding = ContentBinding(
                tenant_id=document.tenant_id, application_id=document.application_id,
                source_id=document.source_id, resource_id=document.resource_id,
                chunk_id=chunk_id, content_version=document.content_version, content=text,
            )
            chunks.append(RetrievedResource(
                source_id=document.source_id, resource_id=document.resource_id, chunk_id=chunk_id,
                content=text, content_version=document.content_version,
                content_attestation=self._signer.issue(binding, ttl_seconds=ttl_seconds),
            ))
            start = end
            index += 1
        return chunks
