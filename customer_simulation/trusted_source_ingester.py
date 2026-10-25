"""Isolated, source-side attested document server for customer simulation.

Only synthetic corpus data. In production, attestations must be issued by a
source-ingestion worker that fetched and verified source versions via the
actual provider APIs. Never deploy this laboratory server as an ingestion API.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from packages.rag_sdk.attestation import ContentBinding, SourceAttestationSigner


@dataclass(frozen=True)
class SyntheticProviderFile:
    resource_id: str
    source_id: str
    version: str
    text: str
    chunk_id: str = "chunk-0"


class AttestedFileResult(BaseModel):
    source_id: str
    resource_id: str
    chunk_id: str
    content_version: str
    content: str
    content_attestation: str


def build_synthetic_ingestion_service(
    *, tenant_id: str, application_id: str,
    documents: list[SyntheticProviderFile], signer: SourceAttestationSigner,
) -> FastAPI:
    """Build a deliberately test-only source system with signer custody."""
    if not tenant_id or not application_id or not documents:
        raise ValueError("A dedicated nonempty lab scope is required")
    indexed = {item.resource_id: item for item in documents}
    if len(indexed) != len(documents):
        raise ValueError("Duplicate source resource identifiers")
    service = FastAPI(title="Isolated Synthetic Source Ingester")

    @service.get("/ingest/v1/documents/{resource_id}", response_model=AttestedFileResult)
    def get_document(resource_id: str) -> AttestedFileResult:
        item = indexed.get(resource_id)
        if item is None:
            raise HTTPException(404, "Synthetic provider resource not found")
        binding = ContentBinding(
            tenant_id=tenant_id, application_id=application_id,
            source_id=item.source_id, resource_id=item.resource_id,
            chunk_id=item.chunk_id, content_version=item.version, content=item.text,
        )
        return AttestedFileResult(
            source_id=item.source_id, resource_id=item.resource_id,
            chunk_id=item.chunk_id, content_version=item.version, content=item.text,
            content_attestation=signer.issue(binding),
        )

    return service
