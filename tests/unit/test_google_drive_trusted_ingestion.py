from __future__ import annotations


import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from connectors.google_drive.adapter import GoogleDriveAdapter
from connectors.google_drive.trusted_ingestion import (
    GoogleDriveIngestionSettings, GoogleDriveTrustedIngestion,
)
from packages.rag_sdk import ContentBinding, SourceAttestationSigner, SourceAttestationVerifier, TrustedSourceIngestor, IngestionError


def _make_transport(*, content: bytes = b"authorized sample", mime: str = "text/plain",
                    version_change: bool = False, oversized: bool = False):
    requests = {"metadata": 0}
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/files/doc1") and req.url.params.get("alt") == "media":
            return httpx.Response(200, content=(b"X" * 2_000_100) if oversized else content)
        if req.url.path.endswith("/files/doc1/export"):
            assert req.url.params.get("mimeType") == "text/plain"
            assert req.url.params.get("alt") is None
            return httpx.Response(200, content=content)
        if req.url.path.endswith("/files/doc1") and "version" in req.url.params.get("fields", ""):
            requests["metadata"] += 1
            return httpx.Response(200, json={
                "id": "doc1", "mimeType": mime,
                "version": "2" if version_change and requests["metadata"] > 1 else "1",
                "modifiedTime": "2026-10-23T10:00:00Z", "trashed": False,
                "parents": ["root"], "size": "1" if oversized else str(len(content)),
            })
        if req.url.path.endswith("/files/doc1"):
            return httpx.Response(200, json={"id": "doc1", "parents": ["root"], "trashed": False})
        if req.url.path.endswith("/files/root"):
            return httpx.Response(200, json={"id": "root", "parents": [], "trashed": False})
        raise AssertionError(str(req.url))
    return httpx.MockTransport(handler), requests


async def _run(*, content: bytes = b"authorized sample", mime: str = "text/plain",
               version_change: bool = False, oversized: bool = False):
    transport, requests = _make_transport(content=content, mime=mime, version_change=version_change, oversized=oversized)
    adapter = GoogleDriveAdapter(access_token="synthetic-owner-token", test_root_folder_id="root")
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(transport=transport, headers={"Authorization": "Bearer synthetic-owner-token"})
    try:
        signing_key = Ed25519PrivateKey.generate()
        signer = TrustedSourceIngestor(SourceAttestationSigner(key_id="trusted-ingester", private_key=signing_key))
        gateway = GoogleDriveTrustedIngestion(adapter, signer, GoogleDriveIngestionSettings(
            tenant_id="tenant-a", application_id="app-a", source_id="drive-a",
        ))
        chunks = await gateway.ingest("doc1")
        verifier = SourceAttestationVerifier(tenant_id="tenant-a", trusted_keys={"trusted-ingester": signing_key.public_key()})
        for chunk in chunks:
            verifier.verify(ContentBinding("tenant-a", "app-a", "drive-a", "doc1",
                                           chunk.chunk_id, chunk.content_version or "", chunk.content), chunk.content_attestation)
        return chunks, requests
    finally:
        await adapter._client.aclose()


@pytest.mark.asyncio
async def test_provider_fetched_text_is_signed_and_bound_to_provider_revision() -> None:
    resources, requests = await _run(content="résumé 🥑".encode())
    assert "".join(item.content for item in resources) == "résumé 🥑"
    assert requests["metadata"] == 2


@pytest.mark.asyncio
async def test_google_docs_provider_export_is_signed_and_version_bound() -> None:
    resources, requests = await _run(
        content="approved internal Google Doc résumé".encode("utf-8"),
        mime="application/vnd.google-apps.document",
    )
    assert "Google Doc" in "".join(chunk.content for chunk in resources)
    assert requests["metadata"] == 2


@pytest.mark.asyncio
async def test_google_docs_export_changed_while_fetching_fails_closed() -> None:
    with pytest.raises(IngestionError, match="changed during"):
        await _run(mime="application/vnd.google-apps.document", version_change=True)


@pytest.mark.asyncio
async def test_version_changed_while_fetching_fails_closed() -> None:
    with pytest.raises(IngestionError, match="changed during"):
        await _run(version_change=True)


@pytest.mark.asyncio
async def test_source_content_larger_than_limit_never_signed() -> None:
    with pytest.raises(IngestionError, match="size limit"):
        await _run(oversized=True)


@pytest.mark.asyncio
async def test_unsupported_google_drive_mime_type_is_rejected() -> None:
    with pytest.raises(IngestionError, match="unsupported"):
        await _run(mime="application/pdf")


@pytest.mark.asyncio
async def test_invalid_provider_bytes_are_not_attested() -> None:
    with pytest.raises(IngestionError, match="valid UTF-8"):
        await _run(content=b"\xff\xfe")


@pytest.mark.asyncio
async def test_google_drive_in_scope_is_required() -> None:
    transport, _ = _make_transport()
    adapter = GoogleDriveAdapter(access_token="synthetic", test_root_folder_id="another-root")
    await adapter._client.aclose()
    adapter._client = httpx.AsyncClient(transport=transport)
    try:
        signer = TrustedSourceIngestor(SourceAttestationSigner(
            key_id="key", private_key=Ed25519PrivateKey.generate()
        ))
        ingester = GoogleDriveTrustedIngestion(adapter, signer, GoogleDriveIngestionSettings(
            tenant_id="tenant-a", application_id="app-a", source_id="source-a",
        ))
        with pytest.raises(IngestionError, match="outside"):
            await ingester.ingest("doc1")
    finally:
        await adapter._client.aclose()
