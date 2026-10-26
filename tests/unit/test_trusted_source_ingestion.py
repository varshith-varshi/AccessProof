from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from packages.rag_sdk import (
    ContentBinding, IngestionError, SourceAttestationSigner,
    SourceAttestationVerifier, TrustedSourceIngestor, VerifiedSourceDocument,
)


def _document(**changes: object) -> VerifiedSourceDocument:
    values: dict[str, object] = {
        "tenant_id": "tenant-a", "application_id": "rag-a", "source_id": "drive-a",
        "resource_id": "file-a", "content_version": "42", "content": "trusted source text",
        "provider_identity_verified": True,
    }
    values.update(changes)
    return VerifiedSourceDocument(**values)  # type: ignore[arg-type]


def test_authenticated_provider_document_is_chunked_and_attested() -> None:
    private = Ed25519PrivateKey.generate()
    signer = SourceAttestationSigner(key_id="current", private_key=private)
    resources = TrustedSourceIngestor(signer, chunk_bytes=7).attest_document(_document())
    verifier = SourceAttestationVerifier(tenant_id="tenant-a", trusted_keys={"current": private.public_key()})
    assert len(resources) > 1
    for resource in resources:
        verifier.verify(ContentBinding("tenant-a", "rag-a", "drive-a", "file-a", resource.chunk_id, "42", resource.content), resource.content_attestation)


@pytest.mark.parametrize("changes", [
    {"provider_identity_verified": False}, {"deleted": True}, {"content": ""},
])
def test_unverified_deleted_or_empty_provider_content_is_not_attested(changes: dict[str, object]) -> None:
    signer = SourceAttestationSigner(key_id="current", private_key=Ed25519PrivateKey.generate())
    with pytest.raises(IngestionError):
        TrustedSourceIngestor(signer).attest_document(_document(**changes))


@pytest.mark.parametrize("chunk_bytes", [1, 2, 3, 4, 7])
def test_ingestion_preserves_multibyte_unicode_at_every_split(chunk_bytes: int) -> None:
    signer = SourceAttestationSigner(key_id="unicode", private_key=Ed25519PrivateKey.generate())
    original = "é € 🧑🏽‍💻 العربية हिंदी Ελληνικά"
    resources = TrustedSourceIngestor(signer, chunk_bytes=chunk_bytes).attest_document(
        _document(content=original)
    )
    assert "".join(chunk.content for chunk in resources) == original
    assert all(chunk.content for chunk in resources)
    # UTF-8 character boundaries can extend the configured byte budget by
    # at most 3 bytes. No chunk can be half a codepoint.
    assert all(len(chunk.content.encode("utf-8")) <= chunk_bytes + 3 for chunk in resources)
