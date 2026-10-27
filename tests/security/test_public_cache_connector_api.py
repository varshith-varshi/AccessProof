"""Customer SDK only releases freshly authorized signed answer cache hits."""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from packages.rag_core import (
    CachedAnswerManifestSigner, CachedAnswerManifestVerifier,
    ContentBinding, RetrievedResource, SourceAttestationSigner,
    SourceAttestationVerifier,
)
from packages.rag_core.cache_connectors import MemoryBackend, ProtectedAnswerCache
from packages.rag_core.protection import ProtectedResponse


def test_public_connector_sdk_prevents_direct_cached_answer_bypass():
    src_key = Ed25519PrivateKey.generate()
    cache_key = Ed25519PrivateKey.generate()
    source = ContentBinding(
        "tenant", "application", "drive-source", "drive-file", "chunk-1",
        "v1", "secret document text",
    )
    attested = SourceAttestationSigner(key_id="ingest", private_key=src_key).issue(source)
    document = RetrievedResource(
        source_id=source.source_id, resource_id=source.resource_id,
        chunk_id=source.chunk_id, content=source.content,
        content_version=source.content_version, content_attestation=attested,
    )

    class Guard:
        allow = True
        def filter_resources(self, **kwargs):
            return {
                "mode": "protect", "decision_id": "decision",
                "decision": "allow" if self.allow else "block",
                "allowed": [{
                    "source_id": document.source_id,
                    "resource_id": document.resource_id,
                    "chunk_ids": [document.chunk_id],
                }] if self.allow else [],
            }
        def check_output(self, **kwargs):
            return {"decision": "allow", "reason": "OK"}

    guard = Guard()
    protected = ProtectedAnswerCache(
        backend=MemoryBackend(), guard=guard,
        tenant_id="tenant", application_id="application",
        signer=CachedAnswerManifestSigner(
            key_id="cache", private_key=cache_key,
        ),
        verifier=CachedAnswerManifestVerifier(
            tenant_id="tenant", trusted_keys={"cache": cache_key.public_key()},
        ),
        source_verifier=SourceAttestationVerifier(
            tenant_id="tenant", trusted_keys={"ingest": src_key.public_key()},
        ),
    )
    with pytest.raises(Exception, match="UNAPPROVED_ANSWER_CANNOT_BE_CACHED"):
        protected.store_approved(
            question="Q", protection=ProtectedResponse("block", None, "denied"),
            authorized_sources=[document],
        )
    protected.store_approved(
        question="Q", protection=ProtectedResponse("allow", "approved answer", "OK"),
        authorized_sources=[document],
    )
    initial = protected.get_authorized(question="Q", employee_token="employee")
    assert initial is not None and initial.decision == "allow"
    assert initial.answer == "approved answer"
    guard.allow = False
    after_revoke = protected.get_authorized(question="Q", employee_token="employee")
    assert after_revoke is not None and after_revoke.decision == "block"
    assert after_revoke.answer is None
    assert not hasattr(protected, "load")
