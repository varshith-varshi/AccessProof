"""Answers and cache entries must stay bound to the Guard's current revision."""
from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from packages.demo_cache.universal import SignedBackendAnswerCache
from packages.rag_core import (
    CacheDependency, CachedAnswerManifest, CachedAnswerManifestSigner,
    CachedAnswerManifestVerifier, ContentBinding, ProtectedRAG,
    RetrievedResource, SourceAttestationSigner, SourceAttestationVerifier,
)
from packages.rag_core.cache_backends import MemoryBackend

REVISION_HASH = "a" * 64
NEXT_REVISION_HASH = "b" * 64


class RevisionGuard:
    def __init__(self, *, revision: int | None = 1, revision_hash: str | None = REVISION_HASH,
                 layer2_revision: int | None = None,
                 layer2_revision_hash: str | None = None) -> None:
        self.revision = revision
        self.revision_hash = revision_hash
        self.layer2_revision = layer2_revision
        self.layer2_revision_hash = layer2_revision_hash
        self.calls: list[str] = []

    def filter_resources(self, **kwargs):
        self.calls.append("layer1")
        resources = kwargs["resources"]
        response = {
            "mode": "protect", "decision_id": "d1", "decision": "allow",
            "allowed": [{
                "source_id": item.source_id, "resource_id": item.resource_id,
                "chunk_ids": [item.chunk_id] if item.chunk_id else [],
            } for item in resources],
        }
        if self.revision is not None:
            response["authorization_revision"] = self.revision
            response["authorization_revision_hash"] = self.revision_hash
        return response

    def check_output(self, **kwargs):
        self.calls.append("layer2")
        response = {"decision": "allow", "reason": "CURRENTLY_AUTHORIZED"}
        if self.layer2_revision is not None:
            response["authorization_revision"] = self.layer2_revision
            response["authorization_revision_hash"] = self.layer2_revision_hash
        return response


def _fixtures(*, revision: int | None = 1, revision_hash: str | None = REVISION_HASH):
    source_private = Ed25519PrivateKey.generate()
    cache_private = Ed25519PrivateKey.generate()
    content = "approved synthetic text"
    binding = ContentBinding(
        "tenant-a", "rag", "source-a", "document-a", "chunk-a", "1", content,
    )
    dependency = CacheDependency(
        source_id="source-a", resource_id="document-a", chunk_id="chunk-a",
        content_version="1",
        content_digest=hashlib.sha256(content.encode()).hexdigest(),
        content_attestation=SourceAttestationSigner(
            key_id="source-key", private_key=source_private,
        ).issue(binding),
    )
    manifest = CachedAnswerManifest(
        tenant_id="tenant-a", application_id="rag", answer="approved answer",
        dependencies=(dependency,), producer_id="synthetic-writer",
        authorization_revision=revision,
        authorization_revision_hash=revision_hash,
    )
    signer = CachedAnswerManifestSigner(key_id="cache-key", private_key=cache_private)
    return (
        manifest,
        signer.issue(manifest),
        SourceAttestationVerifier(
            tenant_id="tenant-a",
            trusted_keys={"source-key": source_private.public_key()},
        ),
        CachedAnswerManifestVerifier(
            tenant_id="tenant-a",
            trusted_keys={"cache-key": cache_private.public_key()},
        ),
        dependency,
        signer,
    )


def test_cache_hit_carries_the_exact_current_revision():
    manifest, token, source_verifier, cache_verifier, *_ = _fixtures()
    result = ProtectedRAG(
        RevisionGuard(), provenance_verifier=source_verifier,
    ).verify_cached_answer(
        employee_token="employee", application_id="rag", manifest=manifest,
        manifest_token=token, manifest_verifier=cache_verifier,
    )
    assert result.decision == "allow"
    assert result.response == "approved answer"
    assert result.authorization_revision == 1
    assert result.authorization_revision_hash == REVISION_HASH


def test_cache_hit_without_revision_binding_is_blocked_when_guard_requires_one():
    manifest, token, source_verifier, cache_verifier, *_ = _fixtures(
        revision=None, revision_hash=None,
    )
    guard = RevisionGuard()
    result = ProtectedRAG(
        guard, provenance_verifier=source_verifier,
    ).verify_cached_answer(
        employee_token="employee", application_id="rag", manifest=manifest,
        manifest_token=token, manifest_verifier=cache_verifier,
    )
    assert result.decision == "block"
    assert result.reason == "CACHE_REVISION_BINDING_REQUIRED"
    assert result.response is None
    assert guard.calls == ["layer1"]


def test_cache_hit_from_an_older_revision_is_never_released():
    manifest, token, source_verifier, cache_verifier, *_ = _fixtures()
    guard = RevisionGuard(revision=2, revision_hash=NEXT_REVISION_HASH)
    result = ProtectedRAG(
        guard, provenance_verifier=source_verifier,
    ).verify_cached_answer(
        employee_token="employee", application_id="rag", manifest=manifest,
        manifest_token=token, manifest_verifier=cache_verifier,
    )
    assert result.decision == "block"
    assert result.reason == "CACHE_AUTHORIZATION_REVISION_STALE"
    assert result.response is None
    assert guard.calls == ["layer1"]


def test_revision_change_between_layer1_and_layer2_blocks_generation_release():
    guard = RevisionGuard(
        revision=1, revision_hash=REVISION_HASH,
        layer2_revision=2, layer2_revision_hash=NEXT_REVISION_HASH,
    )
    result = ProtectedRAG(guard, allow_unattested_metadata=True).run(
        employee_token="employee", application_id="rag",
        request_id="revision-race",
        retrieved=[RetrievedResource("source-a", "document-a", "chunk-a", "text")],
        generate=lambda _: "must not be released",
        source_trace=lambda: [RetrievedResource("source-a", "document-a", "chunk-a", "text")],
    )
    assert result.decision == "block"
    assert result.reason == "AUTHORIZATION_REVISION_CHANGED"
    assert result.response is None


def test_fresh_generation_revision_is_signed_into_cache_and_rechecked():
    manifest, token, source_verifier, cache_verifier, dependency, signer = _fixtures()
    cache = SignedBackendAnswerCache(
        backend=MemoryBackend(), tenant_id="tenant-a", application_id="rag",
        signer=signer, verifier=cache_verifier, source_verifier=source_verifier,
    )
    resource = RetrievedResource(
        source_id=dependency.source_id, resource_id=dependency.resource_id,
        chunk_id=dependency.chunk_id, content="approved synthetic text",
        content_version=dependency.content_version,
        content_attestation=dependency.content_attestation,
    )
    generated = ProtectedRAG(
        RevisionGuard(), provenance_verifier=source_verifier,
    ).run(
        employee_token="employee", application_id="rag", request_id="revision-write",
        retrieved=[resource], generate=lambda _: "approved answer",
        source_trace=lambda: [resource],
    )
    assert generated.decision == "allow"
    assert generated.response is not None
    assert generated.authorization_revision == 1
    cache.store(
        "question", generated.response, [resource],
        authorization_revision=generated.authorization_revision,
        authorization_revision_hash=generated.authorization_revision_hash,
    )
    loaded = cache.load("question")
    assert loaded is not None
    assert loaded[0].authorization_revision == 1
    allowed = cache.authorize_hit(
        question="question", employee_token="employee", guard=RevisionGuard(),
    )
    assert allowed is not None and allowed.decision == "allow"
    assert allowed.authorization_revision == 1
    stale = cache.authorize_hit(
        question="question", employee_token="employee",
        guard=RevisionGuard(revision=2, revision_hash=NEXT_REVISION_HASH),
    )
    assert stale is not None and stale.decision == "block"
    assert stale.answer is None


def test_signed_manifest_cannot_claim_a_different_revision_than_its_token():
    manifest, _token, source_verifier, cache_verifier, _dependency, signer = _fixtures()
    other_manifest = CachedAnswerManifest(
        tenant_id=manifest.tenant_id, application_id=manifest.application_id,
        answer=manifest.answer, dependencies=manifest.dependencies,
        producer_id=manifest.producer_id,
        authorization_revision=2, authorization_revision_hash=NEXT_REVISION_HASH,
    )
    other_token = signer.issue(other_manifest)
    guard = RevisionGuard(revision=2, revision_hash=NEXT_REVISION_HASH)
    result = ProtectedRAG(
        guard, provenance_verifier=source_verifier,
    ).verify_cached_answer(
        employee_token="employee", application_id="rag", manifest=manifest,
        manifest_token=other_token, manifest_verifier=cache_verifier,
    )
    assert result.decision == "block"
    assert result.reason == "CACHE_MANIFEST_INVALID"
    assert guard.calls == []


@pytest.mark.parametrize("revision, revision_hash", [(1, None), (None, REVISION_HASH)])
def test_manifest_rejects_incomplete_revision_binding(revision, revision_hash):
    with pytest.raises(ValueError, match="revision binding"):
        CachedAnswerManifest(
            tenant_id="tenant-a", application_id="rag", answer="answer",
            dependencies=(CacheDependency(
                source_id="source-a", resource_id="document-a", chunk_id=None,
                content_version="1", content_digest="0" * 64,
                content_attestation="attestation",
            ),),
            producer_id="writer",
            authorization_revision=revision,
            authorization_revision_hash=revision_hash,
        )
