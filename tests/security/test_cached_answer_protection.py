"""Cached answers need fresh employee authorization and signed full provenance."""
from __future__ import annotations

import hashlib
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from packages.rag_sdk import (
    CacheDependency, CachedAnswerManifest, CachedAnswerManifestSigner,
    CachedAnswerManifestVerifier, ContentBinding, ProtectedRAG,
    SourceAttestationSigner, SourceAttestationVerifier,
)


class CacheGuard:
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls: list[str] = []

    def filter_resources(self, **kwargs):
        self.calls.append("layer1")
        resources = kwargs["resources"]
        return {
            "mode": "protect", "decision": "allow" if self.allowed else "block", "decision_id": "d1",
            "allowed": ([{"source_id": r.source_id, "resource_id": r.resource_id,
                          "chunk_ids": [r.chunk_id] if r.chunk_id else []} for r in resources]
                        if self.allowed else []),
        }

    def check_output(self, **kwargs):
        self.calls.append("layer2")
        return {"decision": "allow", "reason": "CACHE_CURRENTLY_AUTHORIZED"}


def _manifest():
    source_private = Ed25519PrivateKey.generate()
    cache_private = Ed25519PrivateKey.generate()
    source_signer = SourceAttestationSigner(key_id="source-v1", private_key=source_private)
    content = "private quarterly revenue"
    binding = ContentBinding(
        tenant_id="tenant-a", application_id="rag", source_id="drive-a",
        resource_id="report-7", chunk_id="chunk-1", content_version="42", content=content,
    )
    dependency = CacheDependency(
        source_id="drive-a", resource_id="report-7", chunk_id="chunk-1", content_version="42",
        content_digest=hashlib.sha256(content.encode()).hexdigest(),
        content_attestation=source_signer.issue(binding),
    )
    manifest = CachedAnswerManifest(
        tenant_id="tenant-a", application_id="rag", answer="Revenue is confidential.",
        dependencies=(dependency,), producer_id="trusted-rag-cache-writer",
    )
    return (
        manifest,
        CachedAnswerManifestSigner(key_id="cache-v1", private_key=cache_private).issue(manifest),
        SourceAttestationVerifier(tenant_id="tenant-a", trusted_keys={"source-v1": source_private.public_key()}),
        CachedAnswerManifestVerifier(tenant_id="tenant-a", trusted_keys={"cache-v1": cache_private.public_key()}),
    )


def test_authorized_employee_can_receive_signed_cache_hit():
    manifest, token, source_verifier, cache_verifier = _manifest()
    guard = CacheGuard()
    result = ProtectedRAG(guard, provenance_verifier=source_verifier).verify_cached_answer(
        employee_token="employee", application_id="rag", manifest=manifest,
        manifest_token=token, manifest_verifier=cache_verifier,
    )
    assert result.decision == "allow"
    assert result.response == manifest.answer
    assert guard.calls == ["layer1", "layer2"]


def test_revoked_employee_cannot_reuse_another_employees_cached_answer():
    manifest, token, source_verifier, cache_verifier = _manifest()
    guard = CacheGuard(allowed=False)
    result = ProtectedRAG(guard, provenance_verifier=source_verifier).verify_cached_answer(
        employee_token="revoked-employee", application_id="rag", manifest=manifest,
        manifest_token=token, manifest_verifier=cache_verifier,
    )
    assert result.decision == "block"
    assert result.response is None
    assert guard.calls == ["layer1"]


def test_tampered_answer_or_cross_application_manifest_fails_before_guard():
    manifest, token, source_verifier, cache_verifier = _manifest()
    guard = CacheGuard()
    tampered = CachedAnswerManifest(
        tenant_id=manifest.tenant_id, application_id=manifest.application_id,
        answer="substituted answer", dependencies=manifest.dependencies, producer_id=manifest.producer_id,
    )
    result = ProtectedRAG(guard, provenance_verifier=source_verifier).verify_cached_answer(
        employee_token="employee", application_id="rag", manifest=tampered,
        manifest_token=token, manifest_verifier=cache_verifier,
    )
    assert result.decision == "block"
    assert result.reason == "CACHE_MANIFEST_INVALID"
    assert guard.calls == []


def test_cross_tenant_replay_and_expired_manifest_fail_closed_before_guard():
    manifest, _token, source_verifier, cache_verifier = _manifest()
    cache_private = Ed25519PrivateKey.generate()
    token = CachedAnswerManifestSigner(key_id="replay-key", private_key=cache_private).issue(
        manifest, ttl_seconds=1, now=10,
    )
    expired_verifier = CachedAnswerManifestVerifier(
        tenant_id="tenant-a", trusted_keys={"replay-key": cache_private.public_key()},
    )
    guard = CacheGuard()
    expired = ProtectedRAG(guard, provenance_verifier=source_verifier).verify_cached_answer(
        employee_token="employee", application_id="rag", manifest=manifest,
        manifest_token=token, manifest_verifier=expired_verifier,
    )
    assert expired.decision == "block"
    assert guard.calls == []

    tenant_replay_key = Ed25519PrivateKey.generate()
    tenant_replay_token = CachedAnswerManifestSigner(
        key_id="tenant-replay", private_key=tenant_replay_key,
    ).issue(manifest)
    wrong_tenant = CachedAnswerManifestVerifier(
        tenant_id="tenant-b", trusted_keys={"tenant-replay": tenant_replay_key.public_key()},
    )
    replay = ProtectedRAG(guard, provenance_verifier=source_verifier).verify_cached_answer(
        employee_token="employee", application_id="rag", manifest=manifest,
        manifest_token=tenant_replay_token, manifest_verifier=wrong_tenant,
    )
    assert replay.decision == "block"
    assert guard.calls == []


def test_signed_cache_hit_respects_response_byte_limit():
    manifest, token, source_verifier, cache_verifier = _manifest()
    guard = CacheGuard()
    result = ProtectedRAG(
        guard, max_response_bytes=10, provenance_verifier=source_verifier,
    ).verify_cached_answer(
        employee_token="employee", application_id="rag", manifest=manifest,
        manifest_token=token, manifest_verifier=cache_verifier,
    )
    assert result.decision == "block"
    assert result.reason == "CACHE_RESPONSE_TOO_LARGE"
    assert result.response is None
    assert guard.calls == []


def _signed_with(manifest: CachedAnswerManifest):
    private = Ed25519PrivateKey.generate()
    signer = CachedAnswerManifestSigner(key_id="cache-test", private_key=private)
    verifier = CachedAnswerManifestVerifier(
        tenant_id="tenant-a", trusted_keys={"cache-test": private.public_key()},
    )
    return signer.issue(manifest), verifier


def test_cache_hit_with_forged_dependency_digest_blocks_before_guard():
    manifest, _token, source_verifier, _cache_verifier = _manifest()
    forged_dependency = replace(manifest.dependencies[0], content_digest="0" * 64)
    forged = replace(manifest, dependencies=(forged_dependency,))
    token, cache_verifier = _signed_with(forged)
    guard = CacheGuard()
    result = ProtectedRAG(guard, provenance_verifier=source_verifier).verify_cached_answer(
        employee_token="employee", application_id="rag", manifest=forged,
        manifest_token=token, manifest_verifier=cache_verifier,
    )
    assert result.decision == "block"
    assert result.reason == "CACHE_MANIFEST_INVALID"
    assert result.response is None
    assert guard.calls == []


def test_malformed_dependency_provenance_blocks_before_guard():
    manifest, _token, source_verifier, _cache_verifier = _manifest()
    malformed_dependency = replace(
        manifest.dependencies[0], content_attestation="not-a-valid-attestation",
    )
    malformed = replace(manifest, dependencies=(malformed_dependency,))
    token, cache_verifier = _signed_with(malformed)
    guard = CacheGuard()
    result = ProtectedRAG(guard, provenance_verifier=source_verifier).verify_cached_answer(
        employee_token="employee", application_id="rag", manifest=malformed,
        manifest_token=token, manifest_verifier=cache_verifier,
    )
    assert result.decision == "block"
    assert result.reason == "CACHE_MANIFEST_INVALID"
    assert result.response is None
    assert guard.calls == []


def test_cache_hit_without_trusted_source_verifier_is_blocked():
    manifest, token, _source_verifier, cache_verifier = _manifest()
    guard = CacheGuard()
    result = ProtectedRAG(guard).verify_cached_answer(
        employee_token="employee", application_id="rag", manifest=manifest,
        manifest_token=token, manifest_verifier=cache_verifier,
    )
    assert result.decision == "block"
    assert result.reason == "CACHE_MANIFEST_BINDING_REQUIRED"
    assert result.response is None
    assert guard.calls == []
