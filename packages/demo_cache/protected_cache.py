"""Reference Redis answer cache whose hits MUST pass fresh Guard decisions.

This is not a universal cache interceptor. Only the explicitly integrated
employee-facing route may read from this cache; no raw unguarded GET endpoint
is exposed. The trusted generation backend owns the manifest signing key.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import Any

from packages.rag_sdk import (
    CacheDependency, CachedAnswerManifest, CachedAnswerManifestSigner,
    CachedAnswerManifestVerifier, ContentBinding, RetrievedResource,
    SourceAttestationVerifier,
)


class CacheIntegrityError(ValueError):
    pass


class SignedRedisAnswerCache:
    def __init__(self, *, redis_client: Any, tenant_id: str, application_id: str,
                 signer: CachedAnswerManifestSigner,
                 verifier: CachedAnswerManifestVerifier,
                 source_verifier: SourceAttestationVerifier,
                 ttl_seconds: int = 300, max_entry_bytes: int = 1_000_000) -> None:
        if not 1 <= ttl_seconds <= 3600 or max_entry_bytes <= 0:
            raise CacheIntegrityError("INVALID_CACHE_LIMITS")
        if source_verifier.tenant_id != tenant_id or verifier.tenant_id != tenant_id:
            raise CacheIntegrityError("CACHE_TENANT_MISMATCH")
        self.redis = redis_client
        self.tenant_id = tenant_id
        self.application_id = application_id
        self.signer = signer
        self.verifier = verifier
        self.source_verifier = source_verifier
        self.ttl_seconds = ttl_seconds
        self.max_entry_bytes = max_entry_bytes

    def _key(self, question: str) -> str:
        # Tenant/application-qualified digest; never assume one user's previous
        # allow remains valid for another user on this cache entry.
        digest = hashlib.sha256(json.dumps(
            [self.tenant_id, self.application_id, question],
            ensure_ascii=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        return f"accessproof:v3:answer:{digest}"

    def load(self, question: str) -> tuple[CachedAnswerManifest, str] | None:
        raw = self.redis.get(self._key(question))
        if raw is None:
            return None
        if not isinstance(raw, (bytes, str)) or len(raw) > self.max_entry_bytes:
            raise CacheIntegrityError("CACHE_ENTRY_OVERSIZE_OR_INVALID")
        try:
            record = json.loads(raw)
            required = {"answer", "dependencies", "producer", "manifest_token"}
            revision_fields = {"authorization_revision", "authorization_revision_hash"}
            if (not isinstance(record, dict)
                    or not required.issubset(record)
                    or not set(record).issubset(required | revision_fields)):
                raise ValueError("Invalid cache record")
            deps = record["dependencies"]
            if not isinstance(deps, list) or not 1 <= len(deps) <= 50:
                raise ValueError("Incomplete cache dependencies")
            if not isinstance(record["answer"], str) or not isinstance(record["manifest_token"], str):
                raise ValueError("Invalid answer or manifest")
            dependencies = tuple(CacheDependency(**dependency) for dependency in deps)
            return CachedAnswerManifest(
                tenant_id=self.tenant_id, application_id=self.application_id,
                answer=record["answer"], dependencies=dependencies,
                producer_id=record["producer"],
                authorization_revision=record.get("authorization_revision"),
                authorization_revision_hash=record.get("authorization_revision_hash"),
            ), record["manifest_token"]
        except (ValueError, TypeError, KeyError) as exc:
            raise CacheIntegrityError("CACHE_ENTRY_INVALID") from exc

    def store(self, question: str, answer: str, authorized: list[RetrievedResource],
              authorization_revision: int | None = None,
              authorization_revision_hash: str | None = None) -> None:
        if not authorized or len(authorized) > 50:
            raise CacheIntegrityError("CACHE_DEPENDENCIES_INCOMPLETE")
        dependencies: list[CacheDependency] = []
        for item in authorized:
            if not item.content_version or not item.content_attestation:
                raise CacheIntegrityError("CACHE_SOURCE_ATTESTATION_MISSING")
            # Trusted ingestion attestation must bind the exact source bytes.
            binding = ContentBinding(
                tenant_id=self.tenant_id, application_id=self.application_id,
                source_id=item.source_id, resource_id=item.resource_id,
                chunk_id=item.chunk_id, content_version=item.content_version,
                content=item.content,
            )
            self.source_verifier.verify(binding, item.content_attestation)
            dependencies.append(CacheDependency(
                source_id=item.source_id, resource_id=item.resource_id,
                chunk_id=item.chunk_id, content_version=item.content_version,
                content_digest=hashlib.sha256(item.content.encode("utf-8")).hexdigest(),
                content_attestation=item.content_attestation,
            ))
        manifest = CachedAnswerManifest(
            tenant_id=self.tenant_id, application_id=self.application_id,
            answer=answer, dependencies=tuple(dependencies),
            producer_id="protected-drive-reference-rag",
            authorization_revision=authorization_revision,
            authorization_revision_hash=authorization_revision_hash,
        )
        token = self.signer.issue(manifest, ttl_seconds=self.ttl_seconds)
        record: dict[str, Any] = {
            "answer": answer, "dependencies": [asdict(dep) for dep in dependencies],
            "producer": manifest.producer_id, "manifest_token": token,
        }
        if authorization_revision is not None:
            record["authorization_revision"] = authorization_revision
            record["authorization_revision_hash"] = authorization_revision_hash
        serialized = json.dumps(record, separators=(",", ":"), sort_keys=True)
        if len(serialized.encode("utf-8")) > self.max_entry_bytes:
            raise CacheIntegrityError("CACHE_ENTRY_OVERSIZE_OR_INVALID")
        self.redis.setex(self._key(question), self.ttl_seconds, serialized)
