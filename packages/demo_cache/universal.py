"""Signed AccessProof answer-cache storage with interchangeable cache backends.

Security rules are inherited from the existing verified signed Redis cache:
no unsigned answers, no missing dependencies, no historical-allow reuse.
Storage adapters alone do not intercept arbitrary RAG response paths.
"""
from __future__ import annotations

from typing import Any
from dataclasses import dataclass

from packages.rag_sdk.protection import ProtectedResponse, ProtectedRAG
from packages.rag_sdk.cache_backends import CacheBackend, CacheBackendError
from packages.demo_cache.protected_cache import SignedRedisAnswerCache


class _BackendRedisCompatibility:
    """Reuse the audited signed-manifest implementation without copying logic."""

    def __init__(self, backend: CacheBackend) -> None:
        self.backend = backend

    def get(self, key: str) -> bytes | None:
        return self.backend.get(key)

    def setex(self, key: str, seconds: int, value: str) -> bool:
        if not isinstance(value, str):
            raise CacheBackendError("CACHE_VALUE_INVALID")
        self.backend.set(key, value.encode("utf-8"), seconds)
        return True

    def ping(self) -> bool:
        return self.backend.ping()

    def delete(self, key: str) -> None:
        self.backend.delete(key)


@dataclass(frozen=True)
class AuthorizedCacheHit:
    """The only user-facing response value safe to expose after a cache hit."""
    decision: str
    answer: str | None
    reason: str
    citations: tuple[str, ...] = ()
    authorization_revision: int | None = None
    authorization_revision_hash: str | None = None


class SignedBackendAnswerCache(SignedRedisAnswerCache):
    """Signed answer cache parameterized by any CacheBackend.

    Always call ProtectedRAG.verify_cached_answer with the employee's current
    verified token after a load and before releasing text. A backing cache
    connector alone cannot authorize an answer.
    """

    def __init__(self, *, backend: CacheBackend, **kwargs: Any) -> None:
        self.backend = backend
        super().__init__(redis_client=_BackendRedisCompatibility(backend), **kwargs)

    def ping(self) -> bool:
        return self.backend.ping()

    def invalidate(self, question: str) -> None:
        self.backend.delete(self._key(question))

    def authorize_hit(self, *, question: str, employee_token: str,
                      guard: Any, request_id: str | None = None) -> AuthorizedCacheHit | None:
        """Check one cache hit using both Guard layers before exposing text.

        Returns None only for a genuine cache miss. Any malformed entry,
        revoked permission or backend exception fails closed and never yields
        the cached answer. No historical Guard decision is reused.
        """
        if not employee_token or not isinstance(employee_token, str):
            return AuthorizedCacheHit("block", None, "CACHE_EMPLOYEE_TOKEN_REQUIRED")
        try:
            loaded = self.load(question)
            if loaded is None:
                return None
            manifest, token = loaded
            result: ProtectedResponse = ProtectedRAG(
                guard, provenance_verifier=self.source_verifier,
            ).verify_cached_answer(
                employee_token=employee_token,
                application_id=self.application_id,
                manifest=manifest, manifest_token=token,
                manifest_verifier=self.verifier, request_id=request_id,
            )
            if result.decision != "allow" or result.response is None:
                return AuthorizedCacheHit("block", None, result.reason)
            return AuthorizedCacheHit(
                "allow", result.response, result.reason,
                citations=tuple(dep.resource_id for dep in manifest.dependencies),
                authorization_revision=result.authorization_revision,
                authorization_revision_hash=result.authorization_revision_hash,
            )
        except Exception:
            # Cache or Guard failures must never fall back to an unchecked
            # answer, nor include raw customer data in error details.
            return AuthorizedCacheHit("block", None, "CACHE_PROTECTION_FAILED")
