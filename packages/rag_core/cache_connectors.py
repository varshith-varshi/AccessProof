"""Public Python integration point for protected AccessProof answer caches.

Storage adapters: Redis, Memcached, PostgreSQL, Python memory and callbacks.
All cache hits MUST be freshly authorized using a customer-side Guard in
Protect mode. Nothing in this module auto-intercepts arbitrary RAG routes.
"""
from __future__ import annotations

from typing import Any

from packages.demo_cache.universal import AuthorizedCacheHit, SignedBackendAnswerCache
from packages.rag_core.cache_backends import (
    CacheBackend, CacheBackendError, CallbackBackend, MemcachedBackend,
    MemoryBackend, RedisBackend, SQLAlchemyBackend,
)
from packages.rag_core.protection import ProtectedResponse, RetrievedResource


class ProtectedAnswerCache:
    """High-level safe cache interface for an integrated Python RAG route.

    Only get_authorized returns an answer, after fresh source authorization
    for the requesting employee. Raw cache reads are not public methods.
    """

    def __init__(self, *, backend: CacheBackend, guard: Any, **security: Any) -> None:
        self._signed = SignedBackendAnswerCache(backend=backend, **security)
        self._guard = guard

    def get_authorized(self, *, question: str, employee_token: str,
                       request_id: str | None = None) -> AuthorizedCacheHit | None:
        return self._signed.authorize_hit(
            question=question, employee_token=employee_token,
            guard=self._guard, request_id=request_id,
        )

    def store_approved(self, *, question: str, protection: ProtectedResponse,
                       authorized_sources: list[RetrievedResource]) -> None:
        """Store only approved results using exact source-attested dependencies.

        Customer integration must pass the precise Guard-authorized resources
        consumed during generation, never raw unfiltered retrieval candidates.
        """
        if protection.decision != "allow" or protection.response is None:
            raise CacheBackendError("UNAPPROVED_ANSWER_CANNOT_BE_CACHED")
        self._signed.store(
            question, protection.response, authorized_sources,
            authorization_revision=protection.authorization_revision,
            authorization_revision_hash=protection.authorization_revision_hash,
        )

    def invalidate(self, question: str) -> None:
        self._signed.invalidate(question)

    def healthy(self) -> bool:
        return self._signed.ping()


__all__ = [
    "ProtectedAnswerCache", "AuthorizedCacheHit", "CacheBackend",
    "CacheBackendError", "RedisBackend", "MemcachedBackend",
    "SQLAlchemyBackend", "MemoryBackend", "CallbackBackend",
]
