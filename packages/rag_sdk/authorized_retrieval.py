"""Authorization-first vector retrieval for security-sensitive RAG routes.

The retrieval order is part of the authorization boundary:

    verified principal
    -> allowed resource scope
    -> datastore authorization predicate
    -> ANN search inside that scope
    -> iterative/bounded overfetch
    -> exact authorized fallback
    -> fresh Layer 1 authorization of the final context

A global ANN top-k followed by a post-filter can silently starve an employee of
documents they are entitled to access whenever denied documents crowd the
candidate window.  This module never issues an unscoped search.  It also fails
closed on a truncated scope, a backend that returns out-of-scope identifiers, a
Guard revision change, or any partial Layer 1 denial.

Retrieved context still flows through ``ProtectedRAG.run`` before generation
release, so Layer 1 and Layer 2 remain mandatory for the final answer.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import uuid4

import httpx

from .protection import (
    RetrievedResource, authorization_revision_binding, authorized_resources,
)


class ScopeError(ValueError):
    """The Guard did not issue a complete, usable authorization scope."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class AuthorizationScope:
    tenant_id: str
    application_id: str
    source_id: str
    allowed_resource_ids: frozenset[str]
    decision_id: str
    mode: str
    revision: int | None = None
    revision_hash: str | None = None

    def __post_init__(self) -> None:
        if not all((self.tenant_id, self.application_id, self.source_id, self.decision_id)):
            raise ScopeError("AUTHORIZATION_SCOPE_INVALID")
        if self.mode not in {"protect", "shadow"}:
            raise ScopeError("AUTHORIZATION_SCOPE_INVALID")
        if any(not isinstance(value, str) or not value for value in self.allowed_resource_ids):
            raise ScopeError("AUTHORIZATION_SCOPE_INVALID")
        if (self.revision is None) != (self.revision_hash is None):
            raise ScopeError("AUTHORIZATION_SCOPE_INVALID")
        if self.revision is not None:
            if (not isinstance(self.revision, int) or isinstance(self.revision, bool)
                    or self.revision < 1 or not isinstance(self.revision_hash, str)
                    or len(self.revision_hash) != 64
                    or any(char not in "0123456789abcdef" for char in self.revision_hash)):
                raise ScopeError("AUTHORIZATION_SCOPE_INVALID")


class ScopedVectorBackend(Protocol):
    """Search implementation that applies the scope in the datastore.

    ``limit`` is a candidate bound, not a promise to return that many hits.
    ``exact=True`` requests an exact (index-bypassing) nearest-neighbour scan
    inside the same authorization predicate.
    """

    def search(
        self, *, scope: AuthorizationScope, query: Any, limit: int, exact: bool,
    ) -> Sequence[RetrievedResource]: ...


@dataclass(frozen=True)
class AuthorizedRetrievalResult:
    decision: str
    resources: tuple[RetrievedResource, ...]
    reason: str
    decision_id: str | None = None
    authorization_revision: int | None = None
    authorization_revision_hash: str | None = None
    ann_candidates: int = 0
    iterations: int = 0
    exact_fallback_used: bool = False
    starvation_detected: bool = False


class AuthorizedVectorRetriever:
    """Run ANN retrieval only inside a freshly Guard-issued resource scope."""

    def __init__(
        self, *, backend: ScopedVectorBackend, guard: Any, tenant_id: str,
        page_size: int = 20, max_scan_candidates: int = 200,
        min_results: int = 1, exact_fallback_limit: int = 200,
        max_results: int = 50,
    ) -> None:
        if not tenant_id:
            raise ValueError("tenant_id is required")
        if not 1 <= min_results <= max_results:
            raise ValueError("invalid result bounds")
        if not 1 <= page_size <= max_scan_candidates <= 10_000:
            raise ValueError("invalid candidate scan bounds")
        if not 0 <= exact_fallback_limit <= 10_000:
            raise ValueError("invalid exact fallback bound")
        self.backend = backend
        self.guard = guard
        self.tenant_id = tenant_id
        self.page_size = page_size
        self.max_scan_candidates = max_scan_candidates
        self.min_results = min_results
        self.exact_fallback_limit = exact_fallback_limit
        self.max_results = max_results

    def retrieve(
        self, *, employee_token: str, application_id: str, query: Any,
        request_id: str | None = None,
    ) -> AuthorizedRetrievalResult:
        if not isinstance(employee_token, str) or not employee_token:
            return AuthorizedRetrievalResult(
                "block", (), "AUTHORIZATION_SCOPE_REQUIRES_EMPLOYEE",
            )
        request_id = request_id or str(uuid4())
        try:
            raw_scope = self.guard.authorization_scope(
                employee_token=employee_token, application_id=application_id,
                request_id=request_id,
            )
        except httpx.HTTPError:
            return AuthorizedRetrievalResult("block", (), "AUTHORIZATION_SCOPE_UNAVAILABLE")
        except Exception:
            return AuthorizedRetrievalResult("block", (), "AUTHORIZATION_SCOPE_INVALID")
        try:
            scope = self._parse_scope(raw_scope, application_id)
        except ScopeError as exc:
            return AuthorizedRetrievalResult("block", (), exc.reason)
        except Exception:
            return AuthorizedRetrievalResult("block", (), "AUTHORIZATION_SCOPE_INVALID")
        if not scope.allowed_resource_ids:
            return AuthorizedRetrievalResult(
                "block", (), "NO_AUTHORIZED_RESOURCES", scope.decision_id,
                scope.revision, scope.revision_hash,
            )
        try:
            resources, ann_candidates, iterations, exact_used, starvation = (
                self._search_in_scope(scope=scope, query=query)
            )
        except ScopeError as exc:
            return AuthorizedRetrievalResult(
                "block", (), exc.reason, scope.decision_id,
                scope.revision, scope.revision_hash,
            )
        except Exception:
            # Never expose a backend's partial candidate set on failure.
            return AuthorizedRetrievalResult(
                "block", (), "RETRIEVAL_BACKEND_FAILED", scope.decision_id,
                scope.revision, scope.revision_hash,
            )
        if not resources:
            return AuthorizedRetrievalResult(
                "allow", (), "NO_AUTHORIZED_MATCHES", scope.decision_id,
                scope.revision, scope.revision_hash,
                ann_candidates, iterations, exact_used, starvation,
            )
        try:
            decision = self.guard.filter_resources(
                employee_token=employee_token, application_id=application_id,
                request_id=request_id, resources=list(resources),
            )
        except httpx.HTTPError:
            return AuthorizedRetrievalResult(
                "block", (), "RETRIEVAL_GUARD_UNAVAILABLE", scope.decision_id,
                scope.revision, scope.revision_hash,
            )
        except Exception:
            return AuthorizedRetrievalResult(
                "block", (), "RETRIEVAL_PROTECTION_FAILED", scope.decision_id,
                scope.revision, scope.revision_hash,
            )
        try:
            guard_revision, guard_revision_hash = authorization_revision_binding(decision)
            if decision.get("mode") != "protect" or decision.get("decision") != "allow":
                return AuthorizedRetrievalResult(
                    "block", (), "RETRIEVAL_GUARD_DENIED",
                    str(decision.get("decision_id") or ""),
                    guard_revision, guard_revision_hash,
                )
            if scope.revision is not None and guard_revision is None:
                return AuthorizedRetrievalResult(
                    "block", (), "AUTHORIZATION_REVISION_MISSING", scope.decision_id,
                    scope.revision, scope.revision_hash,
                )
            if scope.revision is None and guard_revision is not None:
                return AuthorizedRetrievalResult(
                    "block", (), "AUTHORIZATION_SCOPE_REVISION_MISSING", scope.decision_id,
                    guard_revision, guard_revision_hash,
                )
            if (scope.revision, scope.revision_hash) != (guard_revision, guard_revision_hash):
                return AuthorizedRetrievalResult(
                    "block", (), "AUTHORIZATION_REVISION_CHANGED", scope.decision_id,
                    guard_revision, guard_revision_hash,
                )
            authorized = authorized_resources(list(resources), decision)
        except (TypeError, ValueError):
            return AuthorizedRetrievalResult(
                "block", (), "RETRIEVAL_GUARD_INVALID", scope.decision_id,
                scope.revision, scope.revision_hash,
            )
        if len(authorized) != len(resources):
            # The scope was supposed to be exact. A partial denial means the
            # scope and Guard disagree, so do not release a silently narrowed
            # context; the caller must restart retrieval against a fresh scope.
            return AuthorizedRetrievalResult(
                "block", (), "RETRIEVAL_GUARD_PARTIAL_DENIAL", scope.decision_id,
                guard_revision, guard_revision_hash,
            )
        return AuthorizedRetrievalResult(
            "allow", tuple(authorized), "AUTHORIZED_CONTEXT",
            str(decision.get("decision_id") or scope.decision_id),
            guard_revision, guard_revision_hash,
            ann_candidates, iterations, exact_used, starvation,
        )

    def _parse_scope(self, payload: dict[str, Any], application_id: str) -> AuthorizationScope:
        if not isinstance(payload, dict):
            raise ScopeError("AUTHORIZATION_SCOPE_INVALID")
        if payload.get("mode") != "protect":
            raise ScopeError("AUTHORIZATION_SCOPE_REQUIRES_PROTECT")
        if payload.get("decision") != "allow":
            reason = payload.get("reason")
            if reason == "AUTHORIZATION_SCOPE_TRUNCATED":
                raise ScopeError("AUTHORIZATION_SCOPE_INCOMPLETE")
            if reason == "NO_AUTHORIZED_RESOURCES":
                raise ScopeError("NO_AUTHORIZED_RESOURCES")
            raise ScopeError("AUTHORIZATION_SCOPE_DENIED")
        if payload.get("scope_complete") is False or payload.get("truncated") is True:
            raise ScopeError("AUTHORIZATION_SCOPE_INCOMPLETE")
        allowed = payload.get("allowed_resource_ids")
        if (not isinstance(allowed, list) or not allowed
                or any(not isinstance(value, str) or not value for value in allowed)):
            raise ScopeError("AUTHORIZATION_SCOPE_INVALID")
        source_id = payload.get("source_id")
        decision_id = payload.get("decision_id")
        if not isinstance(source_id, str) or not source_id or not isinstance(decision_id, str) or not decision_id:
            raise ScopeError("AUTHORIZATION_SCOPE_INVALID")
        revision, revision_hash = authorization_revision_binding(payload)
        return AuthorizationScope(
            tenant_id=self.tenant_id, application_id=application_id,
            source_id=source_id, allowed_resource_ids=frozenset(allowed),
            decision_id=decision_id, mode="protect",
            revision=revision, revision_hash=revision_hash,
        )

    def _search_in_scope(
        self, *, scope: AuthorizationScope, query: Any,
    ) -> tuple[list[RetrievedResource], int, int, bool, bool]:
        collected: list[RetrievedResource] = []
        seen: set[tuple[str, str, str | None]] = set()
        ann_candidates = 0
        iterations = 0
        candidate_limit = max(self.page_size, self.min_results)
        while True:
            hits = list(self.backend.search(
                scope=scope, query=query, limit=candidate_limit, exact=False,
            ))
            ann_candidates += len(hits)
            iterations += 1
            self._reject_out_of_scope(hits, scope)
            collected = self._merge(collected, hits, seen)
            if len(collected) >= self.min_results:
                break
            # A short page means the backend exhausted its scoped candidates.
            if len(hits) < candidate_limit:
                break
            if candidate_limit >= self.max_scan_candidates:
                break
            candidate_limit = min(
                self.max_scan_candidates, max(candidate_limit + 1, candidate_limit * 2),
            )
        exact_used = False
        starvation = False
        if len(collected) < self.min_results and self.exact_fallback_limit:
            exact_hits = list(self.backend.search(
                scope=scope, query=query, limit=self.exact_fallback_limit, exact=True,
            ))
            self._reject_out_of_scope(exact_hits, scope)
            exact_used = True
            before = len(collected)
            collected = self._merge(collected, exact_hits, seen)
            starvation = len(collected) > before
        return (
            collected[:self.max_results], ann_candidates, iterations,
            exact_used, starvation,
        )

    @staticmethod
    def _reject_out_of_scope(hits: list[RetrievedResource], scope: AuthorizationScope) -> None:
        for hit in hits:
            if (not isinstance(hit, RetrievedResource)
                    or hit.source_id != scope.source_id
                    or hit.resource_id not in scope.allowed_resource_ids):
                raise ScopeError("RETRIEVAL_SCOPE_VIOLATION")

    @staticmethod
    def _merge(
        current: list[RetrievedResource], hits: Sequence[RetrievedResource],
        seen: set[tuple[str, str, str | None]],
    ) -> list[RetrievedResource]:
        merged = list(current)
        for hit in hits:
            key = (hit.source_id, hit.resource_id, hit.chunk_id)
            if key in seen:
                continue
            seen.add(key)
            merged.append(hit)
        return merged


__all__ = [
    "AuthorizationScope", "AuthorizedRetrievalResult", "AuthorizedVectorRetriever",
    "ScopedVectorBackend", "ScopeError",
]
