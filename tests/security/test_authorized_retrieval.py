"""Authorization-first retrieval must never starve or over-expose enterprise data."""
from __future__ import annotations

from collections.abc import Callable

import pytest
from sqlalchemy import Column, MetaData, String, Table
from sqlalchemy.dialects import postgresql

from packages.rag_sdk.authorized_retrieval import (
    AuthorizedVectorRetriever, AuthorizationScope,
)
from packages.rag_sdk.pgvector_retrieval import PgVectorAuthorizedBackend
from packages.rag_sdk.protection import RetrievedResource

REVISION = 4
REVISION_HASH = "c" * 64


def _resource(document: str, chunk: str = "chunk-0") -> RetrievedResource:
    return RetrievedResource("drive", document, chunk, f"content {document}")


class FakeScopedBackend:
    def __init__(
        self,
        ann: Callable[[int], list[RetrievedResource]],
        exact: Callable[[int], list[RetrievedResource]] | None = None,
    ) -> None:
        self.ann = ann
        self.exact_results = exact
        self.calls: list[tuple[int, bool]] = []

    def search(self, *, scope, query, limit, exact):
        assert scope.allowed_resource_ids
        self.calls.append((limit, exact))
        source = self.exact_results if exact and self.exact_results is not None else self.ann
        return source(limit)


class ScopeGuard:
    def __init__(self, allowed: list[str], *, revision: int | None = REVISION,
                 revision_hash: str | None = REVISION_HASH, mode: str = "protect",
                 decision: str = "allow", complete: bool = True,
                 deny_resource: str | None = None,
                 final_revision: int | None = REVISION,
                 final_revision_hash: str | None = REVISION_HASH) -> None:
        self.allowed = allowed
        self.revision = revision
        self.revision_hash = revision_hash
        self.mode = mode
        self.decision = decision
        self.complete = complete
        self.deny_resource = deny_resource
        self.final_revision = final_revision
        self.final_revision_hash = final_revision_hash
        self.scope_calls = 0
        self.filter_calls = 0

    def authorization_scope(self, **kwargs):
        self.scope_calls += 1
        payload = {
            "decision_id": "scope-decision", "decision": self.decision,
            "reason": "AUTHORIZATION_SCOPE", "mode": self.mode,
            "source_id": "drive", "allowed_resource_ids": list(self.allowed),
            "truncated": not self.complete, "scope_complete": self.complete,
        }
        if self.revision is not None:
            payload["authorization_revision"] = self.revision
            payload["authorization_revision_hash"] = self.revision_hash
        return payload

    def filter_resources(self, **kwargs):
        self.filter_calls += 1
        resources = kwargs["resources"]
        payload = {
            "decision_id": "final-decision", "decision": "allow", "mode": "protect",
            "allowed": [{
                "source_id": item.source_id, "resource_id": item.resource_id,
                "chunk_ids": [item.chunk_id] if item.chunk_id else [],
            } for item in resources if item.resource_id != self.deny_resource],
        }
        if self.final_revision is not None:
            payload["authorization_revision"] = self.final_revision
            payload["authorization_revision_hash"] = self.final_revision_hash
        return payload


def _retriever(backend, guard, **overrides):
    return AuthorizedVectorRetriever(
        backend=backend, guard=guard, tenant_id="tenant-a", **overrides,
    )


def test_scoped_search_never_returns_an_out_of_scope_document():
    backend = FakeScopedBackend(lambda limit: [
        _resource("allowed-doc"), _resource("denied-doc"),
    ])
    guard = ScopeGuard(["allowed-doc"])
    result = _retriever(backend, guard).retrieve(
        employee_token="employee", application_id="rag", query=[0.1, 0.2],
    )
    assert result.decision == "block"
    assert result.reason == "RETRIEVAL_SCOPE_VIOLATION"
    assert result.resources == ()
    assert guard.filter_calls == 0


def test_exact_fallback_recovers_documents_starved_by_ann_candidate_window():
    backend = FakeScopedBackend(
        ann=lambda limit: [_resource("doc-a")],
        exact=lambda limit: [_resource("doc-a"), _resource("doc-b")],
    )
    guard = ScopeGuard(["doc-a", "doc-b"])
    result = _retriever(
        backend, guard, page_size=2, min_results=2, exact_fallback_limit=50,
    ).retrieve(employee_token="employee", application_id="rag", query=[0.5])
    assert result.decision == "allow"
    assert {item.resource_id for item in result.resources} == {"doc-a", "doc-b"}
    assert result.exact_fallback_used is True
    assert result.starvation_detected is True
    assert backend.calls == [(2, False), (50, True)]
    assert result.authorization_revision == REVISION


def test_bounded_overfetch_grows_when_the_first_authorized_page_is_insufficient():
    first = [_resource(f"doc-{index}") for index in range(20)]
    second = [_resource(f"doc-{index}") for index in range(40)]

    def ann(limit):
        if limit < 70:
            # A full candidate page that deduplicates to only 20 documents.
            return (first * 2)[:35]
        return second

    backend = FakeScopedBackend(ann)
    guard = ScopeGuard([item.resource_id for item in second])
    result = _retriever(
        backend, guard, page_size=20, max_scan_candidates=80, min_results=35,
        max_results=50,
    ).retrieve(employee_token="employee", application_id="rag", query=[0.5])
    assert result.decision == "allow"
    assert len(result.resources) == 40
    assert result.iterations == 2
    assert backend.calls == [(35, False), (70, False)]


def test_truncated_scope_is_a_hard_failure_not_a_partial_search():
    backend = FakeScopedBackend(lambda limit: [_resource("doc-a")])
    guard = ScopeGuard(["doc-a"], complete=False)
    result = _retriever(backend, guard).retrieve(
        employee_token="employee", application_id="rag", query=[0.5],
    )
    assert result.decision == "block"
    assert result.reason == "AUTHORIZATION_SCOPE_INCOMPLETE"
    assert result.resources == ()
    assert backend.calls == []


def test_shadow_or_denied_scope_never_runs_retrieval():
    backend = FakeScopedBackend(lambda limit: [_resource("doc-a")])
    for guard, reason in (
        (ScopeGuard(["doc-a"], mode="shadow"), "AUTHORIZATION_SCOPE_REQUIRES_PROTECT"),
        (ScopeGuard(["doc-a"], decision="block"), "AUTHORIZATION_SCOPE_DENIED"),
    ):
        result = _retriever(backend, guard).retrieve(
            employee_token="employee", application_id="rag", query=[0.5],
        )
        assert result.decision == "block"
        assert result.reason == reason
        assert result.resources == ()
    assert backend.calls == []


def test_scope_revision_must_match_the_final_layer1_decision():
    backend = FakeScopedBackend(lambda limit: [_resource("doc-a")])
    guard = ScopeGuard(
        ["doc-a"], final_revision=REVISION + 1,
        final_revision_hash="d" * 64,
    )
    result = _retriever(backend, guard).retrieve(
        employee_token="employee", application_id="rag", query=[0.5],
    )
    assert result.decision == "block"
    assert result.reason == "AUTHORIZATION_REVISION_CHANGED"
    assert result.resources == ()


def test_partial_final_guard_allowance_blocks_the_whole_context():
    backend = FakeScopedBackend(lambda limit: [
        _resource("doc-a"), _resource("doc-b"),
    ])
    guard = ScopeGuard(["doc-a", "doc-b"], deny_resource="doc-b")
    result = _retriever(
        backend, guard, min_results=2,
    ).retrieve(employee_token="employee", application_id="rag", query=[0.5])
    assert result.decision == "block"
    assert result.reason == "RETRIEVAL_GUARD_PARTIAL_DENIAL"
    assert result.resources == ()


def _pgvector_table() -> Table:
    return Table(
        "chunks", MetaData(),
        Column("tenant_id", String, primary_key=True),
        Column("document_id", String, primary_key=True),
        Column("chunk_id", String),
        Column("content", String),
        Column("content_version", String),
        Column("content_attestation", String),
        Column("embedding", String),
    )


def test_pgvector_query_applies_scope_predicate_before_ranking():
    backend = PgVectorAuthorizedBackend(engine=None, chunks=_pgvector_table())
    scope = AuthorizationScope(
        tenant_id="tenant-a", application_id="rag", source_id="drive",
        allowed_resource_ids=frozenset({"doc-a", "doc-b"}),
        decision_id="decision", mode="protect",
        revision=REVISION, revision_hash=REVISION_HASH,
    )
    statement, parameters = backend.build_query(scope=scope, query=[0.25, -1.0], limit=25)
    sql = str(statement.compile(dialect=postgresql.dialect())).lower()
    assert "chunks.tenant_id = %(tenant_id_1)s" in sql
    assert "chunks.document_id = any" in sql
    assert "chunks.embedding <-> cast(%(query_vector)s as vector)" in sql
    assert "limit %(param_1)s" in sql
    assert parameters["allowed_resource_ids"] == ["doc-a", "doc-b"]
    assert parameters["query_vector"] == "[0.25,-1.0]"


def test_pgvector_rejects_missing_columns_and_non_finite_vectors():
    with pytest.raises(ValueError, match="MISSING_PGVECTOR_COLUMNS"):
        PgVectorAuthorizedBackend(
            engine=None, chunks=Table("chunks", MetaData(), Column("tenant_id", String)),
        )
    backend = PgVectorAuthorizedBackend(engine=None, chunks=_pgvector_table())
    scope = AuthorizationScope(
        tenant_id="tenant-a", application_id="rag", source_id="drive",
        allowed_resource_ids=frozenset({"doc-a"}), decision_id="decision",
        mode="protect", revision=REVISION, revision_hash=REVISION_HASH,
    )
    with pytest.raises(ValueError, match="INVALID_QUERY_VECTOR"):
        backend.build_query(scope=scope, query=[float("nan")], limit=5)
    with pytest.raises(ValueError, match="EMPTY_AUTHORIZATION_SCOPE"):
        backend.build_query(
            scope=AuthorizationScope(
                tenant_id="tenant-a", application_id="rag", source_id="drive",
                allowed_resource_ids=frozenset(), decision_id="decision",
                mode="protect", revision=REVISION, revision_hash=REVISION_HASH,
            ),
            query=[0.1], limit=5,
        )
