"""Reference PostgreSQL/pgvector backend for authorization-first retrieval.

The authorization predicate is part of the SQL query, so ANN search runs inside
the employee's allowed resource scope instead of ranking a global top-k and
discarding unauthorized rows afterwards. pgvector's iterative scan is enabled
for approximate searches; the exact fallback disables index scans in the same
bounded transaction when recall is insufficient.

This backend is UNIT_VERIFIED through SQL-shape and algorithm tests. It has not
been executed against a live PostgreSQL/pgvector deployment in this repository.
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any

from sqlalchemy import Table, any_, bindparam, cast, select, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.engine import Engine
from sqlalchemy.sql.sqltypes import String
from sqlalchemy.types import UserDefinedType

from .authorized_retrieval import AuthorizationScope
from .protection import RetrievedResource


class _VectorType(UserDefinedType[Any]):
    cache_ok = True

    def get_col_spec(self, **kw: Any) -> str:
        return "vector"


def _vector_literal(values: Sequence[float]) -> str:
    if not values or len(values) > 16_384:
        raise ValueError("INVALID_QUERY_VECTOR")
    numbers: list[float] = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("INVALID_QUERY_VECTOR")
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("INVALID_QUERY_VECTOR")
        numbers.append(number)
    return "[" + ",".join(repr(number) for number in numbers) + "]"


class PgVectorAuthorizedBackend:
    """Execute scoped ANN or exact search against a pgvector chunks table."""

    def __init__(
        self, *, engine: Engine, chunks: Table,
        tenant_column: str = "tenant_id", resource_column: str = "document_id",
        chunk_column: str = "chunk_id", content_column: str = "content",
        content_version_column: str = "content_version",
        content_attestation_column: str = "content_attestation",
        embedding_column: str = "embedding",
        iterative_scan: str = "relaxed_order", max_scan_tuples: int = 10_000,
    ) -> None:
        names = {
            tenant_column, resource_column, chunk_column, content_column,
            content_version_column, content_attestation_column, embedding_column,
        }
        missing = names.difference(chunks.c.keys())
        if missing:
            raise ValueError("MISSING_PGVECTOR_COLUMNS")
        if iterative_scan not in {"off", "relaxed_order", "strict_order"}:
            raise ValueError("INVALID_ITERATIVE_SCAN_MODE")
        if not 1 <= max_scan_tuples <= 1_000_000:
            raise ValueError("INVALID_MAX_SCAN_TUPLES")
        self.engine = engine
        self.chunks = chunks
        self.tenant_column = chunks.c[tenant_column]
        self.resource_column = chunks.c[resource_column]
        self.chunk_column = chunks.c[chunk_column]
        self.content_column = chunks.c[content_column]
        self.content_version_column = chunks.c[content_version_column]
        self.content_attestation_column = chunks.c[content_attestation_column]
        self.embedding_column = chunks.c[embedding_column]
        self.iterative_scan = iterative_scan
        self.max_scan_tuples = max_scan_tuples

    def build_query(
        self, *, scope: AuthorizationScope, query: Sequence[float], limit: int,
    ) -> tuple[Any, dict[str, Any]]:
        if not 1 <= limit <= 10_000:
            raise ValueError("INVALID_RETRIEVAL_LIMIT")
        if not scope.allowed_resource_ids:
            raise ValueError("EMPTY_AUTHORIZATION_SCOPE")
        vector = cast(bindparam("query_vector"), _VectorType())
        statement = (
            select(
                self.resource_column.label("resource_id"),
                self.chunk_column.label("chunk_id"),
                self.content_column.label("content"),
                self.content_version_column.label("content_version"),
                self.content_attestation_column.label("content_attestation"),
            )
            .where(
                self.tenant_column == scope.tenant_id,
                self.resource_column == any_(
                    bindparam("allowed_resource_ids", type_=ARRAY(String)),
                ),
            )
            .order_by(self.embedding_column.op("<->")(vector).asc())
            .limit(limit)
        )
        parameters = {
            "query_vector": _vector_literal(query),
            "allowed_resource_ids": sorted(scope.allowed_resource_ids),
        }
        return statement, parameters

    def search(
        self, *, scope: AuthorizationScope, query: Any, limit: int, exact: bool,
    ) -> list[RetrievedResource]:
        if not isinstance(query, (list, tuple)):
            raise ValueError("INVALID_QUERY_VECTOR")
        statement, parameters = self.build_query(scope=scope, query=query, limit=limit)
        with self.engine.connect() as connection:
            with connection.begin():
                if exact:
                    # Exact authorized fallback: the same predicate is used,
                    # but index scans are disabled for this transaction so the
                    # ORDER BY evaluates every scoped row up to the limit.
                    connection.execute(text("SET LOCAL enable_indexscan = off"))
                    connection.execute(text("SET LOCAL enable_indexonlyscan = off"))
                    connection.execute(text("SET LOCAL enable_bitmapscan = off"))
                else:
                    # Values are an enum and a bounded integer, never request
                    # text; PostgreSQL does not accept bind parameters in SET.
                    connection.execute(text(
                        f"SET LOCAL hnsw.iterative_scan = {self.iterative_scan}"
                    ))
                    connection.execute(text(
                        f"SET LOCAL hnsw.max_scan_tuples = {int(self.max_scan_tuples)}"
                    ))
                rows = connection.execute(statement, parameters).mappings().all()
        return [self._resource(scope, row) for row in rows]

    @staticmethod
    def _resource(scope: AuthorizationScope, row: Any) -> RetrievedResource:
        resource_id = row["resource_id"]
        chunk_id = row["chunk_id"]
        content = row["content"]
        version = row["content_version"]
        attestation = row["content_attestation"]
        if (not isinstance(resource_id, str) or not resource_id
                or (chunk_id is not None and not isinstance(chunk_id, str))
                or not isinstance(content, str)
                or (version is not None and not isinstance(version, str))
                or (attestation is not None and not isinstance(attestation, str))):
            raise ValueError("INVALID_PGVECTOR_ROW")
        if resource_id not in scope.allowed_resource_ids:
            # The SQL predicate should make this impossible; a datastore role
            # or RLS misconfiguration must still never leak a chunk into context.
            raise ValueError("PGVECTOR_SCOPE_VIOLATION")
        return RetrievedResource(
            source_id=scope.source_id, resource_id=resource_id,
            chunk_id=chunk_id, content=content,
            content_version=version, content_attestation=attestation,
        )


__all__ = ["PgVectorAuthorizedBackend"]
