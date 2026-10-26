# AccessProof V4 — Authorization-First Retrieval and Cache Reauthorization

**Snapshot:** 2026-10-24
**Evidence level:** `UNIT_VERIFIED` (SQL-shape/algorithm tests) and
`LOCAL_INTEGRATION_VERIFIED` (Guard scope and release tests). No live
PostgreSQL/pgvector deployment was executed.

## 1. The starvation problem

A common RAG design retrieves a global ANN top-k and removes unauthorized rows
afterwards. If denied documents crowd the candidate window, an employee can
receive fewer authorized documents than they are entitled to — or none — even
though relevant authorized content exists. The post-filter also creates a
window in which the application handles unauthorized identifiers.

AccessProof treats retrieval as part of the authorization boundary. The scope
is applied **inside the datastore query**.

## 2. Required retrieval order

```text
verified employee identity
→ Guard-issued allowed-resource scope (Protect mode)
→ datastore authorization predicate
→ ANN search inside that scope
→ bounded iterative overfetch
→ exact index-bypassing fallback when recall is insufficient
→ fresh Layer 1 authorization of the final context
→ model generation (buffered)
→ Layer 2 output/provenance release
```

Implementation: [packages/rag_sdk/authorized_retrieval.py](../../packages/rag_sdk/authorized_retrieval.py).

### Guard scope

`GuardClient.authorization_scope()` calls `POST /guard/v1/authorization-scope`
with the employee JWT, application ID and request ID. A usable scope requires:

- `mode == "protect"` and `decision == "allow"`;
- a non-empty `allowed_resource_ids` list;
- `scope_complete` not false and `truncated` not true;
- a source ID and decision ID;
- a valid authorization revision pair when revisions are enforced.

A missing revision on a revision-enforcing Guard returns
`AUTHORIZATION_REVISION_MISSING`; a truncated scope returns
`AUTHORIZATION_SCOPE_INCOMPLETE`. Neither is treated as an empty-but-valid
scope.

### `AuthorizedVectorRetriever`

The SDK retriever:

- never issues an unscoped search;
- rejects any backend hit whose source or resource is outside the scope
  (`RETRIEVAL_SCOPE_VIOLATION`) instead of filtering it silently;
- starts with `page_size` candidates, doubles up to `max_scan_candidates`, and
  tracks whether a short page exhausted scoped candidates;
- falls back to an exact, index-bypassing search when the minimum result count
  is not met, and reports `starvation_detected` when that fallback found
  additional authorized results;
- re-checks the final context with Guard Layer 1 and blocks on any revision
  mismatch;
- blocks with `RETRIEVAL_GUARD_PARTIAL_DENIAL` if Layer 1 would silently
  narrow the scope — the caller must restart with a fresh scope;
- returns no partial candidate set on backend failure.

Relevant block reasons: `AUTHORIZATION_SCOPE_REQUIRES_EMPLOYEE`,
`AUTHORIZATION_SCOPE_UNAVAILABLE`, `AUTHORIZATION_SCOPE_INVALID`,
`AUTHORIZATION_SCOPE_REQUIRES_PROTECT`, `AUTHORIZATION_SCOPE_DENIED`,
`AUTHORIZATION_SCOPE_INCOMPLETE`, `NO_AUTHORIZED_RESOURCES`,
`RETRIEVAL_SCOPE_VIOLATION`, `RETRIEVAL_BACKEND_FAILED`,
`RETRIEVAL_GUARD_UNAVAILABLE`, `RETRIEVAL_GUARD_DENIED`,
`AUTHORIZATION_REVISION_MISSING`, `AUTHORIZATION_SCOPE_REVISION_MISSING`,
`AUTHORIZATION_REVISION_CHANGED`, `RETRIEVAL_GUARD_PARTIAL_DENIAL`.

## 3. PostgreSQL/pgvector reference backend

[packages/rag_sdk/pgvector_retrieval.py](../../packages/rag_sdk/pgvector_retrieval.py)
implements `ScopedVectorBackend`:

- the SQL query includes `document_id = ANY(:allowed_resource_ids)` (plus
  tenant/source constraints) before ordering by vector distance;
- approximate search enables `hnsw.iterative_scan = strict_order` and sets
  `hnsw.max_scan_tuples` from the candidate bound;
- exact fallback executes in the same transaction and disables index scans so
  the fallback cannot silently degrade back to approximate search;
- returned rows are validated against the scope and any mismatch raises
  `PGVECTOR_SCOPE_VIOLATION`;
- query vectors and candidate bounds are validated before SQL construction.

Limits:

- **No live PostgreSQL execution.** Types, SQL shape and fallback behavior are
  covered by unit tests only (`UNIT_VERIFIED`).
- The backend does not create indexes, extensions, or tables.
- `hnsw.iterative_scan` availability depends on the deployed pgvector version;
  unsupported deployments fail rather than silently dropping the setting.
- Authorization remains dependent on correct resource identifiers in the
  vector store and a fresh Guard scope.

## 4. Protected answer-cache reauthorization

A cache hit is not authorization. `ProtectedRAG.verify_cached_answer()`
requires a signed `CachedAnswerManifest`, a manifest token, and a verifier. It:

- verifies the manifest signature and employee/tenant/application binding;
- verifies the manifest's authorization revision is still current;
- re-runs Layer 1 for the cached resource dependencies;
- re-runs Layer 2 provenance checks before release;
- never invokes a model and never trusts a historical allow decision.

Cache backends (`none`, Redis, Memcached, SQL) are labelled `PARTIAL` at best.
Selecting one is not evidence that a customer's cache return path is protected.
See [../ACCESSPROOF_UNIVERSAL_CACHE_IMPLEMENTATION_2026-10-24.md](../ACCESSPROOF_UNIVERSAL_CACHE_IMPLEMENTATION_2026-10-24.md).

## 5. Test coverage

```bash
.venv/bin/python -m pytest tests/security/test_authorized_retrieval.py -q
.venv/bin/python -m pytest tests/unit/test_guard_authorization_scope.py -q
```

`tests/security/test_authorized_retrieval.py` covers scope enforcement,
starvation fallback, revision changes, out-of-scope hits, partial denials,
cache reauthorization, and pgvector SQL/fallback construction. The Guard scope
tests cover scope truncation, missing revisions and audit evidence.

## 6. Residual gates

1. Execute the pgvector backend against an authorized PostgreSQL deployment
   and record query plans/latency (`LIVE_PROVIDER_VERIFIED` is not claimed).
2. Prove the customer's actual vector store applies the predicate before ANN,
   not only the reference backend.
3. Prove every cache and retrieval path in the customer application uses the
   scoped retriever and release-side reauthorization.
4. Keep unsupported paths out of Protect until separately certified.
