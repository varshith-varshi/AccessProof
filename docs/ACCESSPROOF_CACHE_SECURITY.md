# AccessProof cache security: what is enforced, where, and what is not

Status: 2026-11-04, release **r31** (`8df06eb`), deployed to production and to the lab Guard/Gateway. This page describes enforcement, not intent. A cache path is **protected** only when the content it returns passes through the AccessProof Gateway for the employee making the current request.

## The boundary
AccessProof enforces at the Gateway and Guard. Every model input and every released answer on the certified route goes through:
1. **Layer 1 — Guard `filter-resources`.** The employee's current effective access is checked for each chunk before it enters model context.
2. **Provenance and freshness.** The ingestion signature (Ed25519) is checked over the chunk's exact bytes, tenant, application, source, resource, chunk and content version, and the attestation must not have expired (lifetime ≤ 3600 s). **Since r31** the Guard also requires that `content_version` is a *current* provider version of the document (Graph `eTag`/`cTag` delivered by the control plane). Otherwise the chunk is refused: `SOURCE_CONTENT_VERSION_STALE`, `_UNKNOWN` (deleted or unknown document), or `_REQUIRED`.
3. **Layer 2 — Guard `check-output`.** Before release, authorization is checked again at the same authorization revision. A revision change between Layer 1 and Layer 2 blocks the answer (`AUTHORIZATION_REVISION_CHANGED`).

**Anything a customer application returns to an employee without calling the Gateway is outside this boundary.** AccessProof cannot see or block such a path, and nothing on this page claims it does.

## Cache paths

| # | Cache path | Status | How it is enforced |
|---|---|---|---|
| 1 | Redis retrieval or result cache, when cached chunks are sent to the Gateway as `retrieved_resources` | **Protected** | Each cached chunk is checked by Layer 1 for the current employee, its signature is verified, and its attestation must be unexpired. A poisoned, unsigned, version-swapped or re-chunked entry never reaches the model. |
| 2 | Vector-search and document-chunk caches, same contract | **Protected** | Same as 1. The Gateway does not care where a chunk came from; it re-authorizes and re-verifies every chunk on every request. |
| 3 | LLM answer cache served through `/v1/cache/authorize` or `/v1/responses/authorize` (Redis, Memcached, SQL, in-process or callback adapters in `packages/rag_core/cache_backends.py`) | **Protected** | A signed answer manifest is verified, then every dependency's attestation. Layer 1 runs for the current employee. The hit must carry the authorization revision it was written under; any later ACL, directory or policy change rejects it (`CACHE_AUTHORIZATION_REVISION_STALE`). Layer 2 runs before release. No model call. |
| 3b | LLM answer cache served directly by the application | **Not protected** | Bypass outside the boundary. Use path 3. |
| 4 | Conversation memory and tool results sent as signed `trusted_context` items (r31) | **Protected** | Each item is a signed manifest (same trust anchor as signed cached answers) listing the attested chunks it was derived from. On every request it is re-authorized for the *current* employee: Layer 1 including version freshness, authorization-revision binding, and Layer 2. The final release must be at the same revision. Free-text assistant, tool, system and developer turns are still rejected (422). |
| 4b | Memory or earlier answers replayed as `role:"user"` text | **Not protected (bypass)** | AccessProof cannot prove a user turn was typed by the employee. An application that pastes memory into the question or user turns bypasses provenance. |
| 5 | Cross-user and cross-tenant isolation | **Protected** for paths 1–3 | Authorization uses the employee in the current request's token, never the cache key. Manifests and attestations are tenant- and application-bound. |
| 6 | Revocation while cached data exists | **Protected** for paths 1–3, after detection | Chunks are denied by Layer 1 once the Guard has the new revision. Cached answers are rejected by revision binding. Detection takes up to about 300 s, the ACL sync interval (measured below). |
| 7 | In-flight requests using cached content | **Protected** | Late cached or tool inputs need a trusted `source_trace` and their own Layer 1 check (`PROVENANCE_TRACE_REQUIRED`). A revocation landing between Layer 1 and Layer 2 blocks the answer. |
| 8 | Missing, invalid, unverifiable or stale provenance or authorization evidence | **Fails closed** | Missing or invalid attestation, unknown or revoked signing key, expired attestation, Guard unavailable, stale ACL (`SOURCE_ACL_STALE`), missing revision → no model call or no release. |

## Known limitations (not hidden)
* **Bypass paths.** Paths 3b and 4b, and any cache read the application serves without the Gateway, are not enforced. The route certificate certifies only the Gateway route exercised by the nonce-bound challenge.
* **Version freshness is bounded by ACL sync (≤ 300 s), not by the attestation lifetime.** Until the control plane sees a document edit, the Guard still treats the previous version as current. After it does, chunks at the old version are refused until the RAG re-indexes (fail closed, measured live below). Versioning applies to Microsoft sources whose every live document has a recorded version; other sources keep the attestation-lifetime bound.
* **Revocation window.** Until AccessProof detects a SharePoint change, the Guard holds the previous decision for chunks and answers alike. Measured on r30: direct grant 79–202 s, inherited 25 s, deletion 243 s, group 412 s. Group changes wait for directory sync: 900 s on r30, 300 s from r31. Inside that window the Guard serves its last verified snapshot (bounded staleness). It fails closed when sync evidence is errored or older than the thresholds (ACL 900 s, directory 900 s from r31).

## Evidence
* **Automated (r31):**
  * `tests/security/test_cached_chunk_version_freshness.py` (8): document update, deleted or unknown document, signed answer built from an old version, refusal reasons, sync keep/drop semantics, control-plane completeness rule. Four of them fail without the fix.
  * `tests/security/test_signed_memory_tool_context.py` (7): authorized signed memory and tool items, Bob replaying Alice's memory, memory after revocation, memory from an old document version, tampered/unsigned/cross-tenant memory, no verification key, free-text memory.
  * `tests/security/test_cache_security_matrix.py`: 13 tests covering poisoned, unsigned, version-swapped, re-chunked and expired chunk-cache entries, assistant/tool/system/developer memory, cross-user replay of a chunk and an answer, cross-tenant answers, revocation while cached, and Guard down.
  * Existing cache suites: 71 tests (answer manifests, revision binding, multisource, all response routes, Redis/Memcached/SQL/callback adapters, reference Redis).
* **Live on r30 (lab SharePoint tenant, real Entra tokens, production control plane):**
  * Bob's retrieved chunks never reached the model in Alice's requests, and the reverse (E2E-02/04, model-context witness).
  * A tampered cached chunk with its original attestation was refused with 0 model calls (E2E-11).
  * The application's unprotected cached route is disabled (503).
  * Protected answers are never cached.
  * After revocation the pre-revocation answer was not reused (G / E2E-08).
  * An in-flight revocation was withheld by Layer 2 (F / E2E-09).
* **Live on r31:**
  * Layer 1 with indexed versions: 10/10.
  * For both employees, an authorized document with a stale version → `SOURCE_CONTENT_VERSION_STALE`, and with no version → `SOURCE_CONTENT_VERSION_REQUIRED` (8/8 controls).
  * RAG E2E 8/8.
  * Document-update trial: `document-update-freshness-r31.json`.
* **Not yet live-validated:** the signed answer cache and signed memory/tool context with a real signing producer. The lab Gateway has no cache verification key and refuses those requests (403/503) without a model call.
* **Full regression r31:** SQLite 1523 tests, 0 failed, 0 errors. PostgreSQL 17 as `accessproof_app`: 1523 tests, 0 failed, 0 errors.
