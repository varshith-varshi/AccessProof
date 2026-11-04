# AccessProof cache security: what is enforced, where, and what is not

Status: 2026-11-04, release r30 (`a4f8020`). This page describes enforcement, not intent. A cache path is **protected** only when the content it returns passes through the AccessProof Gateway for the employee making the current request.

## The boundary
AccessProof enforces at the Gateway and Guard. Every model input and every released answer on the certified route goes through:
1. **Layer 1 — Guard `filter-resources`.** The employee's current effective access is checked for each chunk before it enters model context.
2. **Provenance.** The ingestion signature (Ed25519) is checked over the chunk's exact bytes, tenant, application, source, resource, chunk and content version, and the attestation must not have expired (lifetime ≤ 3600 s).
3. **Layer 2 — Guard `check-output`.** Before release, authorization is checked again at the same authorization revision. A revision change between Layer 1 and Layer 2 blocks the answer (`AUTHORIZATION_REVISION_CHANGED`).

**Anything a customer application returns to an employee without calling the Gateway is outside this boundary.** AccessProof cannot see or block such a path, and nothing on this page claims it does.

## Cache paths

| # | Cache path | Status | How it is enforced |
|---|---|---|---|
| 1 | Redis retrieval or result cache, when cached chunks are sent to the Gateway as `retrieved_resources` | **Protected** | Each cached chunk is checked by Layer 1 for the current employee, its signature is verified, and its attestation must be unexpired. A poisoned, unsigned, version-swapped or re-chunked entry never reaches the model. |
| 2 | Vector-search and document-chunk caches, same contract | **Protected** | Same as 1. The Gateway does not care where a chunk came from; it re-authorizes and re-verifies every chunk on every request. |
| 3 | LLM answer cache served through `/v1/cache/authorize` or `/v1/responses/authorize` (Redis, Memcached, SQL, in-process or callback adapters in `packages/rag_core/cache_backends.py`) | **Protected** | A signed answer manifest is verified, then every dependency's attestation. Layer 1 runs for the current employee. The hit must carry the authorization revision it was written under; any later ACL, directory or policy change rejects it (`CACHE_AUTHORIZATION_REVISION_STALE`). Layer 2 runs before release. No model call. |
| 3b | LLM answer cache served directly by the application | **Not protected** | Bypass outside the boundary. Use path 3. |
| 4 | Conversation history and agent memory | **Partially protected** | The certified route accepts only `role:"user"` turns. Assistant, tool, system and developer turns are rejected (422). Enterprise content must arrive as attested `retrieved_resources`. **Limitation:** AccessProof cannot prove that a "user" turn was typed by the employee. An application that replays earlier answers or agent memory as user text bypasses provenance. |
| 5 | Cross-user and cross-tenant isolation | **Protected** for paths 1–3 | Authorization uses the employee in the current request's token, never the cache key. Manifests and attestations are tenant- and application-bound. |
| 6 | Revocation while cached data exists | **Protected** for paths 1–3, after detection | Chunks are denied by Layer 1 once the Guard has the new revision. Cached answers are rejected by revision binding. Detection takes up to about 300 s, the ACL sync interval (measured below). |
| 7 | In-flight requests using cached content | **Protected** | Late cached or tool inputs need a trusted `source_trace` and their own Layer 1 check (`PROVENANCE_TRACE_REQUIRED`). A revocation landing between Layer 1 and Layer 2 blocks the answer. |
| 8 | Missing, invalid, unverifiable or stale provenance or authorization evidence | **Fails closed** | Missing or invalid attestation, unknown or revoked signing key, expired attestation, Guard unavailable, stale ACL (`SOURCE_ACL_STALE`), missing revision → no model call or no release. |

## Known limitations (not hidden)
* **Bypass paths.** Paths 3b and 4 (user-labelled replay), and any cache read the application serves without the Gateway, are not enforced. The route certificate certifies only the Gateway route exercised by the nonce-bound challenge.
* **Content-version staleness ≤ 1 h.** An older version of a document the employee *still has access to* can be replayed from a chunk cache while its attestation is unexpired. The v1 Guard path does not compare `content_version` with the currently synced version; the v2 multisource path requires a version but does not compare it with the source either. This is not a cross-user leak. It can matter when sensitive text was removed from a document the employee can still read.
* **Revocation window.** Until AccessProof detects a SharePoint change (measured 79–412 s on r30; group changes wait for directory sync, default 900 s), the Guard still holds the previous decision for chunks and answers alike.

## Evidence
* **Automated:**
  * `tests/security/test_cache_security_matrix.py`: 13 tests covering poisoned, unsigned, version-swapped, re-chunked and expired chunk-cache entries, assistant/tool/system/developer memory, cross-user replay of a chunk and an answer, cross-tenant answers, revocation while cached, and Guard down.
  * Existing cache suites: 71 tests (answer manifests, revision binding, multisource, all response routes, Redis/Memcached/SQL/callback adapters, reference Redis).
* **Live on r30 (lab SharePoint tenant, real Entra tokens, production control plane):**
  * Bob's retrieved chunks never reached the model in Alice's requests, and the reverse (E2E-02/04, model-context witness).
  * A tampered cached chunk with its original attestation was refused with 0 model calls (E2E-11).
  * The application's unprotected cached route is disabled (503).
  * Protected answers are never cached.
  * After revocation the pre-revocation answer was not reused (G / E2E-08).
  * An in-flight revocation was withheld by Layer 2 (F / E2E-09).
* **Not yet live-validated:** the signed answer-cache endpoint with a real signing producer. The lab Gateway has no cache verification key, so `/v1/cache/authorize` fails closed (`CACHE_TRUSTED_SIGNING_KEYS_NOT_CONFIGURED`).
