# AccessProof V3 — Cache-agnostic connector implementation record

**Date:** 2026-10-24
**Codebase:** /home/white-devil/Downloads/accessproof/f15 (dirty worktree preserved).
**Change scope:** add interchangeable cache storage plus a cache-independent
security release API. No production credentials or customer data were used.
No deployment, database migration, Git commit or restart of production services.

## Implemented components

* `packages/rag_sdk/cache_backends.py`: shared fail-closed `CacheBackend`
  protocol with bounded keys, values and TTLs. Supports Redis, Memcached,
  PostgreSQL/SQLite through SQLAlchemy, Python in-process memory and custom
  read/write/delete/health callbacks. The SQL adapter never provisions itself
  during a user request.
* `packages/demo_cache/universal.py`: reuse of the existing signed cache
  manifest security implementation for each backend, plus a safe
  `authorize_hit` method that calls current-employee Guard Layer 1 + Layer 2.
* `packages/rag_sdk/cache_connectors.py`: public `ProtectedAnswerCache`
  wrapper with `get_authorized`, `store_approved`, `invalidate` and
  `healthy` methods. No raw cache load method is exposed by the wrapper.
* `packages/demo_cache/factory.py`: one customer-owned cache backend at a
  time; explicit selector and restricted config keys. Backward compatible
  Redis URL-only pilot setup, bounded SQLAlchemy pools, thread-safe pooled
  Memcached client, no production process-local memory cache. Conflicting
  backend settings cause an error instead of selecting a silent fallback.
* `packages/demo_cache/provision.py`: explicit customer/operator-controlled
  PostgreSQL signed-cache table provisioning for its independent answer
  namespace. No automatic schema mutation on startup.
* `drive-rag-demo/app.py`: configuration-selected storage on the protected
  answer path, rechecking employee permissions and source evidence for cache
  hits, and readiness checks. Legacy unsigned source fallback remains
  disabled in production mode.
* `apps/gateway/accessproof_gateway/app.py`: cache-technology-independent
  `POST /v1/cache/authorize` endpoint receiving an answer, source dependency
  list and signed manifest. Source and cache signing public keys must be
  independently pinned. No model call is made on a cache hit. A denied
  request cannot release cached text.
* `docker-compose.yml`, `drive-rag-demo/requirements.txt`,
  `pyproject.toml`, `.env.example`, `.env.production.example`:
  optional cache connection and pinned public-key configuration, including
  the new Memcached dependency.
* `docs/universal-cache-connectors.md`: full customer-side setup, Python
  SDK and cache-independent HTTP integration contract.

## Verification on disposable test infrastructure

* Real Redis, Memcached, and PostgreSQL (customer-like reference RAG +
  fake Guard + signed test answer): all passed initial authorized answer,
  signed cache hit and denial after simulated revocation of the same employee.
* Separate PostgreSQL and Memcached services passed direct backend signed
  manifest verification and revocation tests.
* 53 focused cache, Gateway, public API and reference-RAG regressions passed
  after connector changes. Log: `/tmp/ap_universal_final_focused_tests.log`.
* Earlier complete Python suite (before final setup fixes): **730 passed,
  one expected legacy provenance failure, no unexpected failures**. Log:
  `/tmp/ap_universal_full_suite_20261024.log`.
* Final full Python suite completed with exit code 0:
  **735 passed, one expected legacy provenance failure, zero unexpected
  failures**. Log: `/tmp/ap_universal_final_full_suite_20261024.log`.
  Extra cache-health and SQL janitor focused tests added while that suite was
  running also passed independently.
* Signed source dependency lists up to 50 entries, forged payloads, tenant/
  app separation, invalid configuration, unavailable backends, missing
  keys, Guard revocation and cache expiry were included in targeted tests.

## Hard security boundaries

1. **No fully automatic universal interception.** The adapter connects
   supported storage engines; existing application code, HTTP route
   integration or proven network cutover must route all cached responses
   through AccessProof. An arbitrary customer cache can still be used
   directly if the application bypasses that point.
2. **No trustworthy provenance from an opaque answer.** Entries must be
   signed at a trusted cache-write point and include independently attested
   source dependencies. An unsigned historical cache entry must be rejected
   or regenerated only after freshly authorized retrieval/generation.
3. **No instantaneous provider authorization claims.** Signed cache
   reauthorization uses the current Guard policy. Actual Google Drive/
   Microsoft 365 permission propagation, missed events, shared-drive change
   feed completeness and revoke-to-deny latency need customer-side validation.
4. **No third-party framework certification.** LangChain, LlamaIndex,
   Haystack, Memcached deployments with nonstandard serialization, CDNs,
   local memory caches in unrelated processes, and proprietary caches are
   not automatically instrumented; each route requires its own proof.
5. **No production availability guarantee.** Dedicated HA/load tests,
   connection TLS/auth setup, secret rotation, failover, backup/restore,
   enterprise alerting, customer network reviews and compliance controls
   remain outstanding.

**Result:** A shared, extensible cache-protection layer with three tested
external cache engines and two integration methods. Suitable for supervised
pilot integration on supported architectures after required owner approval
and authoritative permission testing. Do not market as zero-code protection
of arbitrary customer caches or as universally production certified.

## Final polish and operator UX

- Added a cache connection autodetection rule for exactly one configured
  storage endpoint; ambiguous or conflicting backend URLs are now rejected
  explicitly. This prevents accidental silent connection to a different
  customer cache. Validated by targeted tests.
- Exposed public `packages.rag_sdk.cache_connectors.ProtectedAnswerCache`
  with `get_authorized` and `store_approved`, intentionally without a
  raw `load` API.
- Added operator-only read-only cache readiness probe:
  `python -m packages.demo_cache.check`. It prints a stable status and
  never logs a customer's database password or cached answer. Dedicated
  unit tests verify ready/unavailable/unconfigured/error-secret paths.
- Pinned cached-answer signing public keys are now passed to the Gateway
  through `docker-compose.yml`. Environment loader rejects malformed keys.
- 53 cross-backend/Gateway/reference-RAG regressions plus 3 read-only
  connection-check tests and the public wrapper test have passed. These
  targeted results were captured independently of the final full-suite
  rerun.
- `docs/universal-cache-connectors.md` contains backend settings, supported
  customer Python integration, HTTP gateway release schema, required
  safety/provenance boundaries and test commands.

**Final full-suite result:** 735 passed, 1 documented expected failure,
0 unexpected failures, exit code 0. Exact local log:
`/tmp/ap_universal_final_full_suite_20261024.log`.

### SQL expiration cleanup

- Added `SQLAlchemyBackend.purge_expired(limit=1000)`, an explicitly invoked,
  bounded PostgreSQL/SQLite maintenance operation that only deletes already
  expired rows from the dedicated signed-cache table, rechecking expiry at
  deletion to avoid removing concurrently refreshed live entries.
- Added `python -m packages.demo_cache.purge_expired` as a customer-approved
  one-shot scheduler target. It does not run automatically inside request
  processing or mutate other customer cache tables.
- A regression test confirms bounded deletion of expired rows, preservation of
  non-expired entries and rejection of invalid cleanup limits.
