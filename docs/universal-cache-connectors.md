# AccessProof cache-agnostic connectors (V3 reference implementation)

**Status: Local integration implemented and tested.** Supported answer-cache
backends: Redis, Memcached, PostgreSQL, single-process Python memory, or an
explicit custom Python callback adapter. This is **not** a universal network
tap, automatic discovery of existing caches, automatic framework hooking or
authorization for cache outputs that bypass AccessProof.

## Two integration models

**A. Integrated Python RAG — signed cache wrapper.** Customer code explicitly
stores approved answers using the signed dependency manifest and retrieves
them using fresh employee authorization:

```python
from packages.rag_sdk.cache_connectors import (
    ProtectedAnswerCache, RedisBackend, MemcachedBackend,
    SQLAlchemyBackend, MemoryBackend, CallbackBackend,
)
from packages.rag_sdk import (
    CachedAnswerManifestSigner, CachedAnswerManifestVerifier,
    SourceAttestationVerifier, GuardClient,
)

# Construct ONE backend per process; use a thread-safe pool for concurrent
# Memcached traffic, or provide a pooled Redis client / SQLAlchemy engine.
cache = ProtectedAnswerCache(
    backend=your_configured_backend,
    guard=GuardClient("http://customer-guard:8080"),
    tenant_id=verified_tenant_id,
    application_id=registered_rag_app_id,
    signer=CachedAnswerManifestSigner(key_id=key_id, private_key=private_key),
    verifier=CachedAnswerManifestVerifier(
        tenant_id=verified_tenant_id, trusted_keys={key_id: public_key},
    ),
    source_verifier=SourceAttestationVerifier(
        tenant_id=verified_tenant_id, trusted_keys=trusted_source_public_keys,
    ),
)

hit = cache.get_authorized(
    question=question, employee_token=verified_employee_jwt,
)
if hit is not None:
    if hit.decision != "allow" or hit.answer is None:
        raise PermissionError("Cached answer cannot be released")
    return hit.answer

# A miss is NOT proof that documents are authorized. Independently run
# Layer 1 -> generation -> Layer 2 in the protected RAG pipeline. ONLY after
# the two-layer result is approved, cache its exact trusted dependencies:
cache.store_approved(
    question=question, protection=protected_result,
    authorized_sources=source_chunks_actually_used_by_the_model,
)
return protected_result.response
```

The caller **must** ensure the signed dependencies come from a trusted source
ingester and match every resource that actually influenced generation. Never
store user-supplied resource IDs or trust an old Guard allow decision.
The signing private key belongs only in the approved cache-write service.

**B. Existing non-Python RAG — HTTP release check.** An application with
an existing cache can keep that cache as-is but must instrument its response
return path to call the customer-side Gateway after retrieving a cached entry:

`POST /v1/cache/authorize`, bearer token = the *verified employee identity*.

Required JSON fields: `tenant_id`, `application_id`, `answer`,
`producer_id`, `dependencies` (list of source/resource/chunk/version/digest/
source-attestation objects), `manifest_token` (the signed cache manifest),
and optional `request_id`. Configure pinned Ed25519 public keys under
`ACCESSPROOF_GATEWAY_CACHE_PUBLIC_KEYS_JSON` and source-ingestion keys under
`ACCESSPROOF_GATEWAY_ATTESTATION_PUBLIC_KEYS_JSON`.

A successful decision returns the authorized answer and citations. An invalid
signature, wrong tenant, stale manifest, missing trusted key, revoked employee,
blocked Layer 2, or Guard failure returns an error with **no answer text**.
The Gateway must be on the delivery path. A bare answer without a trusted
dependency manifest is **not safely reusable**.

This HTTP method is cache-technology independent; it does **not** read external
cache storage or automatically discover/secure alternate answer-return paths.

## Selecting one backend for the supported customer-side reference RAG

The reference application `drive-rag-demo/app.py` accepts exactly one cache.
Set the backend and its connection configuration on the **customer-owned RAG
process only**, not in the browser:

| Selection | Required settings | Notes |
|---|---|---|
| Redis | `ACCESSPROOF_DEMO_CACHE_BACKEND=redis`; `ACCESSPROOF_DEMO_CACHE_URL=redis://...` or `rediss://...` | Backward compatible if only URL is provided |
| Memcached | `ACCESSPROOF_DEMO_CACHE_BACKEND=memcached`; `ACCESSPROOF_DEMO_CACHE_MEMCACHED_HOST=host`; optional port (default 11211) | Customer-private network/TLS transport and access restriction are required for production; use a pooled client |
| PostgreSQL | `ACCESSPROOF_DEMO_CACHE_BACKEND=postgresql`; `ACCESSPROOF_DEMO_CACHE_SQLALCHEMY_URL=postgresql+psycopg://...` | Operator must provision dedicated table in an approved DB/schema |
| Python memory | `ACCESSPROOF_DEMO_CACHE_BACKEND=memory`; `ACCESSPROOF_ENV=development` | Single-process testing only; production rejects |
| Custom Python | Import `CallbackBackend` and `ProtectedAnswerCache` | Customer supplies byte-exact read/write/delete/health callbacks and TTL; no default one-click integration |

The reference RAG additionally needs its configured source public keys,
customer-side Guard/identity context, signed snapshot ingestion, and
`ACCESSPROOF_DEMO_CACHE_KEY_ID` plus
`ACCESSPROOF_DEMO_CACHE_PRIVATE_KEY_B64` (a **separate** Ed25519 cache signing
private key). The signing key must remain server-side.

Conflicting backend destinations are rejected. SQLAlchemy reuses a bounded
connection pool, and Memcached uses a pooled client.

**PostgreSQL provisioning (operator-approved action):**

```bash
ACCESSPROOF_DEMO_CACHE_BACKEND=postgresql \
ACCESSPROOF_DEMO_CACHE_SQLALCHEMY_URL='postgresql+psycopg://...' \
python -m packages.demo_cache.provision
```

Never run the schema step automatically against an unapproved customer
database. Memcached should be on a private authenticated/TLS-isolated network
or an approved protected transport; do not expose unauthenticated Memcached to
public networks.

## Behavioral guarantees and known limits

* Cache keys are tenant + application scoped. Entries use signed answer text,
  source IDs, document versions, SHA-256 content digests and source attestations.
* Cache hits require fresh Layer 1 and Layer 2 Guard authorization for the
  requesting employee. The previous cache writer's allow decision is not
  sufficient. Cross-tenant/application replays and signature tampering deny.
* Signed entries have bounded TTL and sizes. Unavailable caches or Guard
  services cannot cause a permissive fallback. An invalid hit must return a
  denial, not regenerate an unchecked answer.
* The customer application's network, framework, response caches, tools,
  embedded memory, CDN and alternate HTTP/WebSocket routes require separate
  bypass checks. An application that sends cached text to an employee without
  going through this integration remains **unprotected**.
* Cached output signed before a Drive permission revocation becomes blocked
  **only after** the authoritative authorization update reaches Guard. Actual
  Google Workspace propagation latency is not certified by synthetic tests.
* Redis, Memcached and PostgreSQL have passed disposable real Docker
  allow/cache/revoke/deny integration tests. A custom callback backend must
  pass equivalent customer-specific acceptance tests before Protect approval.

## Local verification (safe, synthetic only)

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -p pytest_asyncio.plugin -p no:cacheprovider \
  tests/security/test_universal_cache_connectors.py \
  tests/security/test_public_cache_connector_api.py \
  tests/unit/test_gateway_universal_cache.py

ACCESSPROOF_SMOKE_CACHE_BACKEND=redis \
  .venv/bin/python scripts/signed_reference_docker_smoke.py
ACCESSPROOF_SMOKE_CACHE_BACKEND=memcached \
  .venv/bin/python scripts/signed_reference_docker_smoke.py
ACCESSPROOF_SMOKE_CACHE_BACKEND=postgresql \
  .venv/bin/python scripts/signed_reference_docker_smoke.py
```

The script uses disposable local Docker containers, a synthetic signed
document, a fake Guard, and one ephemeral Redis/Memcached/PostgreSQL service.
It does not mutate real Google Workspace permissions or customer data.

**Release status:** Multi-backend storage compatibility locally implemented.
Automatic third-party cache interception, all-provider certification and
production customer route coverage remain unproven. Do not label the feature
a universally deployable zero-code cache interceptor.

### Read-only connector health check

After setting backend environment variables on the customer-owned process,
run:

```bash
python -m packages.demo_cache.check
```

It prints `CACHE_CONNECTOR_READY`, `CACHE_CONNECTOR_NOT_READY` or
`CACHE_CONNECTOR_NOT_CONFIGURED`, without exposing credentials. This
checks cache connectivity (and the required table for PostgreSQL); it does
**not** certify that the customer application's output routes pass through
AccessProof.

### PostgreSQL retention maintenance

PostgreSQL does not remove expired cache rows by itself. Schedule a
customer-approved periodic run of the bounded, one-shot SQL janitor:

```bash
ACCESSPROOF_DEMO_CACHE_BACKEND=postgresql \
ACCESSPROOF_DEMO_CACHE_SQLALCHEMY_URL='postgresql+psycopg://...' \
python -m packages.demo_cache.purge_expired
```

Each run deletes at most 1,000 expired entries from AccessProof's dedicated
signed-answer table, and never touches existing customer cache tables.
Repeat in a controlled scheduler until the expired backlog is cleared.
The employee request path never performs administrative cleanup.
