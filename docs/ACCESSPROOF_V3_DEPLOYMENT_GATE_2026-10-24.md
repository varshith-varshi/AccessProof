# AccessProof V3 — Deployment and customer-pilot readiness gate
**Date:** 2026-10-24 (Asia/Kolkata)
**Target:** Existing current AccessProof repository, preserve all existing changes
**Verdict:** Locally verified reference security architecture; **NOT CERTIFIED FOR UNIVERSAL PRODUCTION DEPLOYMENT**

## 1. Implemented during this remediation

Existing V3 fixes are recorded in `docs/ACCESSPROOF_V3_FIX_REPORT_2026-10-24.md`:
cache size bounds, streaming-body webhook limit, atomic event claims, Drive
shared-drive changes, Drive watch renewal, guided Google OAuth, signed cache
manifest enforcement, retrieval-system instruction hardening and a working RAG
Docker image. The original worktree contained extensive uncommitted work and
was not reset, committed or overwritten.

New follow-on work:
- `connectors/google_drive/snapshot_agent.py`: customer-controlled periodic
  Drive root inventory, independent provider-backed `text/plain` content
  acquisition, per-chunk source attestation and atomic snapshot publication.
  Partial/provider-failed scans never publish a trusted snapshot.
- `packages/demo_cache/trusted_snapshot.py`: tenant/app/source-bound,
  size-limited, expiry-checked, signed document snapshot loading. Rejects
  tampered bytes, duplicate identifiers, symlinks, missing provenance,
  untrusted derived roles and stale attestations.
- `packages/auth/google_source_token.py`: owner-only Google OAuth credential
  file refresh with Google-pinned token endpoint, temporary-file crash recovery,
  safe token rotation and no RAG exposure of secrets.
- `drive-rag-demo/app.py`: production Protect route refuses unsigned source
  fallback; optional trusted snapshot replaces old synthetic Drive fetch for
  authorized generation. New `/health/ready` requires signed, fresh sources
  and live Guard readiness (and Redis when configured).
- `apps/gateway/accessproof_gateway/app.py`: post-authorization OpenAI-style
  buffered SSE compatibility; **no first byte before both Guard layers allow**.
  This is not upstream live model token streaming.
- `drive-rag-demo/Dockerfile.ingester`, Compose integration and
  `docker-compose.customer-signed-rag.yml`: separate source signer container
  and shared read-only ingestion snapshot for the production-mode reference
  RAG. Legacy test chat stays disabled in the hardened overlay.
- Refreshed compatible Python dependency ranges, and added tests/runbooks.

## 2. Verification available from the current machine

| Check | Evidence | Result |
|---|---|---|
| Full Python suite after signed-ingestion patch | `/tmp/accessproof_all_after_signed_ingestion_20261024.log` | 698 passed, 1 known expected failure, 0 unexpected |
| Source snapshot signature, expiry, tamper and production route | `/tmp/accessproof_trusted_snapshot_hardened.log` | 6 passed |
| Google OAuth renewal and file rotation | `/tmp/accessproof_token_renewal_tests.log` | 4 passed |
| Combined signed-source/cache/stream/ready focused checks | `/tmp/accessproof_new_features_tests.log` | 28 passed |
| Buffered SSE + real TCP Gateway regression | `/tmp/accessproof_buffered_sse_tests.log` | 17 passed |
| Redis and PostgreSQL disposable real services | Earlier Oct 24 remediation log | Verified synthetic revoke and atomic claim |
| Source ingester and RAG Docker build | `/tmp/accessproof_ingester_pinned_20261024.log`, `/tmp/accessproof_rag_pinned_20261024.log` | Built locally |
| React frontend build, lint, typecheck | Earlier Oct 24 verification | Passed |
| Hardened Compose syntax + Ruff | Current local tooling | Passed |
| Fresh disposable Alembic migration | Earlier Oct 24 verification | Upgrade through `g1a7c3d8e9f0` passed |

The full suite ran before the *last* token-file and readiness changes.
Targeted regressions passed afterward. Do not represent the full suite as
rerun after every last change unless it actually is.

## 3. Controlled, customer-authorized pilot activation

Prerequisites:
1. A separate authorized Google Workspace **test** tenant, read-only Drive and
   Workspace Directory permissions, a Google OAuth web-app client with a
   registered redirect URI, and real test employees/groups.
2. A customer-supplied **mode 0600** Ed25519 ingestion key file and matching
   public key, with the secret mounted ONLY into the private ingester.
3. A customer-owned mode 0600 Google OAuth token JSON under a private
   writable secrets directory for refresh-token rotation; secrets never enter
   the RAG container.
4. Correct `ACCESSPROOF_DEMO_SOURCE_ID`,
   `ACCESSPROOF_DEMO_APPLICATION_ID`,
   `ACCESSPROOF_DEMO_ATTESTATION_TENANT`, Guard and OIDC bindings,
   and one approved folder whose supported file content can be independently
   ingested (reference ingester supports `text/plain` and native Google Docs text exports only).
5. Private Redis with auth/TLS/ACL isolation if using signed answer caching.
6. Explicit approval from the owner of the customer Docker host and network.

After reviewing `docker compose ... config` and mounted secret permissions,
the *reference* signed RAG stack can be started in a sandbox with:

```sh
docker compose -f docker-compose.yml \
  -f docker-compose.customer-signed-rag.yml \
  --profile guard --profile drive-rag --profile drive-rag-ingest \
  up -d --build
```

This does not automatically wire an arbitrary production RAG chatbot.
Inspect the existing Gateway customer cutover/network boundary runbook before
sending any employee traffic to the Gateway.

## 4. No-go gates that cannot be completed in a synthetic container

**Provider and authorization gate**
- Live Google OAuth/Directory consent and actual test users, groups, nested
  groups, shared drives, inheritance, moves, links, removals and content
  provenance were not accessed or verified.
- Live Google `changes.watch` callback reachability, renewal timing, missed
  notifications, Google Groups update events, and latency from provider revoke
  to Guard denial were not measured.
- SharePoint/OneDrive effective permissions, Graph OAuth, tenant owner approval
  and customer-side Protect are **not** provider-certified.

**Customer RAG bypass gate**
- Universal zero-code instrumentation cannot protect arbitrary application
  cache/tool/model/database/background/WebSocket paths. An arbitrary customer
  route can serve content without calling AccessProof unless network/route
  interception or complete instrumentation is independently proven.
- Arbitrary LangChain/LlamaIndex/Haystack/custom app and Memcached/proprietary
  caches are not automatically covered.
- Buffered SSE is supported on the known Gateway route; live upstream token
  streaming, additional agent/tool actions and uninstrumented assistant memory
  are not certified.

**Operational gate**
- Real multi-worker multi-AZ failover, database/Redis disaster recovery,
  private-model egress proof, credentials rotation across replicas, enterprise
  load p95/p99, monitoring/alerting, performance SLOs and external penetration
  testing remain outstanding.
- Customer-specific network bypass challenges must succeed. Never claim
  `one-click` or `universal` until those checks are green.
- Signed reports attest test-runner observation; source-of-truth cloud-provider
  observation still needs independent live validation.

**Release decision:** `NO-GO` for generic enterprise production marketing.
`GO` only for a constrained, explicitly authorized sandbox/pilot of the
reference `Google Drive text/Google Docs -> signed ingester -> Python RAG/Redis ->
Guard/Gateway` architecture after the owner supplies the required external
credentials, network routes, and test identities, and all mandatory customer
validation gates pass. No deployment has been made to production.

## 5. Final local reference deployment rehearsal

After the initial report, the following additional checks were completed:

- Full Python suite re-executed with exit code 0:
  **703 passed, 1 known expected failure, 0 unexpected failures**. Log:
  `/tmp/accessproof_final_full_suite_20261024.log`.
  Later changed Google Docs ingestion was also covered by its own 14 passing
  unit/security regressions (`/tmp/accessproof_google_docs_verified_ingestion.log`).
- A separate, self-contained three-container rehearsal was added as
  `scripts/signed_reference_docker_smoke.py`; its first execution finished
  with exit code 0. It built a synthetic signed source, started a fake Guard,
  launched the hardened-mode reference RAG Docker image and real Redis in a
  disposable Docker network, then proved a first allowed answer, authorized
  signed cache hit, and cache denial after revocation of the **same synthetic
  employee**. Log: `/tmp/accessproof_full_docker_signed_cache_revoke.log`.
  No real customer data, identity tokens, Google APIs, or production services
  were accessed. All disposable containers and the network were removed.
- The production-mode Docker route returned HTTP 503 at both
  `/health/ready` and `/v1/protected-chat` without Guard/trusted-source
  readiness. This is deliberate, not a deployment error.
- Continuous ingestion now supports source-attested Google Docs
  **text exports** in addition to text/plain. Initial/final provider
  version, MIME type, boundary and modified-time checks are enforced.
  Other document formats remain unsupported.
- The owner-only OAuth credential-store, source snapshot and signed-cache
  failure controls have targeted passing regression tests. A deliberately
  disconnected Redis cache blocks rather than regenerating unchecked output.
- An additional Google API documentation review confirms that complete
  shared-drive change detection requires processing both user and
  **each relevant shared-drive change feed**. The current user-scoped Drive
  push integration plus bounded known-file rechecks has **not** implemented
  all per-drive feeds. Do not certify all shared-drive revocation events.

### Still blocked despite green local tests

The reference route is suitable for authorized technical **pilot validation**,
not open-ended enterprise production certification. A real Google Workspace
owner must consent and supply tenant-backed test accounts. A real SharePoint
tenant is likewise necessary before signing off SharePoint Protect. The
customer's actual RAG topology, caches, tool paths, streaming/WebSockets and
network egress must be certified independently; testing our reference sidecar
does not certify a different customer application. Production failover/load,
operational monitoring and independent audit/evidence integrity checks remain
required.

These are hard **NO-GO** release conditions for a claim of universal,
zero-code, continuous permission enforcement. No production deployment,
live provider mutation, or rollback was attempted. The original dirty
working tree remains preserved with changes uncommitted.
