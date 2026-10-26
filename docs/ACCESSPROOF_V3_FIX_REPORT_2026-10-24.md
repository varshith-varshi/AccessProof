# AccessProof V3 audit remediation — local repository record (24 October 2026)

**Repository:** `/home/white-devil/Downloads/accessproof/f15` (existing dirty working tree preserved).
**Scope:** Code and automated tests only. No production migration, live OAuth,
customer network action, deployment cutover, provider user data, or Protect
certification occurred. Existing security release gates are deliberately intact.

## Remediations completed in the local worktree

1. `packages/rag_sdk/protection.py`: signed cache-hit delivery now enforces
   the configured UTF-8 response byte budget (`CACHE_RESPONSE_TOO_LARGE`).
2. `apps/api/accessproof_api/app.py`: the unauthenticated Google callback
   examines request-body chunks and rejects >8192 bytes before any full-buffer
   read, with an application-level reverse-proxy limit still required.
3. `apps/worker/accessproof_worker/main.py`: provider journal claiming now
   uses an atomic conditional UPDATE/RETURNING, removing the prior
   select-then-update duplicate-lease race.
4. `connectors/google_drive/adapter.py` and
   `apps/api/accessproof_api/acl_sync.py`: accept valid shared-drive change
   records identified by `driveId` and perform a bounded re-evaluation of
   known source resources. Fail closed on provider/large-index ambiguity.
5. `apps/worker/accessproof_worker/watch_lifecycle.py`: optional Google
   `changes.watch` channel registration, 3-day subscriptions, 6-hour renewal
   margin, encrypted channel tokens, replacement handoff and best-effort
   removal of superseded channels. Existing periodic ACL/directory poll stays
   enabled; no group push guarantee.
6. `packages/auth/google_consent.py`, Google API OAuth routes, new
   `GoogleSourceOAuthState` ORM + migration, and Sources UI: admin-initiated
   one-time/hashed state, encrypted PKCE verifier, fixed Google token URL,
   restricted read scopes, offline refresh, backend-only secret storage,
   source-root validation and replay protection. Requires a real Google Cloud
   OAuth client and organization authorization before any customer use.
7. `packages/demo_cache/protected_cache.py`, `drive-rag-demo/app.py`:
   explicit opt-in Redis signed-cache reference integration. The trusted
   reference RAG signs all attested source dependencies only after a full
   Guard success. Every cache hit rechecks current employee permission in
   Guard Layer 1 and Layer 2. Invalid, expired, oversized and revoked hits
   block without returning cached/model text. External, uninstrumented caches
   are NOT automatically protected.
8. `apps/gateway/accessproof_gateway/app.py`: externally sourced enterprise
   document text is no longer placed in a model `system` message, reducing
   privilege confusion from prompt-injection content. This does NOT guarantee
   semantic immunity to prompt injection or hallucinations.
9. `.env.example`, `.env.production.example`, all three Docker Compose
   variants, and dedicated runbooks expose the opt-in Google API OAuth,
   worker watch callback, and reference signed-cache settings in their actual
   target containers. Configuration was revalidated locally after the edit.

## Verification evidence

- Focused initial cache/webhook/event-claim regressions: 10 passed.
- Google watch, cache, Drive changes and ACL synchronization: 19 passed.
- Google OAuth flow and helper: 2 passed (synthetic provider).
- Signed reference Redis cache permit/revoke/deny: 1 passed (synthetic).
- Combined cross-layer security/Gateway/revocation/integration tests: 39 passed.
- Fresh disposable SQLite Alembic upgrade: successful through revision
  `g1a7c3d8e9f0`; no production database migrated.
- web-v2 ESLint, TypeScript typecheck, and Next.js production build: passed.
- Docker Compose configuration: passed; Ruff selected changed modules and
  `git diff --check`: passed.
- Complete Python suite: **690 passed, 1 expected failure, exit code 0**,
  with deprecation and known test-fixture warnings. Log:
  `/tmp/accessproof_full_suite_fix_20261024.log` (runtime ~425.54 s).
  The one expected failure remains the intentional legacy metadata-only
  provenance limitation; it was not converted into a false pass.

## Mandatory release blockers NOT solved or not independently verified

- Independent completeness certification of arbitrary existing customer RAG
  routing, model egress, opaque caches, tools, memory, background, WebSocket and
  streaming routes. No universal zero-code/one-click enforcement guarantee.
- Actual Google Workspace effective permissions including group changes,
  nesting, shared drive inheritance, moves and provider role propagation,
  authorized employee OIDC/JWKS, consent/refresh, live Google notifications and
  measured provider revoke-to-denial latency. Synthetic tests do not prove
  this. Shared-drive revalidation is bounded (20k known resources) and has
  not been live-provider certified.
- The ordinary demo Drive fetcher does NOT emit trusted source attestations.
  The trusted-ingestion CLI can generate signed `text/plain` manifests, but
  automated customer index ingestion and end-to-end real Drive-to-Redis
  deployment remain to be integrated and tested. Signed-cache protection
  remains opt-in and fails closed without attested inputs.
- Product-specific no-code adapters for arbitrary LangChain, LlamaIndex,
  Haystack, model provider caches and general Redis/Memcached are not complete.
  The reference RAG JSON route is protected; alternate customer paths require
  independent proof.
- Provider permission notifications are only hints, not authorization truth.
  The new watch lifecycle is off until explicitly configured with a reachable
  HTTPS callback; group changes remain periodically reconciled. No production
  latency SLO can be claimed.
- Real production PostgreSQL/Redis multi-worker leases under load, HA/failover,
  recoverability, alerting, quotas, full-model prompt injection resistance,
  incident response and external security review are not validated.
- Signed runner reports attest validated runner evidence; the control plane
  cannot independently observe every customer-side provider operation.
- Legacy metadata-only SDK provenance route remains intentionally restricted;
  it must not receive certified Protect status.
- Microsoft 365/SharePoint effective-permission Protect certification remains
  a separate task and was not changed by these Google Drive fixes.

## Next controlled customer validation

In an explicitly authorized disposable Workspace tenant, complete Google OAuth
and watch setup, ingest real signed test documents, run one approved customer
Python RAG/Redis/Gateway route, verify real employee OIDC subject mappings,
allow and denial, file/group revocations, cached-answer denial, missed events,
source/API outage and recovery, and generate a signed report that honestly
identifies provider observation versus runner attestation. Freeze a Git release
commit and prove deployment image matches it before a production pilot.

**Verdict:** meaningful local remediation; reference route readiness only.
**No blanket enterprise production-readiness certification.**

## Additional October 24 verification after first full suite

- `tests/unit/test_google_drive_v1_security.py` gained a synthetic
  shared-drive membership test exercising **the ACL synchronizer and
  Guard event processor**, not just provider JSON parsing. An initial
  permitted document grant was followed by a `driveId`-only change, which
  emitted and processed the needed revocation. The new regression passed.
- An isolated PostgreSQL 17 container exercised two simultaneous event
  claimers; only one received the event and `attempts == 1` remained true.
- An isolated Redis 7 container exercised the signed cache against real
  Redis commands; allow-then-deny behavior succeeded with no previously
  cached answer returned to a revoked synthetic employee.
- The reference Drive RAG Docker build originally succeeded but failed to
  start because `cryptography` was missing from
  `drive-rag-demo/requirements.txt`. The runtime dependency has now been
  declared (`cryptography>=46,<47`), the Docker image rebuilt successfully,
  and an ephemeral container passed `/health` plus a verified fail-closed
  HTTP 503 on `/v1/protected-chat` without a configured Guard.
- These follow-up checks have individual pass evidence, but the earlier
  `690 passed, 1 expected failure` complete-suite result predates the newly
  appended shared-drive regression. Re-run complete suite after freezing
  the tree for the final customer pilot release.
