# AccessProof V1 — Google identity bridge and release gates
**Date:** 26 October 2026
**Repository:** `/home/white-devil/Downloads/accessproof/f15`
**Scope:** Google Workspace directory + explicitly approved Google Drive roots only.

## Changes implemented in this continuation

- **Provider-backed principal binding.** Workspace Directory stable user/group IDs
  are distinguished from Google Drive permission IDs. Production sync uses
  Drive v2 `permissions.getIdForEmail` with the approved OAuth credential
  before persisting an authorizing identity. Matching email strings or directory
  IDs alone cannot authorize a Drive grant.
- **Fail-closed data modeling.** `GuardSubject.drive_permission_id` and
  `GuardGroup.drive_permission_id` are nullable and uniqueness-constrained per
  organization/provider. Missing and ambiguous provider resolutions never
  establish ALLOW. Suspended/removed employees lack an active direct grant.
- **Group ACL arrives before directory.** Unknown Drive permission groups are
  non-authorizing provisional records. A subsequent complete, validated
  directory sync can promote an exact provider-ID match, preserving prior
  source-scoped grant references. A recycled email never promotes a group.
- **Legacy authorization invalidation.** When the verified identity bridge
  changes, former source grant paths are invalidated, explicit effective-policy
  recalculation is queued, and a full approved-root ACL inventory is required
  before declaring source health.
- **Cross-tenant group isolation.** Even a locally stored/internal group key
  is rejected if its group organization/provider doesn't equal the bound source.
- **Google OAuth lifecycle.** OAuth callback records durable source-scoped
  directory/ACL synchronization work. Periodic workers retry with bounded
  backoff, and no longer depend on the administrator leaving a tab open.
- **Guard atomicity.** Policy decisions, source/app bindings, identity mappings,
  authorization revisions, and the installed-ACK outbox are committed
  together in one Guard-local SQLite transaction. Interrupted steps roll back;
  interrupted ACK delivery is retried after Guard restart.
- **Authorization propagation gap.** Source Protect readiness is false while
  provider ACL changes still have unresolved Guard permission events, or
  machine policy distribution is not yet acknowledged as installed.
- **Operator-owned OAuth credentials.** A customer supplies neither server
  OAuth secret nor provider refresh tokens in the standard onboarding UI.
  Worker obtains OAuth client credentials from operator runtime configuration.

## Verified test evidence

- Local unit/security checks have covered Google permission-ID resolution,
  provisional/verified group promotion, user suspension, stale email reuse,
  duplicate ID rejection, ambiguous provider lookup, atomic policy snapshots,
  interrupted ACK retry, OAuth initialization, worker retry/rollback, and
  end-to-end synthetic HTTP RAG revocations.
- Migration check: full Alembic migration chain to
  `m6f1a9c2d318` passed against a **new isolated PostgreSQL 16** container;
  verified both permission-ID columns, two unique constraints and RLS enforced
  on three evidence-related tables. The disposable container was removed.
- Web-v2: TypeScript and 3 focused Google onboarding Playwright tests passed.
- Selected Google/Guard/source/callback/RAG regression suite: **60 passed**
  on a separate disposable SQLite database, with **0 failures**. Isolating
  the test database prevented collisions with another concurrent test process.
  See `/tmp/ap-v1-isolated-selected.log` (last line `ISOLATED_TEST_EXIT:0`
  in process output).
- These are **simulated tests and local infrastructure checks**, not live
  enterprise provider certification or a measured revocation SLO.

## Release assessment — NO-GO for unrestricted enterprise Protect

1. A real, authorized Google Workspace domain/admin OAuth consent, supported
   scope verification and Google OAuth publication/security-review requirements
   remain external dependencies. The Google Drive permission-ID v2 endpoint
   needs real-tenant behavioral and quota verification.
2. Prove the *effective* permission semantics of customer Shared Drives,
   inherited ACLs, limited-access folders, shared-drive membership, nested
   groups, and account suspension against Google with independent employee
   access checks, rather than only mocks.
3. Measure Google revoke-to-Guard-denial latency at p50/p95/p99 under load;
   event notifications are signals to resynchronize, not proof of instantaneous
   authorization. Agree an SLO and safe degraded behavior in writing with
   the first partner.
4. Customer-side Guard/Gateway/SDK must have exactly one certified,
   non-bypassable RAG route, backed by attested source ingestion and Layer 1 +
   Layer 2 adversarial evidence. Unknown caches, streams, tools and agents must
   fail closed in production Protect unless individually certified.
5. Run deployment artifact signing/build verification, schema migration and
   rollback, backup/restore, credential rotation/recovery, load tests, outage
   drills, audit delivery under failure and third-party security testing.
6. Complete tenant-isolation validation with the actual PostgreSQL application
   role and least-privileged database users (the migration smoke test used the
   new container's database administrator).
7. Do not call a source 'protected' merely because its directory or ACL cursor
   is fresh. Unresolved events and policy acknowledgements must have drained.

## Controlled first-customer path

Seek a technical validation partner with **one approved Google Drive root**,
synthetic documents/canaries and authentic Workspace test employee accounts.
Complete onboarding -> full directory and ACL sync -> certified RAG route ->
controlled direct/group/folder/shared-drive revocations -> crash/restart tests ->
auditable evidence. Start in Shadow with test data, move to limited Protect
only after signed customer approval and the scoped release gates above.

**No production deployment, customer credential access, destructive cleanup,
or blanket 'production-ready' certification was performed in this work.**
