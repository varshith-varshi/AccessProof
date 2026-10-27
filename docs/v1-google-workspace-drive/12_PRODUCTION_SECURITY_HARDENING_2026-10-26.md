# AccessProof V1 — Security hardening continuation (26 October 2026)

**Scope:** Google Workspace + Drive as the only published production V1 source.
**Worktree:** `/home/white-devil/Downloads/accessproof/f15` (`web-v2`).
**Release verdict:** **NO-GO for unrestricted customer Protect / sensitive data.**
Changes are local and not deployed. No authorized real Google tenant, OAuth
verification, customer RAG app, enterprise network or production DB was tested.
Existing user changes were preserved; no reset or cleanup.

## Implemented in this continuation

### 1. Atomic, restart-safe customer Guard authorization state
- `apps/guard/accessproof_guard/cache.py`: installation of policy grants,
  application bindings, verified identity mapping and revision records shares
  one durable SQLite transaction; nested writers no longer commit independently.
- `apps/guard/accessproof_guard/sync.py`: installed ACK follows the complete
  commit. Installed-ACK versions are journaled in the same transaction and
  retried after process/network interruption and restart.
- `tests/security/test_guard_atomic_snapshot_install.py`: injected failures
  after every installation step, restart rollback, invalid binding, network-ACK
  failure and retry. This proves **local SQLite atomicity**, not storage-cluster
  durability or arbitrary customer route correctness.

### 2. Durable Google source synchronization
- Google OAuth callback commits source-scoped `directory` and `acl` queued
  cursors together with encrypted refresh credentials. An operator closing
  the browser does not lose the bootstrap.
- Worker checks for queued work approximately every 30s, without increasing
  all healthy-source provider polling to that rate. Failed directory snapshots
  roll back partial employee/group records, retain a durable degraded error,
  and have bounded retry backoff.
- The UI no longer issues redundant browser-side directory bootstrap POSTs.
- The customer-triggered `sync-directory` API now also rolls back partial
  provider reads **before** committing a durable degraded state, and has a
  regression simulating an exception after an employee row is flushed.
- `tests/integration/test_google_oauth_bootstrap_jobs.py` verifies closure-
  independent jobs, rollback, backoff and recovery.
- **Remaining:** source-scoped lease fencing for multiple workers, durable
  provider quota budgets, retry-after respect, large-tenant soak and change
  channel recovery must be proven on staging/real tenant.

### 3. Policy delivery and authorization event backlog gates
- Worker permission-event claims now use an atomic conditional UPDATE
  instead of SELECT/mutate/COMMIT susceptible to duplicate claims.
- Guard machine source-health refuses `healthy` when there are unresolved
  permission events or unacknowledged policy distributions for that source.
- Activation preflight includes `PERMISSION_EVENTS_RESOLVED`. Do not
  equate a fresh Drive ACL read to completed customer Guard enforcement.
- Synthetic HTTP RAG lifecycle tests now explicitly cover safe blocking
  *during* a revocation/ACK transition and ordinary denial afterward.

### 4. Provider-backed Google Drive principal identity bridge
- Google Workspace Directory `user.id`/`group.id` and Drive permission
  `Permission.id` are different opaque values. Source-side email matching
  is forbidden for production ALLOW decisions, including recycled aliases.
- `connectors/directory.py`: fixed-origin, no-redirect Google Drive v2
  `permissions.getIdForEmail` lookup (officially supports `drive.readonly`).
- `apps/api/accessproof_api/db.py`: separate optional `drive_permission_id`
  on subjects and groups, with organizational uniqueness constraints.
- New migration `m6f1a9c2d318_google_drive_permission_ids.py`.
- `apps/api/accessproof_api/directory_sync.py`: resolve/cached verified
  Drive IDs for active users and groups; reject missing, duplicated or changed
  IDs; adopt only provisional ACL groups matching a trusted Drive permission ID.
  On a changed identity map, queue complete approved-root ACL inventory,
  invalidate old grant paths, and queue fresh DENY/ALLOW recalculation.
- `apps/api/accessproof_api/acl_sync.py`: production user/group matching uses
  only provider-backed Drive permission IDs; unknown groups remain inactive.
  Suspended or removed principals never satisfy a direct grant.
- `apps/api/accessproof_api/app.py`: a legacy green directory cursor cannot
  certify Protect until active Workspace users and groups have verified Drive
  permission IDs; Guard and activation both check this.
- `tests/security/test_google_drive_permission_id_bridge.py`,
  `tests/security/test_google_drive_permission_id_binding.py`,
  `tests/security/test_google_drive_stable_principal_mapping.py`:
  mismatched Directory IDs, recycled email, suspended users, provisional
  groups, provider failures, legacy ALLOW invalidation and migration coverage.
- The migration completed from blank SQLite to Alembic head
  `m6f1a9c2d318`. The test models preserve legacy suspended-subject discovery
  only for local revocation cleanup; production ALLOW never trusts those users.
  **PostgreSQL migration/rollback and Google provider validation remain unexecuted.**

## What this does not prove

1. Google Workspace delegated OAuth operator approvals and restricted-scope
   verification, including tenant-specific consent and provider quotas.
2. Independent effective-authorization checks covering direct/group/nested
   grants, Shared Drives, limited-access folders, link shares, changes/moves
   and email renames. A successful provider response is not independent proof.
3. End-to-end Google change -> policy event -> Guard install -> first deny
   latency, including network loss and multi-worker crashes. No revocation
   SLA/SLO is certified yet.
4. Exhaustive enumeration of all approved Drive content for the delegated
   principal. Consent does not imply access to everyone's My Drive.
5. Full customer-specific RAG bypass coverage, verified employee OIDC
   audience/issuer, trusted content attestation, LLM generation, cache,
   streaming/tools and every response channel.
6. Staging PostgreSQL RLS/migration concurrency, backups and actual restore,
   multi-node/high-availability tests, load/soak, disk-full and incident
   recovery drills. A local SQLite Guard rollback test is not HA evidence.
7. Independent security assessment or SOC 2/ISO 27001 certification. Neither
   compliance certification nor commercial Protect eligibility is claimed.

## Verification scope and commands

See /tmp logs from this session:
- `/tmp/ap-v1-atomic-suite.log` and `/tmp/ap-v1-ack-outbox-final.log`.
- `/tmp/ap-v1-durable-backend-final.log`,
  `/tmp/ap-v1-security-hardening-final.log`.
- `/tmp/ap-v1-customer-lifecycle-retest3.log`: 3 HTTP RAG adapters passed.
- `/tmp/ap-v1-durable-ui.log`: 3 Google browser flows passed.
- `/tmp/ap-v1-google-legacy-cleanup-final2.log`: 13 identity regression tests passed.
- `/tmp/ap-v1-unified-hardening-suite.log`: 46 selected hardening tests passed.
- `/tmp/ap-v1-manual-dir-atomic-retest.log`: 8 security tests passed after fixes.
- `/tmp/ap-google-schema-migration.log`: fresh SQLite migration.
- Initial full Python run reached early failing HTTP lifecycle assertions
  under the stricter fail-closed behavior, was stopped for diagnosis; those
  lifecycle tests were corrected to require ACK settlement and passed
  separately. **Do not report an all-green full repository suite** unless a
  new complete run finishes.

Run before release:
```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest \
  -p pytest_asyncio.plugin -p anyio.pytest_plugin -q
cd web-v2 && npm run lint && npm run typecheck && npm run build && npm run test:e2e
```
Execute PostgreSQL migration in a disposable staging DB first with backups,
then validated release artifacts; never use developer SQLite results as a
substitute for the production database.

## Go/no-go decision

- Synthetic local demo and controlled staging/Shadow pilot: **possible**
  within the exact supported capabilities and with written customer approval.
- Customer production Protect involving confidential documents: **NO-GO**
  until all applicable P0 gates above are independently validated, and
  rollback/incident recovery are rehearsed.
- Deployment, external provider API setup, customer secrets and billing were
  deliberately NOT modified by this continuation.
