# AccessProof V1 — Local Hardening and Customer-Readiness Review
**Date:** 21 October 2026  
**Scope:** Actual local working tree at /home/white-devil/Downloads/accessproof/f15; isolated synthetic tests.  
**Decision:** **Not approved for unrestricted enterprise production.** Conditionally ready to prepare a narrowly scoped, nonproduction Google Workspace + customer RAG pilot, subject to the release gates below. **No production deployment was performed.**

## What was actually executed
- Inspected actual Python Guard, normalized ACL ingestion, directory synchronization, worker scheduling, OAuth refresh, provider connectors, and Protect readiness.
- Copied source into isolated snapshot, excluded .env, databases, backups, customer credentials, and live infrastructure. Tested with process-unique SQLite, synthetic providers/users and a fake customer RAG.
- Demonstrated **three initially failing adversarial tests** in isolation:
  1. Suspended user retained published allow with a direct Drive grant.
  2. Removed user was left active after a complete directory snapshot.
  3. A later Drive revoke was misclassified as stale after group membership events because the system globally compared a small Drive ACL sequence with a millisecond timestamp from directory events.
- Fixed confirmed defects with permanent regression coverage, then added hardening tests for group deletion, revocation during suspension and reactivation, worker scheduling, readiness freshness, and malformed OAuth token responses.
- Merged verified source edits safely into the active **local** worktree with exact SHA-256 premerge comparison. Original files backed up under `premerge-backups/`. Existing unrelated edits preserved.

## Verified fixes

| ID | Severity | Fix (in local source) | Test |
| --- | --- | --- | --- |
| AP-20261021-01 | Critical | Employee suspension re-resolves all published permissions, not merely the employee database row; denies inactive identities. Resuming a valid employee rechecks retained grants. | `test_suspended_employee_is_denied_despite_existing_direct_document_grant` |
| AP-20261021-02 | Critical | Accounts absent from a *completed* paginated directory snapshot are marked removed and existing Guard decisions republished as denies. | `test_removed_employee_not_left_authorized_by_previous_snapshot` |
| AP-20261021-03 | Critical | Resolve ACL grants and directory membership events within their own revision domains. Remove invalid global cross-type staleness comparison; keep entity-level replay checks and monotonic Guard policy versions. | `test_acl_revoke_after_group_membership_events_must_override_stale_allow` |
| AP-20261021-04 | High | Groups absent from a complete directory snapshot retire memberships and existing group-based allows. | `test_deleted_group_retires_memberships_and_denies_existing_group_grant` |
| AP-20261021-05 | High | A revoked Drive permission is still reconciled against a suspended employee; old grant cannot return on reactivation. | `test_drive_revoke_while_employee_suspended_reconciles_stored_grant` |
| AP-20261021-06 | Medium | New validated sources are due for employee sync until their **directory cursor**, not source validation timestamp, reports a successful sync. | `test_new_connected_source_directory_sync_is_due_even_when_validated_recently` |
| AP-20261021-07 | High | Protect readiness now requires fresh, successful **both Drive ACL and employee/group directory** synchronization; stale directory cannot be presented as ready. | `test_protect_readiness_requires_fresh_directory_not_just_drive_acl` |
| AP-20261021-08 | Medium | Reject missing/empty access tokens and invalid `expires_in` in OAuth refresh responses without overwriting saved credentials. | Six invalid-response parameterized cases |
| AP-20261021-09 | Usability | Google Drive V1 source setup now tells the administrator that directory read access and offline refresh are required; it still correctly discloses no automatic Google consent. | Frontend lint and TypeScript checking |

Modified local sources: `apps/api/accessproof_api/guard_pipeline.py`, `apps/api/accessproof_api/directory_sync.py`, `apps/api/accessproof_api/acl_sync.py`, `apps/worker/accessproof_worker/main.py`, `apps/api/accessproof_api/app.py`, `packages/auth/oauth_refresh.py`, `web-v2/app/sources/page.tsx`.
Added tests: `tests/security/test_directory_lifecycle_fail_closed.py`, `tests/security/test_oauth_refresh_protocol.py`.

## Local verification evidence
- **Active local repository Python suite:** **378 passed, 5 deprecation warnings**, return code 0. Log: `live-full-pytest.log`.
- **Python Ruff:** PASS on apps, connectors, packages, tests.
- **TypeScript RAG SDK:** **4 passed** (`evidence/ts-sdk.log`).
- **Frontend TypeScript and ESLint:** PASS; including following small onboarding copy change (`evidence/frontend-typecheck.log`, `evidence/frontend-lint.log`).
- **Browser Playwright desktop/mobile:** **21 passed, 1 intentionally skipped**, with fake API replies (`evidence/browser-e2e.log`). This does not prove real Google Workspace, RAG, or live production setup.
- **Frontend Webpack build:** command succeeded from isolated snapshot (`evidence/frontend-webpack-build.log`). It warned about files skipped in standalone tracing because `node_modules` was symlinked to the original repo; the deployment image is therefore NOT verified from this build alone.
- **Git diff --check:** PASS after merge.
- No real cloud/customer identities, credentials, Drive files, production databases, or external endpoints were used in the tests.

To re-run safely:
```bash
cd /home/white-devil/Downloads/accessproof/f15
TMPDIR=/dev/shm env -u PYTHONPATH -u ACCESSPROOF_CURRENT_DATABASE_URL PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  .venv/bin/python -m pytest -p pytest_asyncio.plugin -o addopts='' -q
.venv/bin/ruff check apps connectors packages tests
npm --prefix web-v2 run typecheck
npm --prefix web-v2 run lint
```

## Remaining production release blockers

**P0 — real provider and customer boundary checks (not run).**
1. **Administrator-approved real Google Workspace OAuth consent / refresh:** Current UI still accepts manually supplied access/refresh tokens; no completed self-service Google authorization flow. Validate actual Drive and Admin SDK Directory API permissions with a dedicated sandbox and Google-admin approval, not a personal access token.
2. **Real Drive permission semantics:** Shared Drives, inherited access, permission additions/removals, Google Groups including nested groups, ownership/move/delete/shortcut behavior, aliases, external collaborators, throttling/pagination, and shared-folder boundaries. Use synthetic files and disposable sandbox identities.
3. **Revocation latency and fail-safe objective:** Default scheduled ACL poll is **300s**, directory sync **900s**, known ACL reconciliation **3600s**, followed by event processing and Guard sync. These are not instant permission-change triggers. Measure end-to-end time from actual Google revocation to denied RAG output and define a customer-approved SLO. Confirm Guard blocks or refuses Protect when either source is degraded/stale. Do not claim instantaneous revocation.
4. **Live RAG SDK integration:** Verify with an actual disposable customer-style RAG application (real framework, chunk IDs, citations, caching, regeneration, streaming/buffering, exceptions). Prove restricted content never reaches model or end-user and that allowed positive controls still work.
5. **Actual enterprise identity:** Verify signed OIDC/JWKS ID tokens and real audience/issuer/tenant claims from an authorized test IdP. Include wrong-tenant, expired and revoked identities, employee offboarding, aliases and identity mapping.

**P0 — operational release checks (not run).**
6. Rehearse real container/VM installs, Guard enrollment, upgrades, signed packages, automated secret rotation, rollback, backups and point-in-time restore in nonproduction.
7. Test PostgreSQL/Redis/broker persistence, migrations, tenant row-level isolation, worker restarts, parallel workers, failover, no double-consumption, rate limits, overloaded queues, authentication logging and observability under staging load.
8. Run sustained staging soak, fault injection, memory/CPU/throughput, pause/resume and Guard disconnection tests.
9. Complete independent security review, cloud IAM/secret permissions, alert handling, incident response, privacy/legal review and customer data handling before broad enterprise production use.

**Product behavior still missing:**
- A true one-click/admin-approved Google OAuth consent onboarding flow (the current flow is manual pilot setup).
- Push-driven near-real-time provider notifications; current automation is poll-based. Real-world change visibility is provider-dependent.
- Real provider/IdP integration certification and measured customer-specific SLO.

## Controlled pilot release gate
Proceed only with a disposable Google Workspace tenant and root folder, qualified administrator, signed verified employee identity, customer-side Guard, one explicitly instrumented buffered RAG route, documented Shadow→Protect validation, controlled positive/negative/revocation tests, measured latency, and authorized rollback. Keep production customer data and real employee access out of the validation environment until the gates are met.

**Verdict:** Significant source-level vulnerabilities were found and corrected, with full available local tests passing. **This is not a guarantee of error-free customer integrations, a production security certification, or proof that all conceivable gaps were found.**
