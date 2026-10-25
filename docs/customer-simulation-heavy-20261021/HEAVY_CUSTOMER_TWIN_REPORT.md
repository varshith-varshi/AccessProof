# AccessProof V1 — Heavy Synthetic Customer Testing and Defect Remediation

**Test date:** 21 October 2026  
**Repository:** `/home/white-devil/Downloads/accessproof/f15`  
**Execution:** On user's connected Ubuntu machine, using an isolated snapshot first, then safely merging changes into the active *local* checkout. No production deployment or third-party/customer testing.

## Exact status
- **388/388 Python tests passed in the active checkout**, with five dependency deprecation warnings.
- **4/4 TypeScript RAG SDK tests passed.**
- **Browser Playwright desktop/mobile:** **21 passed, 1 intentionally skipped** using simulated APIs (`evidence/browser-desktop-mobile.log`). This checks UI behavior, not real customer server integration.
- **Ruff**, frontend **TypeScript**, **ESLint**, and **git diff --check** passed.
- **10,000 synthetic document metadata rows** tested through the real Guard PolicyCache, including 10,000 individual policy verifications, **24,000 concurrent mixed decision checks in eight threads**, and 2,000 bulk offboarding-denial policy updates. These are correctness tests, **not** throughput/revocation SLAs.
- **80 alternating permission grant/revoke changes**, randomized between simulated Drive change-feed and authoritative reconciliation, all matched the synthetic oracle. Current ACL/directory/SDK unit and local HTTP lifecycle tests also passed.
- The fake customer environment includes synthetic Northstar and Blueharbor, distinct source IDs, deliberately colliding resource IDs, and Canary-marked documents. No real data touched.
- **Customer matrix:** 150 uniquely sampled scenario *descriptions*, NOT 150 independently executed end-to-end tests. It now reports NOT_TESTED until tests run and is backed separately by the suite above. Twenty-six scenarios expressly require an external sandbox.

## Defects reproduced and fixed

| ID | Priority | Evidence before fix | Actual fix | Regression test |
| --- | --- | --- | --- | --- |
| HEAVY-01 | Critical | When a new Drive document grant was discovered by periodic reconciliation, subsequent Drive revocation was rejected as stale because reconciliation stamped seconds-since-epoch while change-feed events used per-source increments. The fake employee retained an allow. | `reconcile_known_acls` now obtains the source ACL cursor, requires initial ACL bootstrap, advances the **same durable revision domain**, and persists the new revision transactionally. Subsequent deltas can revoke the reconciled grant. | `tests/security/test_twin_acl_revision_replay.py` (red→green; 80 randomized state flips) |
| HEAVY-02 | High | Malicious/compromised directory pagination could direct a token-bearing HTTP client to an attacker-selected domain, and a repeated page token could create an unbounded loop. | Enforce HTTPS official-domain pagination anchored to the same endpoint path; detect repeated URLs/tokens and cap page count. | `tests/security/test_twin_directory_provider_chaos.py` (red test showed outbound mock request; loop test intentionally terminated before fix; green after patch) |
| HEAVY-03 | High | A malformed HTTP 200 Directory page could be treated as an empty complete directory, losing trustworthy employee state. | Reject malformed/missing typed user/group collections; accept legitimate tagged empty lists. Reject invalid/missing stable IDs. | `tests/security/test_twin_directory_provider_chaos.py` |
| HEAVY-04 | High | A malformed HTTP 200 Google Drive changes response with no continuation/start token was accepted as a completed poll. | Validate change-list response and continuation or new start token. | `tests/security/test_twin_drive_provider_chaos.py` (red→green) |
| HEAVY-05 | High | A malformed HTTP 200 Google permissions response could be treated as an empty ACL and incorrectly revoke all tracked users. | Request/validate `kind`, require valid permission-list collection or properly typed empty-list response. | `tests/security/test_twin_drive_provider_chaos.py` (red→green) |
| HEAVY-06 | High | A malformed HTTP 200 Google Drive folder list could be treated as an empty, successful inventory. | Request/validate `kind`, require valid file list or appropriately typed empty response. | `tests/security/test_twin_drive_provider_chaos.py` (red→green) |
| HEAVY-07 | Evidence integrity | The fake-env generator repeated a narrow set of combinations and labeled 10 catalogue rows as end-to-end verified without executing them. | Deterministic seeded sampling from the full Cartesian space; 150 distinct combinations; generated cases explicitly NOT_TESTED until actually exercised. Corresponding test and output files updated. | `tests/unit/test_customer_simulation_harness.py` |

Files updated:
- `apps/api/accessproof_api/acl_sync.py`
- `connectors/directory.py`
- `connectors/google_drive/adapter.py`
- `customer_simulation/harness/digital_twin.py`
- `tests/unit/test_customer_simulation_harness.py`
- `customer_simulation/02_scenario_matrix.csv`, `customer_simulation/evidence/latest-summary.json`, `customer_simulation/README_RUN_FIRST.md`

New regression and load tests:
- `tests/security/test_twin_acl_revision_replay.py`
- `tests/security/test_twin_directory_provider_chaos.py`
- `tests/security/test_twin_drive_provider_chaos.py`
- `tests/load/test_twin_large_policy_cache.py`

All replaced files have previous versions at `docs/customer-simulation-heavy-20261021/premerge-backups/`. Unrelated local edits preserved.

## Tests performed versus catalogued
**Performed:** existing full Python suite (including local end-to-end control-plane/Guard/RAG HTTP), new three fake-provider chaos suites, 80 ACL transitions, 10k-document cache workload, 24k parallel cache lookups, 2k bulk-denial policy updates, 4 TS SDK tests, lint and typechecking.

**Not individually performed:** all 150 labelled scenario combinations. They are an unexecuted catalog and should not be promoted to pass status from the generator.

**Not performed:** full Docker/VM deployment rebuild/rollback, PostgreSQL+Redis under distributed failure, external Google Workspace/IdP/real customer RAG/OAuth, measured physical revocation latency, high-availability soak.

## Open gaps / release gates
1. **No completed administrator-approved Google OAuth consent flow:** onboarding still uses manual approved OAuth credentials. Google Workspace Admin SDK directory scopes require real consent and domain administrator approval.
2. **No push-based instant Google permission update guarantee:** Drive ACL polling default ~300s, employee/group directory poll default ~900s, reconciliation default ~3600s, plus event and Guard propagation. A customer revocation SLA must be measured with a real test Workspace.
3. **Real provider fidelity:** Shared Drive inherited permissions, permission expiration at the exact time boundary, nested/reassigned groups, partial accessibility of drives, change-token invalidation/410, Google rate limits, permission inheritance, and effective identities require actual authorized Google Workspace sandbox checks. Google responses may legitimately omit empty array fields; updated adapter accepts this when response has the expected `kind`, but real provider tests are essential.
4. **Real RAG instrumentation:** every cache/tool/retriever/streaming route requires a verifiable customer integration. A fully synthetic RAG cannot prove protection for arbitrary unwrapped pipelines.
5. **Distributed deployments:** test PostgreSQL and Redis in staging, rollback, migration, offboarding latency, API+worker concurrency, health alerts, installation upgrades, and backup restore.
6. **Operational and security review:** least-privilege access, independent review, observability, privacy, incident recovery, and documented customer-specific scope exclusions.

**Verdict:** Substantial real local hardening complete; **eligible for continued supervised sandbox/pilot preparation**, **not** verified as zero-error or ready for unrestricted customer production.

## Reproduction
```bash
cd /home/white-devil/Downloads/accessproof/f15
TMPDIR=/dev/shm env -u PYTHONPATH -u ACCESSPROOF_CURRENT_DATABASE_URL \
  PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest \
  -p pytest_asyncio.plugin -o addopts='' -q
.venv/bin/ruff check apps connectors packages tests customer_simulation
npm --prefix web-v2 run typecheck
npm --prefix web-v2 run lint
PATH="$PWD/web-v2/node_modules/.bin:$PATH" npm --prefix packages/rag-sdk-typescript test
```
