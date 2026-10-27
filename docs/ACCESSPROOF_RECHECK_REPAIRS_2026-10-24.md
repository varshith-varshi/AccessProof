# AccessProof local regression repairs — 2026-10-24 (Asia/Kolkata)

## Scope

Repaired the three reproducible failures from the previous repository recheck
and a misleading server-signed validation flag. All changes remain local to
the existing `f15` worktree; other user changes were preserved. No production
environment or customer credentials were accessed.

## Confirmed issues and corrections

| Issue | Root cause | Correction |
|---|---|---|
| SQLite upgrade to latest revision fails | `e6f8a2c4d9b0` used PostgreSQL-style `ALTER COLUMN ... SET NOT NULL`, which SQLite does not implement | Use an Alembic batch alter for SQLite and preserve native ALTER for PostgreSQL; keep the backfill and NOT NULL invariant. |
| Cleanup janitor test receives HTTP 422 | Synthetic cleanup-only test claimed `PASS` without any provider-confirmed source denial/stable probe evidence, violating the new security evidence contract | The fixture now returns `INCONCLUSIVE` rather than falsely asserting a security PASS. The janitor's durable cleanup task and eventual reconciliation remain asserted. |
| Guard activation test receives HTTP 409 | Fixture claimed Guard policy version 2 was installed without a policy distribution record | Test now checks the forged heartbeat returns 409, registers an actual installed policy distribution, verifies degraded Guard cannot activate Protect, then tests healthy Guard acknowledgment. No security gate removed. |
| Signed report validation flag incorrectly always true | `outcome != "PASS" or True` is tautologically true | `server_validation.passed` now equals `outcome == "PASS"`; strict PASS evidence validator continues running before a PASS can be stored. |

## Regression evidence

- The three originally failing integration files: **13 passed**, 1 warning.
- Added assertions: upgraded SQLite `test_runs.oracle_canary` remains NOT NULL; the signed result of an inconclusive cleanup run has `server_validation.passed == false`; failing end-to-end runner results also have `server_validation.passed == false`.
- **Complete Python suite: 670 passed, 1 expected failure, 9 warnings; exit code 0; 373.32 seconds.**
- TypeScript SDK: **34 passed, exit code 0**; TypeScript compile: exit code 0.
- Ruff and `git diff --check` on changed files: passed.
- Expected failure is the documented **legacy metadata-only SDK source-provenance integrity gap**. It is not hidden, reclassified, or resolved by these repairs.

## Release decision

The local regressions are repaired. This evidence does **not** establish
production readiness for arbitrary customer RAGs, live Google Workspace
permissions, SSO, revocation, or full model/tool/cache bypass resistance.
Customer-side Protect certification and controlled staging validation still
apply. Do not weaken Guard policy distribution, signed-source provenance,
tenant isolation, or strict PASS evidence requirements for test convenience.
