# AccessProof adversarial audit — ACTIVE CHECKOUT VERIFICATION (20 Oct 2026)

## Reconciled into the live working tree
The newly discovered **source-binding reuse** vulnerability was fixed in-place in:
- `apps/guard/accessproof_guard/app.py`
- `apps/guard/accessproof_guard/cache.py`
- `tests/security/test_cross_source_context_binding.py` (new red-to-green regression)

Pre-patch file backups are at `premerge-backups/` under this folder. The merge script used SHA-256 preflight and exact-match replacements to preserve other concurrent edits. The other two fixes (Protect/Shadow downgrade handling and safe 503 on Guard outage) were already independently fixed in the active checkout by the time we reconciled; focused live tests passed. The isolated snapshot's source files were **not** copied wholesale over them.

## Verified exact live commands and results

```
TMPDIR=/dev/shm env -u PYTHONPATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -p pytest_asyncio.plugin -q
# exit 0; 338 tests collected and passed
.venv/bin/ruff check apps connectors packages tests
# exit 0; All checks passed!
git diff --check
# exit 0
```

Targeted source-binding and revocation suite: 11 tests passed after the active-checkout merge.

## Other validations (isolated 305-test snapshot)
- 305/305 Python tests passed after fixes, Ruff passed.
- TS RAG SDK: 4 tests passed.
- UI: ESLint and TypeScript typecheck passed.
- Next.js `next build --webpack` passed, but symlinked dependencies generated standalone trace warnings; Turbopack default build failed on unsupported external node_modules symlink.
- Browser tests against isolated local Webpack development server on 127.0.0.1:3011: 21 passed, 1 skipped.
- Local synthetic PolicyCache: 2,000/2,000 allow/deny cases correct in 8-thread test (benchmark is NOT a Guard production SLA).

## Verdict
**NO-GO: unattended production Protect, 24/7 SLA or confidential enterprise documents.** Conditional next step: approved synthetic-data Google Workspace and independent RAG integration tests; verify real identities, full request-path instrumentation, revocation propagation, rollback/recovery and customer acceptance.

No deployment, production database migration or customer credential manipulation was performed.
