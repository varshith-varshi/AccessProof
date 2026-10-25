# AccessProof adversarial audit — verified checkpoint (2026-10-20)

**Scope:** Local, synthetic-only repository test and fix loop, using an isolated copy of the current AccessProof checkout. Master prompt categories A–K were triaged; **not all 68 scenarios were executed individually.** No attacks against real services or customers.

## Outcome
- Snapshot before fixes: 305 backend test cases collected; **four distinct test failures** (two Protect/Shadow cross-layer checks, one outdated revocation-race test seam, one Guard outage response classification).
- New independent red case: **cross-source application rebinding with ID collision returned ALLOW** before fix.
- Snapshot after fixes: **305/305 backend tests passed**; Ruff passed; TypeScript SDK **4/4**; frontend lint and TypeScript type-check passed; Next.js Webpack build passed; Playwright **21 passed, 1 skipped**; synthetic local cache **2,000/2,000 decisions correct**.
- Default Turbopack build blocked by symlinked node_modules location in snapshot; Webpack alternative succeeded, but standalone trace warnings remain.
- Confirmed security findings fixed in snapshot: **2 P1** (mode downgrade, source-binding collision), **1 P2** (misleading outage HTTP status). Race test seam was corrected, not counted as a new vulnerability.
- Known unresolved security/integration gaps are detailed in `unresolved_risks.md`. No external target penetration test was performed.

## Evidence
Red failures: `/tmp/accessproof-redteam-20261020/snapshot-baseline.log`, `source-rebind-red.log`.
Green: `final-pytest.log`, `source-rebind-green.log`, `targeted-after-v2.log`, `ruff.log`, `frontend-lint.log`, `frontend-types.log`, `frontend-build-webpack.log`, `browser-e2e.log`, `ts-sdk.log`, `cache-benchmark.log`.

## Deliverables
Source fixes: `packages/rag_sdk/protection.py`, `apps/guard/accessproof_guard/app.py`, `apps/guard/accessproof_guard/cache.py`, `drive-rag-demo/app.py`; test correction: `tests/security/test_release_version_race.py`; new regression: `tests/security/test_cross_source_context_binding.py`.

## Verdict
**NOT READY for unattended production** or a 24/7 security guarantee. **Locally suitable to prepare an approved, synthetic-data controlled pilot after integrating the fixes with the active checkout**, then validating real Google Drive and independently built customer RAG under written authorization.

**Critical coordination note:** During this audit a separate process continued modifying `/home/white-devil/Downloads/accessproof/f15`. All edits above were made only to the isolated snapshot to prevent overwriting user work. Do not claim that the live/deployed app contains these fixes until safely reconciled and retested.
