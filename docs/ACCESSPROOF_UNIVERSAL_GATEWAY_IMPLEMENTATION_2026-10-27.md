# AccessProof — engineering delivery report, 27 October 2026

## A. Executive summary
Implemented a first controlled multi-source V2 Guard and Gateway reference path. Preserved dirty pre-existing workspace edits and the retired SDK deletion. Added explicit source bindings, migration/backfill, revision hashing across sources, independent source identity mapping, source/ID/chunk/content-version lineage and atomic one-time release checks. Production readiness **has not been achieved**.

## B. Files created or modified for this pass
Created `apps/guard/accessproof_guard/multisource.py`, `migrations/versions/n7a2b4c6d801_multisource_application_bindings.py`, `tests/security/test_multisource_guard_v2.py`, `tests/integration/test_gateway_multisource_real_guard.py`, and the eight 2026-10-27 architecture/integration/security documents. Modified `apps/guard/accessproof_guard/app.py`, `apps/guard/accessproof_guard/cache.py`, `apps/api/accessproof_api/app.py`, `apps/api/accessproof_api/db.py`, `apps/api/accessproof_api/schemas.py`, `apps/api/accessproof_api/authorization_revision.py`, `apps/gateway/accessproof_gateway/app.py`, `packages/rag_core/protection.py`, `web-v2/app/applications/page.tsx`, `web-v2/lib/api.ts`, and `tests/unit/test_gateway_multisource_snapshots.py`.

## C. Architecture
An application registers multiple tenant-validated source bindings. Authenticated Guard policy sync installs the approved list atomically, with health for each source and a single revision representing the complete application source/policy state. The Gateway verifies independently signed chunks, calls Guard V2 to resolve each employee's source identity and filter retrieved content, generates a buffered answer using only authorized context, then submits source-version-scoped dependency lineage to Guard V2 for a one-time atomic release check. V1 explicitly rejects multi-bound applications.

## D. Security changes
Cross-source document-ID collisions, wrong user/tenant, unapproved source, duplicate/replayed context, changed ACL, revision rollover, source outage, shifted mapped identities and tampered source attestation fail closed under the tested route. No source from another application is silently accepted, and the original Guard V1 context cannot authorize V2 lineage.

## E. Test evidence
Focused V2 and Gateway local tests: 14 passed after exact content-version binding, history blocking and tamper negatives.
Broader selected Gateway/security/integration subset: 84 passed and was included in final combined execution.
Core regression/migration and connector-contract tests were included in the final combined execution: **128 passed, 0 failed, 0 skipped**.
Ruff on modified Python files: passed. Web-v2 TypeScript check: passed. Playwright application-registration checks on desktop and mobile: 2 passed.
An attempted full pytest suite with *all* plugin auto-loading disabled encountered unrelated async-marked tests failing because pytest-asyncio was disabled; the full run was interrupted rather than represented as a pass. Local Graph/Drive/Entra provider E2E results: NOT_TESTED in this pass.

## F. Compatibility and G. Deployment
See `ENTERPRISE_RAG_COMPATIBILITY.md`, `CUSTOMER_GATEWAY_INTEGRATION.md` and `PRODUCTION_DEPLOYMENT.md`. Only documented source-attested, bounded, buffered text routes are reference-validated. Customer-side alternate egress/cache/tool routes require separate verification. No live production cutover was performed.

## H. Live validation and I. Remaining blockers
No genuine cross-provider enterprise trial validation or independent customer environment security certification has been completed for this V2 change. Runtime permission lag, connector token health, identity provider consent, RAG route interception, cache release, automated compatibility discovery, production stress/recovery tests and approved cutover all remain work items. Control-plane multi-source Protect activation deliberately blocks absent customer-route evidence.

## J. Readiness verdict
**LOCAL_REFERENCE_VALIDATED** — strictly the new V2 signed-snapshot reference configuration with synthetic sources and test identities. **NOT PRODUCTION READY.** Do not claim the product supports every enterprise pipeline or prevents every unauthorized LLM disclosure.
