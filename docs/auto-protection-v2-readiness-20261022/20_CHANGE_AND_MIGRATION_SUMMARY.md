# Local change and migration summary

**Preserved:** all pre-existing modified and untracked files, backup directories and private environment secrets. Baseline repo commit `ab59ffd`, first git status 139 changed/untracked entries. No `git reset`, `git clean`, checkout, commit or production deployment.

**New core files:** `apps/api/accessproof_api/source_certification.py`, `tests/security/test_source_effective_certification.py`, `tests/security/test_unified_v2_four_regressions.py`, `tests/integration/test_automatic_protection_preflight.py`, `packages/rag-sdk-typescript/test/protect-mode-boundary.test.mjs`; 3 new Alembic revisions `a2b4c6d8e0f2`, `b3c5d7e9f103`, `c4d6e8f0a215`.

**Surgical edits:** `apps/api/accessproof_api/acl_sync.py`, `app.py`, `db.py`, `packages/auth/microsoft_consent.py`, `packages/rag_sdk/protection.py`, `packages/rag-sdk-typescript/src/index.ts`, Python integration/example and regression tests, `web-v2/app/applications/page.tsx`, `web-v2/lib/api.ts`, `web-v2/e2e/web-v2.spec.ts`, sample Drive RAG route. Existing broader user edits were not rolled back.

**Rollback:** Only test database upgrade/downgrade performed, never user/production database. For real deployment, take encrypted backup, rehearse populated PostgreSQL migration, check legacy grant-key translation and old-Guard compatibility, confirm no legacy cert/click can set Protect, deploy via authorized staging then roll forward/rollback with audit review. No migration or release has run on production.

**Security debt:** must implement reliable native SharePoint/OneDrive ACL oracle and issuance, real route challenge and release observer, software compatibility manifest, load/concurrent worker behavior, a protected release package and real provider validation before customer Protect.
