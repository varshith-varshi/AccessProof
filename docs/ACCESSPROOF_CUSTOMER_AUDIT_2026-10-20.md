# AccessProof customer-integration audit — 2026-10-20

## Scope and evidence
- Authorized machine: whitedevil-Acer-ALG-AL15G-53 (Desktop Commander).
- Repository: `/home/white-devil/Downloads/accessproof/f15`.
- Existing substantial uncommitted changes were preserved; no git reset, commit, production deploy, or credentials changes.
- This is an executable LOCAL audit against available tests and selected negative-path probes. The large Codex pack is a catalogue of hypotheses and parameterized scenarios, NOT 20,000 independently executed automated tests.
- STATUS: LOCAL CODE AUDIT = PASS with specific hardening changes and warnings; LIVE PROVIDER VALIDATION = BLOCKED; REAL CUSTOMER INTEGRATION ACCEPTANCE = BLOCKED; PRODUCTION CERTIFICATION = NO.

## Executed evidence
1. Backend: 273 collected Python test items, all passing after changes. Command:
   `env -u PYTHONPATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TMPDIR=/dev/shm .venv/bin/python -m pytest -p pytest_asyncio.plugin -q`.
2. Frontend: `npm run lint`, `npm run typecheck`, `npm run build` all passed under web-v2.
3. Playwright: `npm run test:e2e` = 21 passed, 1 skipped (desktop/mobile).
4. TypeScript customer RAG SDK: 4 tests passed using the installed web-v2 TypeScript binary (package-local node_modules was absent; plain npm test initially failed because tsc was not installed in that directory). SDK unit evidence is not a real framework compatibility certification.
5. Static: Ruff, Python compilation, selected strict mypy, and `git diff --check` passed.
6. `docker compose config --quiet` passed. `docker compose ps` showed local drive-rag/api/db/guard/redis/web-v2/worker running; container runtime status was not treated as security readiness.
7. Disposable migration: fresh SQLite database `/dev/shm/accessproof-audit-disposable-20261020.sqlite` migrated from base to Alembic head `c2d4e6f8a0b1`; verified `processing_started_at` exists.
8. Customer safety regression tests: protect-health missing field rejected; Unicode byte limit; invalid buffer chunks; large streaming response; legacy cache migration defaults unhealthy; restart invalidates source health; unsafe recovery script --help and default execution blocked.

## Reproduced issues and fixes
- SECURITY: Protect-mode sync previously accepted control-plane snapshots without `source_acl_healthy`, using a healthy default. Reproduced with failing regression test. Fixed `apps/guard/accessproof_guard/sync.py`: reject missing/non-boolean health on Protect bindings before any policy/binding state updates.
- SECURITY: A pre-health-field Guard SQLite cache gained implicit healthy status during schema migration. Reproduced with an old-schema fixture. Fixed `apps/guard/accessproof_guard/cache.py`: added source-health column defaults to 0, not 1.
- SECURITY/RESILIENCE: A restarted Guard previously reused persisted positive source-health status without revalidating the current source. Reproduced with restart fixture. Fixed Guard cache constructor: reset Protect binding health to unhealthy until fresh authenticated sync; expect brief fail-closed startup.
- PERFORMANCE/AVAILABILITY: Python RAG output buffering repeatedly re-encoded and concatenated all previous content, creating quadratic work on many streaming chunks. Fixed `packages/rag_sdk/protection.py` with per-chunk UTF-8 byte tracking and a single join. Added Unicode/boundary/large-chunk regressions.
- VALIDATOR SAFETY: `scripts/validate_redis_durable_recovery.py --help` unexpectedly executed a destructive validation because it ignored command-line arguments. Fixed it to display normal help and require both `--execute` and explicit `ACCESSPROOF_DISPOSABLE_VALIDATION=YES`; NEVER run it against customer data or the developer's active database.
- Updated one preexisting sync mock to include the required explicit source-health field; added `tests/security/test_customer_integration_hardening.py`.

## Critical caveat discovered
- The existing repository-root `accessproof.db` is a legacy SQLite file: its `alembic_version` is empty, and `guard_permission_events` lacks `processing_started_at`. The recovery validator attempted to use it before the CLI guard was added; an insert failed due to the schema mismatch. The script also performs a cleanup of specifically named test organizations before that insert, so its impact on any preexisting validation-only rows cannot be established from the available evidence. At the time of later read-only inspection there were no matching validation organizations. **Do not use or auto-migrate this database before reviewing its role, preserving a backup, inspecting data, and rehearsing migration.** The fresh disposable database migrated successfully. Docker's PostgreSQL database is separate and was not migrated here.

## Priority gates: NOT executed / NOT proven
- P0 LIVE GOOGLE WORKSPACE: approved Workspace organization, real Drive OAuth scopes, root boundary, users/groups/inherited/shared-drive permissions, folder moves, revocations, repeated page tokens, missing scope handling. Mock tests pass but these are NOT Google provider evidence.
- P0 LIVE VERIFIED IDENTITY: real issuer/JWKS and signed Alice/Bob tokens, stable subject mapping to the source permission principal, claim rotation and revocation, tenant boundaries.
- P0 CUSTOMER RAG: use an authorized external RAG with stable Drive file IDs, instrument all initial/cached/tool/rerank retrieval before model use, ensure no unverified bytes escape via SSE/WebSocket, citations, generation retries or cached answers. The SDK cannot automatically prove the customer's framework is correctly integrated.
- P0 REVOCATION WINDOW: measure from actual provider revoke through source/directory sync, installed Guard policy and prevented output. Defaults documented in release gate (300s Drive / 900s directory polling) mean instant or real-time revocation cannot presently be promised.
- P0 SAFE CUSTOMER CUTOVER: review existing policy/grant IDs, perform staging backup-and-restore and migration/rollback rehearsal, rotate machine credentials, verify API+worker+web compatibility, health alerts and outage fail-closed behavior. Do not deploy local edits as-is to production.
- P1 OTHER: installer/network/TLS/proxy compatibility on a clean customer machine, Google consent/verification, signed deliverables, observability, load/soak under realistic customer conditions, exact enterprise SDK version certification, third-party security assessment, customer contracts.
- LOCALHOST SETUP WARNING: Guard's setup endpoint currently relies on the Host header as an application-level localhost check. The shipped Compose host binding uses 127.0.0.1, which must be preserved; do NOT expose setup over a public listener or trust a Host header as authentication. A stronger topology-aware local setup trust model still needs review.

## Customer pilot Go/No-Go
- Synthetic unit/contract/in-process browser testing: GO for continuing LOCAL development; detailed results above.
- Dedicated, synthetic-data Google Workspace pilot: CONDITIONAL only with explicit provider owner authorization, least-privilege test credentials, genuine issuer, safe test environment, rollback and a defined success test matrix.
- Live customer Protect deployment on confidential data: NO-GO until the P0 provider/identity/RAG/cutover gates are evidenced.
- Seven-day pilot commercial timeline is a proposal, not a guarantee that complex integration or approvals can be completed in seven days.

## Reviewable changed files in this audit
- `apps/guard/accessproof_guard/sync.py`
- `apps/guard/accessproof_guard/cache.py`
- `packages/rag_sdk/protection.py`
- `scripts/validate_redis_durable_recovery.py`
- `tests/unit/test_guard_cache.py`
- `tests/security/test_customer_integration_hardening.py`
- This report.

No other pre-existing modified files were intentionally changed. Source edits are currently on the developer machine only, not deployed to the running Docker containers or production.
