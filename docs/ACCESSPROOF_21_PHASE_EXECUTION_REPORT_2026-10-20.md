# AccessProof — 21-phase enterprise-readiness execution report
**Date:** 2026-10-20 (Asia/Kolkata)
**Scope:** Local authorized Ubuntu development machine, synthetic fixtures, local builds and disposable migration only.
**Repository:** /home/white-devil/Downloads/accessproof/f15
**Branch / starting commit:** master / ab59ffd
**Device:** whitedevil-Acer-ALG-AL15G-53
**Production/customer access:** NONE; no credentials used, deployments changed, existing DB migrated, or Git state reset.

## Executive result
- LOCAL CODE AUDIT: PASS for the supported tests actually run, with three reproduced failure conditions fixed.
- REAL GOOGLE / OIDC VALIDATION: BLOCKED; no approved test Workspace, live signed employee identities, or authorized source fixtures.
- CUSTOMER RAG ACCEPTANCE: BLOCKED; customer integration and real model transport have not been tested.
- CUSTOMER PRODUCTION PROTECT: NO-GO.
- CONTROLLED SYNTHETIC-DATA DESIGN-PARTNER PILOT: CONDITIONAL GO for explicitly authorized nonproduction validation only, not a production-security sign-off.

The supplied pack has 21 phases, 121 priority cases (80 P0 / 41 P1), and 19,696 parameterized risk hypotheses in a 20,000-line master. These are not 19,696 completed tests, and this audit does not claim that every priority case is separately executed.

## Existing implementation inspected
FastAPI control plane, worker, Google Drive source adapter, directory/ACL synchronization, customer-side Python Guard with durable SQLite policy cache and source freshness, Python/TypeScript RAG SDKs, Docker Compose/installer packaging, Next.js web-v2 console, Alembic schema, security/integration/unit/browser test suites. Production is not assumed to match the local source.

## Confirmed reproduced defects and fixes (new work)
**AP-001 [P1] False Guard readiness with no assigned applications.**
- Reproduction: synthetic enrolled Guard, policy version 5, fresh policy sync, explicitly synchronized empty application list; /health incorrectly returned ready=true and status=ok.
- Regression: test_enrolled_guard_with_zero_application_bindings_is_not_ready failed (expected False, observed True).
- Root fix: enrolled Guard readiness requires an authenticated application-binding sync and at least one installed application binding in addition to policy version/freshness/source health. No authorization semantics were relaxed.
- File: apps/guard/accessproof_guard/app.py; test: tests/unit/test_guard_health_readiness.py.

**AP-002 [P1 security] Insecure machine-credential file permissions accepted.**
- Reproduction: synthetic credentials.json mode 0644 was loaded without complaint.
- Regression: test_guard_refuses_world_readable_machine_credentials failed before fix.
- Root fix: open credential file first and check opened file is a regular file and owner-only on POSIX. Unsafe permissions now cause an explicit safe startup error (operator action: chmod 600).
- File: apps/guard/accessproof_guard/app.py; test: tests/unit/test_guard_machine_credential_permissions.py.

**AP-003 [P1 security] Symlinked machine-credential file accepted.**
- Reproduction: synthetic credentials.json symlink to another file was followed and consumed.
- Regression: test_guard_refuses_symlinked_machine_credentials failed before fix.
- Root fix: O_NOFOLLOW on POSIX, fstat regular-file validation and no separate pre-open path check. Valid owner-only file still loads correctly.
- File: apps/guard/accessproof_guard/app.py; test: tests/unit/test_guard_machine_credential_permissions.py.
- Platform limit: symlink prevention is proven in the tested Linux environment; Windows native-file ACL equivalence was not certified. Current customer Guard packaging uses a Linux container.

No other source files were intentionally changed by this audit. Many earlier uncommitted files already existed and were preserved. No new production release was activated.

## Exact tests and evidence
- Baseline: TMPDIR=/dev/shm env -u PYTHONPATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -p pytest_asyncio.plugin -q — exit 0, before these four added test cases.
- Focused red regressions: Guard readiness test FAILED before patch; 0644 credential and symlink tests FAILED before patch.
- Focused green: Guard readiness/cache/service and credential/onboarding/service tests PASS after fixes.
- Final: TMPDIR=/dev/shm env -u PYTHONPATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -p pytest_asyncio.plugin -q — exit 0; 281 items collected and passed. Logs: /tmp/accessproof-21phase-pytest-final.log, /tmp/accessproof-21phase-collected.log.
- Python lint: .venv/bin/ruff check apps connectors packages tests — PASS; /tmp/accessproof-21phase-ruff-final.log.
- Selected Python strict types: .venv/bin/mypy packages/rag_sdk/protection.py apps/guard/accessproof_guard/identity.py apps/guard/accessproof_guard/app.py connectors/google_drive/adapter.py — PASS for these four files, not the entire codebase.
- Diff check: git diff --check — PASS.
- UI (web-v2): npm run lint; npm run typecheck; npm run build — all PASS.
- Browser (web-v2): npm run test:e2e — 21 PASS, 1 SKIP; no claim that skipped path passed.
- TypeScript SDK: PATH="$PWD/web-v2/node_modules/.bin:$PATH" npm --prefix packages/rag-sdk-typescript test — 4 PASS. Package-local compiler not installed; an initial relative-PATH invocation failed until corrected; not a product test failure.
- Docker Compose structure: docker compose -f docker-compose.yml config --quiet — PASS.
- Fresh disposable SQLite: unique /dev/shm path, both DATABASE_URL and ACCESSPROOF_CURRENT_DATABASE_URL explicitly pointed to it; .venv/bin/alembic upgrade head / current — PASS at c2d4e6f8a0b1; 58 tables. No existing database was touched.
- Clean-room Guard package: copied only necessary source/config into /tmp, ran build-guard-package.sh with audit-only version 0.1.4-audit, validated SHA-256, extracted, checked shipped filenames for .env/credentials/databases/git files, parsed Compose, shell syntax — PASS. Production release assets were not modified.
- Clean isolated Docker image: docker build -f apps/guard/Dockerfile from extracted package — PASS; docker run --rm --network none --read-only --tmpfs /tmp --tmpfs /var/lib/accessproof-guard with health import — PASS, expected degraded/ready=false. Initial Docker invocation omitted -f, produced a harness error, was corrected; not an application defect.
- Logs: /tmp/accessproof-new-audit-*, /tmp/accessproof-21phase-*; temporary logs may not persist and are not an immutable audit trail.

## 21 phase coverage matrix
| Phase | Outcome in this run | Evidence and limits |
|---|---|---|
| 01 Safety/architecture | PARTIAL | Repository and trust boundaries inspected; no formal external threat-model signoff |
| 02 Workflow/quality gates | PASS LOCAL | Baseline/red-green/final suites and reproducible logs |
| 03 Identity/tenant | PARTIAL | Existing synthetic auth/RBAC/tenant suite passed; real signed IdP/JWKS blocked |
| 04 Google Drive ACL | PARTIAL | Simulated Drive/ACL/directory suites passed; real Drive blocked |
| 05 Layer 1 trust | PARTIAL | Synthetic Guard/RAG payload and denial tests; actual customer model input unobserved |
| 06 Layer 2/streaming | PARTIAL | Buffer/provenance/late-source tests; real customer SSE/WebSocket untested |
| 07 Revocation/concurrency | PARTIAL | Local cache/revoke regressions; provider end-to-end timing and load untested |
| 08 Guard enrollment/policy | PARTIAL | New readiness/credential fixes, existing enrollment tests, isolated Docker smoke |
| 09 RAG adapters | PARTIAL | Python/TS SDK and local adapter contracts; real adapter version certification blocked |
| 10 API/web UX | PARTIAL | Python integration + UI build + 21 Playwright passes, 1 skip; no production acceptance |
| 11 Workers/DB/Redis | PARTIAL | Integration tests, disposable SQLite migrations; crash/HA/backup drills not completed |
| 12 Deployment/supply chain | PARTIAL | Compose, checksum, isolated package/image build; no registry/signature/SBOM attestation |
| 13 Pilot/performance | BLOCKED | No approved customer pilot, full load or real network latency benchmark |
| 14 Final reporting | PASS | This report and Go/No-Go below |
| 15 Clean-room install | PARTIAL | Isolated archive/build/container smoke; not a new physical customer workstation |
| 16 Real Workspace OIDC/revocation | BLOCKED | Requires separate explicit approved tenant, users, consent and test changes |
| 17 RAG identity adapter compatibility | PARTIAL/BLOCKED | Local SDK contracts pass; actual customer RAG and principal mapping blocked |
| 18 Adversarial negative paths | PARTIAL | Existing security suite and 0644/symlink negative tests; no third-party pentest |
| 19 Recovery/upgrades | PARTIAL | Fresh migration and unhealthy startup; restore/rolling upgrade/prod rollback blocked |
| 20 Seven-day design-partner gates | BLOCKED | No signed scope, source fixtures, validated customer RAG or acceptance |
| 21 Customer error catalog | PARTIAL | Credential permission and misleading readiness errors reproduced/fixed; full catalog not individually forced |

## Open risks / test prerequisites
**P0 external/customer blockers (not reproduced local bugs):**
1. Real Google Workspace: approved root folder; Alice/Bob/group test principals; OAuth/Directory scopes; inherited/shared-drive/shortcut/move/delete/grant/revoke; actual propagation and repeat paging.
2. Real trusted identity: customer OIDC issuer, signed Alice/Bob tokens, JWKS rollover, audience/tenant mapping, guest/group principal identity.
3. Real RAG: one customer-approved RAG with trustworthy Drive file IDs on ALL retrieval, cache, tool, reranker and conversation paths; inspect actual model request BEFORE generation and response byte release AFTER Layer 2.
4. Revocation SLA: Drive change polling, directory membership refresh, Guard sync and in-flight response must be measured from real provider revoke to denial; do not advertise instantaneous revoke.
5. Cutover: existing DB/grant-key reconciliation, staged backup/restore and rollback, policy rollback protection, machine credential rotation, verified worker/API/web image consistency.

**P1/P2 follow-up:** customer TLS/proxy/browser setup, OAuth consent/self-service limitations, supported OS/architecture and clean end-user installation, recovery under DB/Redis/provider outages, fault/load/soak testing, signed distribution/SBOM, safe support telemetry. Keep setup endpoint loopback-only; Host header is not independent authentication and a publicly exposed listener remains unsafe. Domain/anyone Drive sharing deliberately fail-closed and are unsupported in V1. Layer 2 verifies structured source lineage, not arbitrary semantic leakage or model hallucinations.

## Go/No-Go customer pilot sheet (synthetic-only)
| Gate | Result | Owner/action |
|---|---|---|
| G0 Approved nonproduction scope and rollback | BLOCKED | Founder and customer security owner |
| G1 Real IdP, tenant isolation and Guard install | PARTIAL LOCAL / REAL BLOCKED | Founder + customer IdP admin |
| G2 Actual allowed source in customer RAG | BLOCKED | Customer RAG engineer |
| G3 Denied source absent from actual model payload | BLOCKED | Customer RAG engineer + founder |
| G4 Actual output buffering and streaming safety | BLOCKED | Customer RAG engineer |
| G5 Source-to-Guard revocation timeline | BLOCKED | Workspace admin + founder |
| G6 Provider/Guard outage fail-closed recovery | PARTIAL LOCAL / REAL BLOCKED | Founder + operator |
| G7 Authorized answers, overhead and load | PARTIAL LOCAL / REAL BLOCKED | Customer + founder |
| G8 Support errors and safe logs | PARTIAL LOCAL | Founder |
| G9 Signed customer acceptance | BLOCKED | Customer approver |

**Disposition:** Conditional GO for a narrowly scoped, nonproduction, synthetic-data validation engagement AFTER written authorization; default Shadow/observation initially, Protect only after real P0 gates demonstrate safe enforcement. NO-GO for unattended production Protect with confidential customer documents. Do not represent local mocks as real source/IdP validation; do not guarantee zero customer integration errors.

**Known operational caveat:** Preexisting repository-root accessproof.db was identified in earlier local audits as a legacy SQLite schema and must not be auto-migrated. This run used only a fresh disposable database.
