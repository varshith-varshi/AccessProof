# AccessProof — Customer Integration Readiness Audit

**Date:** 2026-10-20
**Machine:** whitedevil-Acer-ALG-AL15G-53 (Ubuntu); Desktop Commander remote session
**Repo:** `/home/white-devil/Downloads/accessproof/f15`
**Scope:** Synthetic/local security tests, API and browser regression, Guard bundle and clean install, static checks, dependency checks, fresh DB migration, known customer integration blockers.
**IMPORTANT:** This document does **not** certify production readiness or a complete execution of the 20,000-line scenario matrix. No Google Workspace/customer system was accessed; no existing containers, data, or production deployments were changed.

## Verdict

**NO-GO for unattended customer production Protect enforcement.**
**GO for planning a controlled design-partner validation** subject to test-tenant credentials, scope, security approvals and a documented pilot contract. A production readiness claim remains blocked by real-provider evidence and operational rehearsals.

## Commands actually executed / local evidence

| Check | Evidence | Outcome |
|---|---|---|
| Python regression baseline | `TMPDIR=/dev/shm env -u PYTHONPATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -p pytest_asyncio.plugin -q` | PASS: 263 tests at initial baseline; 273 tests collected and passed on final rerun (other tests were also added to the working tree during the audit) |
| Python lint | `.venv/bin/ruff check apps connectors packages tests` | PASS |
| Python types | `.venv/bin/mypy packages/rag_sdk/protection.py apps/guard/accessproof_guard/identity.py connectors/google_drive/adapter.py` | PASS for these three source files only |
| Browser typecheck | `cd web-v2 && npm run typecheck` | PASS |
| Browser lint | `cd web-v2 && npm run lint` | PASS |
| Production frontend build | `cd web-v2 && npm run build` | PASS |
| Browser Playwright | `cd web-v2 && npm run test:e2e` | 21 PASS, 1 SKIP; isolated port 3011 |
| TypeScript RAG SDK | `PATH=./web-v2/node_modules/.bin:$PATH npm --prefix packages/rag-sdk-typescript test` | 4 PASS; SDK package lacks its own installed node_modules; compiler reused from frontend |
| Local Compose structure | `docker compose -f docker-compose.yml config --quiet` | PASS |
| Package Compose structure | Synthetic staged `.env`, `docker compose config --quiet` | PASS |
| Frontend production dependency audit | `cd web-v2 && npm audit --omit=dev --audit-level=high --json` | No vulnerabilities reported at query time |
| Shell parsing | `bash -n scripts/build-guard-package.sh scripts/build-runner-linux.sh packaging/guard/start.sh packaging/guard/start.command` | PASS |
| Clean SQLite migration | Temporary URL to `.venv/bin/alembic upgrade head` and `alembic current` | PASS; `c2d4e6f8a0b1 (head)` |
| Release packaging | `ACCESSPROOF_GUARD_VERSION=0.1.2 bash scripts/build-guard-package.sh` and `sha256sum -c` | PASS |
| Archive secret scan | `tar -tzf`, reject embedded `.env`, database, git files, `.pyc` | PASS for archive names |
| Clean customer-image build | Extract archive in `/tmp`, `docker build -f apps/guard/Dockerfile -t accessproof-guard:audit-0.1.2 .` | PASS |
| Isolated container runtime smoke | `docker run --rm --network none --read-only --tmpfs /tmp --tmpfs /var/lib/accessproof-guard ...` | PASS: reports runtime version 0.1.2; fails readiness safely with no policy |
| Existing local stack status | `docker compose ps`; local `/health/live`, `/health/ready`, Guard `/health` | API live/ready 200; running Guard policy version=0 and ready=false (NOT customer-ready) |

**Relevant logs:** `/tmp/accessproof-audit-273-pytest.log`, `/tmp/accessproof-audit-final-pytest.log`, `/tmp/accessproof-audit-e2e.log`, `/tmp/accessproof-audit-nextbuild.log`, `/tmp/accessproof-audit-clean-build.log`, `/tmp/accessproof-audit-clean-smoke.log`, `/tmp/accessproof-audit-alembic.log`. They are local and may be temporary; sensitive payloads were not intentionally logged.

## Confirmed issues fixed in this audit

### FIX-001 — Guard advertised healthy without any policy

- **Reproduction:** A Guard with `sync_age_seconds=0`, all sources healthy, and `policy_version=0` returned `status=ok`, `ready=false`.
- **Red evidence:** Newly written `tests/unit/test_guard_health_readiness.py` failed because `ok != degraded`.
- **Fix:** `apps/guard/accessproof_guard/app.py` computes `ready` once and reports `status=degraded` unless ready and sync-error-free.
- **Green evidence:** Focused test passed; additional success/degraded cases added; full suite rerun.
- **Customer impact:** Avoids a misleading green status before a policy has been installed.

### FIX-002 — Customer Docker healthcheck accepted HTTP 200 even when unready

- **Reproduction:** Existing `packaging/guard/compose.yml` healthcheck only opened `/health`; the API returned HTTP 200 even while `ready=false`.
- **Fix:** Docker healthcheck now parses JSON and requires both `ready=true` and `status=ok`.
- **Evidence:** Synthetic extracted release `docker compose config --quiet` PASS; clean image builds and smoke response `ready=false` / `degraded`.
- **Customer impact:** Docker marks unconfigured, unenrolled Guard as unready rather than falsely healthy.

### FIX-003 — Packaged release misidentified its Guard runtime version

- **Reproduction:** Guard 0.1.1 bundle had no explicit `ACCESSPROOF_GUARD_VERSION` despite app defaulting to 0.1.0.
- **Fix:** `scripts/build-guard-package.sh` validates release version and stamps the exact release version into the packaged Compose runtime environment, avoiding stale values from an existing customer `.env`.
- **Evidence:** Version 0.1.2 bundle built; checksum valid; packaged Compose declares `ACCESSPROOF_GUARD_VERSION: 0.1.2`; isolated container smoke printed `runtime_version: 0.1.2`.
- **Customer impact:** Accurate diagnostics, version negotiation, and future upgrade handling.

## Changed files (this audit)

- `apps/guard/accessproof_guard/app.py`
- `packaging/guard/compose.yml`
- `scripts/build-guard-package.sh`
- **New:** `tests/unit/test_guard_health_readiness.py`
- **New, NOT DEPLOYED:** `dist/accessproof-guard-0.1.2.tar.gz`, its checksum, and matching `packaging/guard/releases/` archive and checksum.

**Working tree warning:** More than 70 files were already modified/untracked prior to audit. Those changes were preserved. Do not `git reset --hard`, clean, or overwrite without reconciling concurrent work. No commit or production deployment was done.

## 21-phase coverage overview

| Phase | Evidence | Status |
|---|---|---|
| 01 Safety and architecture | Existing docs/config/test inventory | PARTIAL, local review |
| 02 Execution workflow | Baseline, logs, red/green and report | PASS local |
| 03 Identity and tenant | Python mock/contract/integration tests | PARTIAL; real signed IdP tokens BLOCKED |
| 04 Google Drive authorization | Mock ACL, pagination, group and change-feed tests | PARTIAL; real provider BLOCKED |
| 05 Layer 1 pre-generation | SDK, Guard and synthetic RAG tests | PARTIAL, local |
| 06 Layer 2 provenance/streaming | Buffer, deny, late source and proof context tests | PARTIAL, local |
| 07 Revocation/cache/races | Local simulation and regression | PARTIAL; live timing BLOCKED |
| 08 Guard enrollment/policies | Local contract tests + isolated runtime smoke | PARTIAL; real enrollment BLOCKED |
| 09 RAG adapters | Python SDK, 4 TypeScript SDK tests | PARTIAL; customer RAG BLOCKED |
| 10 API/UI | Backend suite, Next build, Playwright | PASS tested local flows only |
| 11 Workers/DB/Redis | Suite, local healthy DB/Redis, SQLite migrations | PARTIAL; distributed failure testing not run |
| 12 Supply chain/deployment | Compose, package hash, image build, npm audit | PARTIAL; production rollback BLOCKED |
| 13 Pilot/performance | Pilot criteria planned | BLOCKED on real pilot |
| 14 Final report | This report | PASS |
| 15 Clean install | Fresh extract, Compose config, Docker build and smoke | PASS for controlled clean-bundle path |
| 16 Live Workspace OIDC/revoke | No external test tenant | BLOCKED |
| 17 Customer RAG compatibility | Supported adapter contracts/synthetic tests | BLOCKED for real customer |
| 18 Adversarial tests | Existing local security tests | PARTIAL; no external pentest |
| 19 Recovery/incident/rollback | Documentation review only | BLOCKED for deployed staging rehearsal |
| 20 Seven-day partner pilot | Not yet agreed with a customer | BLOCKED |
| 21 Customer diagnosis | Three confirmed installation/health issues fixed | PARTIAL |

The master prompt's roughly **19,696 parameterized combinations** are test *hypotheses*, not executed tests. The project has broad but finite automated coverage. Neither 21/21 fully tested nor zero customer bugs is a defensible claim.

## P0 prerequisites before customer Protect deployment

1. Obtain explicit authorization for a dedicated Google Workspace test tenant, test folder, and dedicated Alice/Bob employee identities. Do not use production employees' documents, credentials or secrets.
2. Verify actual OIDC signed tokens: issuer, audience, signature/JWKS rotation, tenant, stable ID, expiry and inaccessible identity/provider failures.
3. Verify live Drive direct grant/revoke, inherited folder permission, nested group removal, multiple independent grants, Shared Drive behavior when supported, move, delete, copy and paging. Current V1 deliberately denies `anyone` / domain-shared permissions; disclose this unsupported case.
4. Integrate at least one *actual* customer-style RAG with trusted document metadata and verified identity. Test retrieval, rerank, tools, cache, conversation history, streaming, non-streaming, and Layer 2 lineage. Missing or spoofed lineage must not authorize data.
5. Record observed detection, directory sync, policy installation and Guard-denial timestamps under provider changes. Existing defaults (Google Drive 300s, directory 900s) are NOT instantaneous enforcement SLAs.
6. Verify Guard enrollment, complete installed policy, and Protect mode. The existing local Guard currently shows `policy_version=0` and `ready=false`; it must not be presented as protecting any app.
7. Rehearse staging database backup/restore, upgrade from old grant formats, rollback, Guard credential rotation, outage monitoring, audit logs and alerting; verify real deployment configuration before production.
8. Obtain acceptance from customer technical/security owner and document scope, price, data handling, schedule, escalation contacts and responsibility for each integration component.

## Next permitted actions

- Meet the validation partner and agree on a test environment with written permission; use synthetic files and test identities first.
- Configure live provider/identity integration and execute the P0 matrix with independently observable evidence.
- Run a limited Shadow pilot, fix reproducible defects, then a controlled Protect pilot after passing all agreed negative and revocation tests.
- Route a customer to production only after operational backup/rollback, support, data handling, and purchase agreements have been reviewed.
- For deployment of the *new source/release*, explicitly select/publish bundle version 0.1.2 and rebuild/deploy the reviewed app image; the currently running containers were NOT updated.

## Continuation — customer launcher hardening and Guard 0.1.3

**Scope:** Additional local audit through Desktop Commander after the initial 0.1.2 checks. Existing deployments, credentials, external providers, and customer systems were not modified.

### FIX-004 — Linux startup launcher selected the wrong port

- **Reproduced with a failing regression test:** A customer .env containing GUARD_PORT=18081 configured Docker on that port, but packaging/guard/start.sh still opened http://127.0.0.1:8080/setup. This could make a working customer Guard look broken.
- **Fix:** The Linux launcher reads only the numeric GUARD_PORT value from .env when no explicit process environment override exists; it supports quoted values and rejects invalid values before Docker startup. It checks for curl instead of silently failing. The .env file is not sourced/executed.
- **Evidence:** Four new tests in tests/unit/test_guard_customer_launcher.py cover file-configured port, explicit override, quoted port, and invalid port. First test failed before the fix; all four passed afterward.
- **Windows:** packaging/guard/start.ps1 now reads and validates the .env port consistently. PowerShell and Windows Docker Desktop were unavailable, so this fix has not been proven end-to-end on Windows.

### New customer release artifact and verification

- Built Guard 0.1.3 without overwriting the previously prepared 0.1.2 release: packaging/guard/releases/accessproof-guard-0.1.3.tar.gz.
- Release checksum, extracted Compose syntax and archive hygiene checks passed (no .env files, DBs, pyc or .git internals in bundle).
- A clean Docker customer image built successfully from the extracted 0.1.3 bundle.
- A short-lived read-only container with --network none was launched for smoke testing and subsequently stopped. It reported status=degraded, policy_version=0 and ready=false without any enrollment, and reported runtime version 0.1.3 as expected.
- Latest full backend regression: **277 passed, 3 warnings**, using a fresh isolated pytest temporary directory.
- Ruff, shell parsing, Compose parsing, and git diff --check passed. Earlier Next.js build/lint/typecheck, Playwright 21 passed / 1 skipped, and TypeScript SDK 4 passed remain the available frontend evidence.

### Files changed in this continuation

- packaging/guard/start.sh
- packaging/guard/start.ps1
- New tests/unit/test_guard_customer_launcher.py
- New (NOT DEPLOYED) dist/accessproof-guard-0.1.3.tar.gz plus checksum and corresponding packaging/guard/releases assets.

### Customer pilot readiness remains conditional

The 20,000-line master pack describes possible scenarios; it does NOT mean 20,000 unique tests were executed or that every possible error was fixed.

P0 external validation still needed: real Google Workspace permission state (including inherited/group grants and revocation), genuine signed OIDC identities, a real customer RAG architecture and provenance instrumented through every input/output path, live revocation timing measurements, and staging upgrade/rollback with monitoring. Windows installation was not exercised on Windows. Running local Guard still lacks an installed policy (ready=false). Production deployment was not performed.

**Next safe step:** With written owner approval, use a dedicated test Google Workspace tenant, Alice/Bob test identities and synthetic documents; run the agreed provider/RAG/identity tests in Shadow mode, fix any reproduced failures, and only enable controlled Protect evaluation after negative tests and rollback criteria pass.
