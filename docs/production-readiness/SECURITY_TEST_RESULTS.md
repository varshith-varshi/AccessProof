# Security test results

Last updated 2026-11-08T09:15Z.

## Automated suites (this session)

| Suite | Command | Result |
|---|---|---|
| Unit + security (baseline, before changes) | `env -u PYTHONPATH -u AMENT_PREFIX_PATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TMPDIR=/dev/shm .venv/bin/python -m pytest -p pytest_asyncio.plugin tests/unit tests/security -q` | exit 0 |
| Unit + security (after F-001 changes) | same | **1630 passed, 9 skipped, 0 failed**, exit 0 |
| Focused F-001 regressions | `tests/unit/test_certifier_renewal_watchdog.py`, `test_route_attestation_observation_retry.py`, `test_live_employee_identity_tool.py` | 31 passed (9 new) |
| Ruff on changed files | `.venv/bin/ruff check …` | clean |
| **Second session:** early recertification, sign-in trigger, gates document, drill guard | `test_route_attestation_observation_retry.py`, `test_recertify_after_signin.py`, `test_deployer_gates_document.py`, `test_postgres_isolation_drill_guard.py`, `test_deployer_document_url_limit.py` | all pass (14 new tests) |
| **Second session:** full unit + security | `env -u PYTHONPATH -u AMENT_PREFIX_PATH .venv/bin/python -m pytest -q tests/unit tests/security` | **1644 passed, 9 skipped, 0 failed**, exit 0 |
| **Real PostgreSQL 17 tenant isolation + restore drill** | `scripts/drills/postgres_isolation_restore_drill.py` (disposable loopback DB) | PASS: 50 tenant tables, 0 violations before and after restore; cross-tenant INSERT rejected; GUC bypass inert. Negative control (superuser) correctly flagged 4 violation classes |

## Threat-area coverage map

TESTED_LOCAL means automated tests in `tests/security` and `tests/unit` cover the area. VERIFIED_LIVE means it was observed on the live route as part of route certification. The latest such evidence comes from the certification runs on 2026-11-04 and 2026-11-05 and the daily attestations since then; this session re-ran neither.

| Area | Status | Live evidence source |
|---|---|---|
| Unauthorized retrieval / cross-user (Alice vs Bob) | TESTED_LOCAL + VERIFIED_LIVE (route cert checks 1–3) | route certificate runs, `~/.ap-id/route-certs/` |
| Mixed authorized/denied chunks (partial answer, not whole denial) | TESTED_LOCAL; Gateway code DEPLOYED (unchanged since `501a74c`/R54). `15b870a` touched only the demo RAG | **NOT_VERIFIED live** |
| Cached chunks reauthorized per employee; no cross-employee reuse | TESTED_LOCAL | route cert cache check (repeat question) |
| Revocation and restoration, in-flight | VERIFIED_LIVE (route cert includes one live SharePoint revocation, restored in `finally`) | 2026-11-05 certs |
| Forged attestations, tampered/replayed requests, token swap, cross-app, cross-source | VERIFIED_LIVE (route cert gateway attack checks) | same |
| Gateway bypass / unsigned route probes | VERIFIED_LIVE (route probe checks) | same |
| Guard / Gateway outage fail-closed | VERIFIED_LIVE (route cert outage checks) | same |
| Database RLS bypass | TESTED_LOCAL on real PG 17 (drill, F-009) + authorization matrix; live gate I NOT_VERIFIED today (F-003) | — |
| Prompt injection / response exfiltration / streaming buffering | TESTED_LOCAL | — |
| Cross-tenant leakage (live, two real tenants) | DB layer TESTED_LOCAL (drill); live NOT_VERIFIED: only one real Microsoft tenant exists | — |
| Auth/session (account attack matrix, Owner-only approve) | TESTED_LOCAL | — |
| Control-plane outage | TESTED_LOCAL | — |

## This session's security-relevant change
F-001 changes add no allow path. The watchdog sends only the non-secret `claims` and `session` queries, and refuses token queries (tested). The attestation preflight refuses a recertification without live sessions. The session lifetime is now enforced on the wall clock, which is stricter: it can no longer outlive its stated hours across a suspend.

## Second-session security review of changes
- **Early recertification** adds no allow path. It runs the identical full 14-check certification and import; it only runs it earlier. It never extends a certificate. It requires both sessions with a known lifetime ≥3 h. A failed early attempt does not suppress the live attestation, so it cannot fail closed by starvation.
- **Gates document:** read-only, pinned to the instance, two regex-validated ENV_VAR inputs, never spliced into shell text. The deployer's deny on document and IAM changes is unchanged.
- **Drill:** refuses non-loopback hosts and non-"drill" databases. Its evidence contains no passwords.
