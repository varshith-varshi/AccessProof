# Security test results

Last updated 2026-11-08T08:35Z.

## Automated suites (this session)

| Suite | Command | Result |
|---|---|---|
| Unit + security (baseline, before changes) | `env -u PYTHONPATH -u AMENT_PREFIX_PATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TMPDIR=/dev/shm .venv/bin/python -m pytest -p pytest_asyncio.plugin tests/unit tests/security -q` | exit 0 |
| Unit + security (after F-001 changes) | same | **1630 passed, 9 skipped, 0 failed**, exit 0 |
| Focused F-001 regressions | `tests/unit/test_certifier_renewal_watchdog.py`, `test_route_attestation_observation_retry.py`, `test_live_employee_identity_tool.py` | 31 passed (9 new) |
| Ruff on changed files | `.venv/bin/ruff check …` | clean |

## Threat-area coverage map

TESTED_LOCAL means automated tests in `tests/security` and `tests/unit` cover the area. VERIFIED_LIVE means it was observed on the live route as part of route certification. The latest such evidence comes from the certification runs on 2026-11-04 and 2026-11-05 and the daily attestations since then; this session re-ran neither.

| Area | Status | Live evidence source |
|---|---|---|
| Unauthorized retrieval / cross-user (Alice vs Bob) | TESTED_LOCAL + VERIFIED_LIVE (route cert checks 1–3) | route certificate runs, `~/.ap-id/route-certs/` |
| Mixed authorized/denied chunks (partial answer, not whole denial) | TESTED_LOCAL (`15b870a` signed retrieval cache + reauthorization) | **NOT_VERIFIED live** (this behavior is in HEAD and not deployed in R44) |
| Cached chunks reauthorized per employee; no cross-employee reuse | TESTED_LOCAL | route cert cache check (repeat question) |
| Revocation and restoration, in-flight | VERIFIED_LIVE (route cert includes one live SharePoint revocation, restored in `finally`) | 2026-11-05 certs |
| Forged attestations, tampered/replayed requests, token swap, cross-app, cross-source | VERIFIED_LIVE (route cert gateway attack checks) | same |
| Gateway bypass / unsigned route probes | VERIFIED_LIVE (route probe checks) | same |
| Guard / Gateway outage fail-closed | VERIFIED_LIVE (route cert outage checks) | same |
| Database RLS bypass | TESTED_LOCAL (`scripts/validate_postgres_authorization_matrix.py`); live gate I NOT_VERIFIED today | — |
| Prompt injection / response exfiltration / streaming buffering | TESTED_LOCAL | — |
| Cross-tenant leakage (live, two real tenants) | NOT_VERIFIED: only one real Microsoft tenant exists | — |
| Auth/session (account attack matrix, Owner-only approve) | TESTED_LOCAL | — |
| Control-plane outage | TESTED_LOCAL | — |

## This session's security-relevant change
F-001 changes add no allow path. The watchdog sends only the non-secret `claims` and `session` queries, and refuses token queries (tested). The attestation preflight refuses a recertification without live sessions. The session lifetime is now enforced on the wall clock, which is stricter: it can no longer outlive its stated hours across a suspend.
