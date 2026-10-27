# AccessProof V4 — Baseline and Environment

**Snapshot date:** 2026-10-24 (**verification refresh:** 2026-10-25)
**Repository:** `/home/white-devil/Downloads/accessproof/f15`
**Branch:** `master`
**Checkout:** `ab59ffd77a806066612fa33150d0bccb6006d69e` (`Harden Guard concurrency and durable recovery`)
**Alembic head:** `j4e2f6a8c013` (single head; adds Guard-reported authorization revisions)

## Worktree state (preserved)

The worktree was already heavily modified before this change set. No reset,
clean, force-checkout, or stash was performed.

| Measure | Observed |
|---|---|
| `git status --porcelain` entries | 298 |
| Untracked entries | 219 |
| Tracked modifications | 79 |

This change set added or modified only files related to the V4 frontend/evidence
work:

- `apps/api/accessproof_api/protection_state.py` (new)
- `apps/api/accessproof_api/app.py` (protection overview, dashboard evidence, signed reports)
- `apps/api/accessproof_api/db.py` (`control_plane_reports`)
- `apps/api/accessproof_api/schemas.py` (`ControlPlaneReportCreate`)
- `apps/api/accessproof_api/auth.py` (API-key scope for report reads)
- `migrations/versions/h2b8d4e6f901_control_plane_reports.py` (new)
- `web-v2/app/protection/page.tsx`, `web-v2/app/reports/page.tsx`,
  `web-v2/app/dashboard/page.tsx`, `web-v2/app/applications/page.tsx`,
  `web-v2/app/integrations/setup/page.tsx`, `web-v2/components/ui.tsx`,
  `web-v2/lib/api.ts`, `web-v2/e2e/web-v2.spec.ts`
- `.github/workflows/ci.yml`
- `scripts/verify_control_plane_report.py` (new)
- `docker-compose.production.yml`, `docs/production-deployment.md`
- `tests/unit/test_protection_state.py`, `tests/unit/test_verify_control_plane_report.py`,
  `tests/integration/test_protection_overview.py`,
  `tests/integration/test_control_plane_reports.py`
- `docs/v4/` evidence documents

### Deep-research wave (this continuation)

The second wave implemented the missing authorization/evidence capabilities
from the deep-research report:

- `packages/rag_sdk/authorized_retrieval.py` (AuthorizationScope,
  AuthorizedVectorRetriever, scope/starvation/revision failure reasons)
- `packages/rag_sdk/pgvector_retrieval.py` (authorization predicate inside SQL,
  iterative ANN scan, exact index-bypassing fallback)
- `packages/capability_registry.py` and `scripts/export_capability_registry.py`
- `apps/api/accessproof_api/route_certification.py` and
  `apps/api/accessproof_api/revocation_timeline.py`
- `apps/api/accessproof_api/observability.py` (authorization freshness,
  revision lag, route coverage, revocation timing, Layer 2/cache counters)
- `apps/api/accessproof_api/app.py`, `db.py`, `schemas.py` (capability and
  timeline endpoints, Guard revision reporting)
- `apps/guard/accessproof_guard/{app,cache,sync}.py` (scope endpoint, revision
  snapshot and heartbeat report)
- `migrations/versions/j4e2f6a8c013_guard_reported_revisions.py`
- `scripts/compatibility_scan.py`
- `docs/v4/03_FEATURE_AND_CAPABILITY_MATRIX.csv`,
  `docs/v4/04_INTEGRATION_COMPATIBILITY.md`,
  `docs/v4/19_AUTHORIZATION_FIRST_RETRIEVAL.md`,
  `docs/v4/20_ROUTE_CERTIFICATION_AND_REVOCATION_EVIDENCE.md`
- New tests: `test_guard_authorization_scope.py`,
  `test_compatibility_scanner.py`, `test_capability_registry.py`,
  `test_route_certificate_state.py`, `test_revocation_timeline_api.py`,
  `test_guard_revision_reporting.py`, and additions to
  `test_rag_route_challenge_api.py` and `test_observability.py`

No customer data, production credentials, live tenant state, or deployed
services were accessed. No Docker image was built locally for this change set.

## Environment constraints

| Resource | Observed |
|---|---|
| Disk | 6.1 GB available on `/` (99% used) at the deep-research snapshot |
| RAM | 15 GiB total, 8.5 GiB available |
| Swap | 2.0 GiB, unused at snapshot |
| Node.js | v24.18.0 |
| Python | 3.12 virtual environment (`/.venv`) for tests |

The disk constraint is treated as a hard operating limit: no uncontrolled
Docker builds, no large artifact generation, and no destructive cleanup. Test
databases are per-process SQLite temp files (`tests/conftest.py`).

## Architecture map

| Area | Location | Role |
|---|---|---|
| Control-plane API | `apps/api/accessproof_api` | FastAPI endpoints, RBAC, tenant scoping, reports, protection state |
| Worker | `apps/worker/accessproof_worker` | Durable permission-event fan-out and ACL resolution |
| Runner | `apps/runner/accessproof_runner` | Legacy synthetic validation runner |
| Guard | `apps/guard/accessproof_guard` | Customer-side Layer 1/2 decision point, cache, sync |
| Gateway | `apps/gateway/accessproof_gateway` | Reference supported route, cache authorization, cutover checks |
| Active frontend | `web-v2` | Next.js 16 App Router UI with server-side `/api` proxy |
| Legacy frontend | `apps/web` | Superseded; compose profile `legacy` only |
| Connectors | `connectors/` | Google Drive and Microsoft 365 source adapters |
| Shared packages | `packages/` | auth, crypto signing, identity, policy, RAG SDK, test engine, report rendering |
| Schema | `migrations/versions/` | Alembic migrations (40 revisions) |
| CI | `.github/workflows/ci.yml` | Python, web-v2, TypeScript SDK, containers |
| Customer reference RAG | `drive-rag-demo/` | Docker reference route; independent RAG remains outside this tree |

## Verification baseline

Final verification on the completed tree (2026-10-25):

```text
.venv/bin/ruff check .                        # All checks passed
.venv/bin/mypy apps packages connectors integrations  # Success: 139 files
.venv/bin/python -m compileall -q apps packages connectors integrations scripts migrations
# exit 0

.venv/bin/python -m pytest -o addopts="" -q
# 865 passed, 1 xfailed, 0 failed, 0 skipped, 7 warnings in 509.29s
# log: /tmp/ap_v4_full_pytest_dr.log

DATABASE_URL=sqlite:////tmp/ap_v4_migration_dr.db .venv/bin/alembic upgrade head
# exit 0 through j4e2f6a8c013 (log: /tmp/ap_v4_migration_dr.log)
.venv/bin/python -m pytest -o addopts="" -q tests/integration/test_migrations.py  # 1 passed
.venv/bin/alembic heads                       # j4e2f6a8c013 (head)

cd web-v2 && npm run lint        # passed
cd web-v2 && npm run typecheck   # passed
cd web-v2 && npm run test:e2e    # 29 passed, 1 skipped (mobile-only assertion) in 16.1s
cd packages/rag-sdk-typescript && npm test  # 34 passed in 130ms
```

The full-suite result covers the Python tests; Playwright, TypeScript SDK, lint,
typecheck, migration and compile checks ran separately as above. Targeted
deep-research reproduction commands are listed in `01_FINDINGS_REGISTER.md`.

`docker compose -f docker-compose.production.yml config --no-interpolate -q`
and the same for `docker-compose.ec2.yml` and `docker-compose.yml` all returned
exit 0 (syntax only). Without required environment variables, production
Compose fails closed on the first missing image variable.

No Docker image was built locally; the CI `containers` job has not been
executed. The full-suite result and release verdict are recorded in
`docs/v4/18_FINAL_V4_READINESS_REPORT.md`.

## Known P0 limitations at snapshot

1. **Microsoft 365 / SharePoint / OneDrive Protect is restricted.** Effective
   permissions are not independently certified against a live authorized
   tenant; `MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED` remains a required
   check.
2. **Route certification is reference-route only.** `PROTECTED_VERIFIED`
   requires current machine-bound evidence; the legacy `mode=protect` value is
   not proof of protection. Arbitrary API, SSE, WebSocket, tool, cache and
   worker paths are not covered.
3. **Revocation timing is measured from retained evidence only.** The
   six-timestamp timeline and end-to-end histogram report `NOT_OBSERVED`/no
   sample when evidence is absent. No live provider mutation experiment was
   performed, so no latency claim or SLO is certified.
4. **Authorization-first retrieval is not live-verified.** The pgvector backend
   is `UNIT_VERIFIED` only; it was not executed against PostgreSQL/pgvector, and
   no customer vector store was inspected.
5. **The capability registry contains no live evidence.** All entries are
   `UNIT_VERIFIED`, `LOCAL_INTEGRATION_VERIFIED`, or
   `CONTRACT_SIMULATED`. `CONSTRAINED_PILOT` and `CERTIFIED_PROFILE` release
   gates are refused by the registry.
6. **Production reliability evidence is incomplete.** Multi-worker, failover,
   load, disaster recovery, and independent security testing remain gated.
7. **Release reproducibility is incomplete.** `docker-compose.ec2.yml` still
   carries a hard-coded frontend tag; a verified image-digest release manifest is
   not yet implemented.
8. **Disk headroom is critical.** Large local containers/builds are unsafe.

## Change plan executed in this pass

| Wave | Scope | State |
|---|---|---|
| 0 | Truth/release safety: CI targets `web-v2`, hard-coded Protect removed, explicit protection state model, accurate dashboard/report semantics | Implemented for the scoped files |
| 1 | Evidence/reporting: signed control-plane reports, verification, offline verifier | Implemented and tested |
| 2 | Remaining V4 register items (F04, F06–F17, F20–F28) | Partially addressed: F04/F05/F15/F18/F21/F23/F24/F28 improved by wave 3; F06/F07/F09/F10/F12/F13/F16/F17/F20/F22/F25/F26/F27 remain open or limited. See `01_FINDINGS_REGISTER.md` |
| 3 | Deep-research P0/P1: authorization revisions and Guard reporting, scope-bound retrieval, cache reauthorization, route certificates, revocation timeline, bounded metrics, capability registry/CSV, read-only compatibility scanner | Implemented and locally tested; live-provider and PostgreSQL evidence remain open |
