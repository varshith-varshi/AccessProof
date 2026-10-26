# AccessProof V4 — Final Readiness Report

**Date:** 2026-10-25
**Checkout:** `ab59ffd77a806066612fa33150d0bccb6006d69e` (`master`) plus the
uncommitted change set described below.
**Verdict:** **LAB — scoped local verification only. Enterprise production is
NO-GO.** This change set does not claim a constrained pilot, a certified
configuration, or provider certification. It fixes specific truth, evidence,
frontend, CI, retrieval, authorization-revision and migration defects and
records everything it did not verify.

---

## 1. Exact checkout, dirty state, and preserved work

| Item | Value |
|---|---|
| HEAD | `ab59ffd77a806066612fa33150d0bccb6006d69e` |
| Branch | `master` |
| Git status | 298 porcelain entries: 79 tracked modifications, 219 untracked |
| Commits created | None |
| Reset/clean/force-checkout/stash | None |
| Alembic head | `j4e2f6a8c013` (single head) |

The worktree was already heavily modified when this pass began. All prior
changes and untracked files were preserved. This pass did not overwrite or
delete another agent's work. The principal files added or edited for V4 are
linked throughout sections 2 and 3; a small number of pre-existing lint/type
errors in already-modified files were fixed without changing runtime behavior.

No customer data, production credentials, live tenant state, or deployed
services were accessed. No secrets, tokens, document text, prompts, answers, or
private keys were printed or added to documentation.

## 2. Feature-by-feature implementation status

### F01 — CI targets the active frontend: FIXED

[.github/workflows/ci.yml](.github/workflows/ci.yml) now has four jobs:

- `python`: ruff, mypy, compileall, pytest, single-head check, blank SQLite
  migration.
- `web`: `web-v2` npm ci/lint/typecheck/build + Playwright E2E.
- `typescript-sdk`: builds and tests `packages/rag-sdk-typescript`.
- `containers`: API, worker, runner, Guard, Gateway, and `web-v2` Docker builds
  plus a DB/Redis Compose smoke.

Legacy `apps/web` is no longer built or tested. [web-v2/Dockerfile](web-v2/Dockerfile)
is the frontend image built by CI. GitHub Actions itself was not executed in
this pass; local equivalents were.

### F02 — hard-coded Protect UI: FIXED

[web-v2/app/protection/page.tsx](web-v2/app/protection/page.tsx) now loads
`GET /api/v1/current/protection/overview` and renders only backend-owned
per-application states. [apps/api/accessproof_api/protection_state.py](apps/api/accessproof_api/protection_state.py)
defines twelve explicit states (`NOT_CONFIGURED`, `CONNECTED`, `VALIDATING`,
`SHADOW`, `PROTECT_PENDING`, `PROTECTED_VERIFIED`, `DEGRADED`, `STALE`,
`BLOCKED`, `CERTIFICATION_EXPIRED`, `UNSUPPORTED`, `UNKNOWN`) with documented
precedence. A mode flag, Guard heartbeat, or absence of errors cannot promote an
application to verified.

[web-v2/app/applications/page.tsx](web-v2/app/applications/page.tsx) also uses
the backend state instead of inferring protection from `mode`.
`GET /api/v1/current/protection/overview` is implemented in
[apps/api/accessproof_api/app.py](apps/api/accessproof_api/app.py) and is
tenant-scoped with RBAC.

### F03/F19 — reports: PARTIAL (real signed JSON delivered; no PDF package)

[web-v2/app/reports/page.tsx](web-v2/app/reports/page.tsx) generates, lists,
verifies, and downloads signed evidence. The backend endpoints are in
[apps/api/accessproof_api/app.py](apps/api/accessproof_api/app.py), storage is
in [apps/api/accessproof_api/db.py](apps/api/accessproof_api/db.py), the
request schema is [apps/api/accessproof_api/schemas.py](apps/api/accessproof_api/schemas.py),
and the migration is
[migrations/versions/h2b8d4e6f901_control_plane_reports.py](migrations/versions/h2b8d4e6f901_control_plane_reports.py).
Offline verification is [scripts/verify_control_plane_report.py](scripts/verify_control_plane_report.py).
Reports are metadata-only, tenant-scoped, Ed25519-signed, expire after 30 days,
and are capped at 200 per tenant. No PDF evidence package, external
timestamping, or third-party attestation exists. See
[12_EVIDENCE_AND_REPORT_VERIFICATION.md](12_EVIDENCE_AND_REPORT_VERIFICATION.md).

### F18 — dashboard coverage and missing data: FIXED for available data

[web-v2/app/dashboard/page.tsx](web-v2/app/dashboard/page.tsx) shows registered
vs verified applications, unverified applications, Guard health, fresh sources,
and Layer 1/Layer 2 decision telemetry. Missing telemetry is rendered as
`NO DATA`, never zero or a pass. Revocation-to-first-denial timing remains
`NO DATA` because no measured experiment exists; no SLO/histogram was invented.

### F05 — cache capability labels: PARTIAL (truthful labels, no certification)

[web-v2/app/integrations/setup/page.tsx](web-v2/app/integrations/setup/page.tsx)
labels Redis, Memcached, and PostgreSQL as reference adapters and states that
the opt-in Docker smoke is the only evidence. Selecting a backend does not
certify a customer's cache return paths.

### F28 — evidence distinction: FIXED for static scope

Protection, Dashboard, and Reports distinguish directly observed control-plane
state, customer-Guard assertions, provider-confirmed permissions, and
`NOT_OBSERVED`. The machine-readable capability matrix is now generated from
the canonical registry at
[03_FEATURE_AND_CAPABILITY_MATRIX.csv](03_FEATURE_AND_CAPABILITY_MATRIX.csv)
and explicitly records evidence levels and restrictions.

### Deep-research wave — authorization-first retrieval: implemented and unit/local tested

[packages/rag_sdk/authorized_retrieval.py](../../packages/rag_sdk/authorized_retrieval.py)
adds `AuthorizationScope` and `AuthorizedVectorRetriever`. Retrieval obtains a
Guard-issued scope, applies it before ANN, rejects out-of-scope hits, overfetches
within bounds, falls back to an exact authorized scan, detects starvation, and
re-runs Layer 1 on the final context with revision binding. Scope truncation,
missing revisions, partial denials and backend failures fail closed.

[packages/rag_sdk/pgvector_retrieval.py](../../packages/rag_sdk/pgvector_retrieval.py)
implements the reference pgvector backend with `document_id = ANY(...)` inside
the query, iterative HNSW scanning, and an exact index-bypassing fallback. It is
**`UNIT_VERIFIED` only**; no PostgreSQL/pgvector deployment was executed.

Cache hits are reauthorized through `ProtectedRAG.verify_cached_answer()`, which
verifies the signed manifest, current revision, Layer 1 dependencies and Layer 2
provenance before release.

See [19_AUTHORIZATION_FIRST_RETRIEVAL.md](19_AUTHORIZATION_FIRST_RETRIEVAL.md).

### Authorization revisions and Guard reporting: implemented

Signed, monotonic, tenant/application-scoped revisions are generated in
[apps/api/accessproof_api/authorization_revision.py](../../apps/api/accessproof_api/authorization_revision.py).
The Guard cache rejects stale revisions and same-revision/hash forks. Guards
report `active_authorization_revisions` in the authenticated heartbeat; the
control plane rejects unbound applications (`403`) and unissued revision/hash
pairs (`409`) and stores accepted reports for lag measurement
(`accessproof_guard_revision_lag_seconds`).

### Route certificates: implemented for the reference Gateway route

[apps/api/accessproof_api/route_certification.py](../../apps/api/accessproof_api/route_certification.py)
derives `NOT_APPLICABLE`, `MISSING`, `TESTED_NOT_CUTOVER`, `CERTIFIED` and
`EXPIRED` states from nonce-bound challenges. Certificates bind
tenant/application/Guard/source/adapter/contract/policy version, expire after
24 hours, and are surfaced in Protection status/overview and the UI. A Guard
policy change correctly invalidates a previous certificate as `EXPIRED`
(regression covered).

### Revocation timeline and metrics: implemented with `NOT_OBSERVED` semantics

[apps/api/accessproof_api/revocation_timeline.py](../../apps/api/accessproof_api/revocation_timeline.py)
exposes six timestamps: provider mutation, provider observation, ACL commit,
authorization revision creation, first Guard use under that revision, and first
matching verified denial. Missing values are explicit `NOT_OBSERVED`; unrelated
denials do not count; subject/resource identifiers are not returned.

[apps/api/accessproof_api/observability.py](../../apps/api/accessproof_api/observability.py)
adds bounded freshness, revision-lag, route-certificate coverage, Layer 2,
cache-reauthorization and end-to-end revocation metrics. A gauge with no sample
means no retained evidence; it is not zero.

### Capability registry and compatibility scanner: implemented as evidence tools

[packages/capability_registry.py](../../packages/capability_registry.py) is the
canonical support registry, exposed via `GET /api/v1/current/capabilities` and
`scripts/export_capability_registry.py`. It contains no live evidence and
refuses `CONSTRAINED_PILOT`/`CERTIFIED_PROFILE`; Microsoft 365 is not
Protect-eligible; PDF packages, native streaming, WebSocket, tools, Kubernetes
and independent certification are unsupported.

[scripts/compatibility_scan.py](../../scripts/compatibility_scan.py) is a
read-only static scanner that never imports/executes target code, skips
secrets/symlinks, and always returns `NOT_CERTIFIED` with blockers. See
[04_INTEGRATION_COMPATIBILITY.md](04_INTEGRATION_COMPATIBILITY.md) and
[20_ROUTE_CERTIFICATION_AND_REVOCATION_EVIDENCE.md](20_ROUTE_CERTIFICATION_AND_REVOCATION_EVIDENCE.md).

### Other findings

F06, F07, F09–F13, F16, F17, F20, F22, F25 and F26 remain open or limited as
recorded in [01_FINDINGS_REGISTER.md](01_FINDINGS_REGISTER.md). F08 Microsoft
Protect remains restricted. F09 release-manifest reproducibility and F10
separated migration remain open. F27's known provenance gap is represented by a
strict XFAIL test, not a passing claim.

## 3. Confirmed defects and regression coverage

| Before | After | Regression evidence |
|---|---|---|
| CI built/tested legacy `apps/web` | CI builds/tests `web-v2`; TS SDK job added | Playwright 29 passed/1 skipped locally; workflow reviewed but not executed on GitHub |
| Protection page implied a static Protect state | Backend state per application; unknown/stale/blocked are explicit | `tests/unit/test_protection_state.py`, `tests/integration/test_protection_overview.py`, Playwright protection test |
| Reports page was a placeholder | Signed, expiring, verifiable JSON reports | `tests/integration/test_control_plane_reports.py`, `tests/unit/test_verify_control_plane_report.py`, Playwright reports test |
| Dashboard omitted coverage/freshness and had no missing-data semantics | Verified coverage, Guard/source freshness, decision telemetry, explicit `NO DATA` | `tests/integration/test_control_plane_reports.py`, Playwright dashboard test |
| Production web container received unused `API_URL`/`NEXT_PUBLIC_API_URL` | Receives `ACCESSPROOF_API_URL`/`ACCESSPROOF_API_HOST` used by the web-v2 proxy | Compose config validation; [docs/production-deployment.md](../production-deployment.md) |
| 8 ruff errors and 18 mypy errors blocked the CI Python job | `ruff` and `mypy` clean | Targeted 84 tests for the type-fixed modules passed after changes |
| Retrieval ranked a global ANN top-k then post-filtered, allowing scope starvation and unauthorized handling | Scope predicate is applied in the datastore; exact authorized fallback and starvation reporting added; out-of-scope hits block | `tests/security/test_authorized_retrieval.py`, `tests/unit/test_guard_authorization_scope.py` |
| A Guard policy change erased route evidence and reported `MISSING` | Superseded challenges are located and reported as `EXPIRED` with prior evidence | `tests/integration/test_route_certificate_state.py` |
| Revocation timing had no measurement path | Six-timestamp retained-evidence timeline and end-to-end histogram; missing values are `NOT_OBSERVED`/no sample | `tests/integration/test_revocation_timeline_api.py` |
| Guard revision application was unreported | Authenticated heartbeat reports revisions; unbound/unissued reports are rejected; lag metric added | `tests/integration/test_guard_revision_reporting.py`, `tests/integration/test_observability.py` |
| No machine-readable capability matrix or static bypass scanner | Registry + CSV export + read-only scanner, always `NOT_CERTIFIED` | `tests/integration/test_capability_registry.py`, `tests/unit/test_compatibility_scanner.py` |

The type fixes were behavior-preserving: explicit string narrowing, a
`Callable` annotation, a manifest type annotation, a generator return type, a
typed key list, and one ignored missing stub for `pymemcache`. No security
condition was weakened.

## 4. Supported environments and unsupported combinations

**Verified in this pass**

- CPython 3.12 virtual environment with SQLite test databases.
- Node.js 22/24, `web-v2` lint, typecheck, production standalone build, and
  Chromium Playwright at desktop and mobile viewports (API routes mocked).
- SQLite blank upgrade to `j4e2f6a8c013` and legacy-to-head upgrade.
- Compose YAML syntax for base, production, and EC2 files; production Compose
  rejects missing required image variables.
- Authorization-first retrieval algorithm/SQL shape, Guard scope failure modes,
  cache reauthorization, route certificates, revision reporting, revocation
  timeline, capability registry, scanner and bounded metrics (unit/local tests).

**Not verified in this pass**

- PostgreSQL (including production migration and rollback) and any live
  PostgreSQL/pgvector query plan or latency.
- Docker image builds, container runtime, real Redis/Memcached, real Guard,
  Gateway, source ingester, or customer RAG.
- Live Google Workspace, Microsoft Entra/SharePoint/OneDrive, or LLM providers;
  no provider mutation experiment or independent live-user oracle.
- A customer application's own vector store, cache, streaming, WebSocket, tool
  or worker return paths being covered by a route certificate.
- Multi-worker/HA behavior, load, disaster recovery, backup restore, TLS/proxy,
  and independent security testing.
- GitHub Actions execution.

**Explicitly unsupported or restricted**

- Arbitrary RAG routes and non-buffered native streaming/WebSocket/tool output.
- Microsoft Protect without independently certified effective permissions.
- Claims that cache selection alone establishes protected return paths.
- Any claim that `PROTECTED_VERIFIED` covers bypasses outside the enrolled,
  challenged route.

## 5. Exact test commands, duration, counts, and logs

| Check | Command | Result | Duration |
|---|---|---|---|
| Full Python suite (final tree) | `.venv/bin/python -m pytest -o addopts="" -q` | **865 passed, 1 xfailed, 0 failed, 0 skipped, 7 warnings** | 509.29s (8:29) |
| Report/protection tests | pytest on `test_protection_state.py`, `test_protection_overview.py`, `test_control_plane_reports.py` | 22 passed | n/a |
| Deep-research tests | pytest on retrieval, Guard scope, scanner, capability registry, route certificate, challenge, timeline, revision reporting and observability modules | included in the full suite (all passed) | n/a |
| Offline verifier | pytest on `test_verify_control_plane_report.py` | 5 passed | n/a |
| Migration test | pytest on `test_migrations.py` | 1 passed | 4.27s |
| Type-fixed module tests | pytest on google token/webhook, provider worker, gateway boundary/installer/agent/cutover, cache connectors, Redis cache | 84 passed | 21.40s |
| Ruff | `.venv/bin/ruff check .` | All checks passed | n/a |
| Mypy | `.venv/bin/mypy apps packages connectors integrations` | Success, 139 files | n/a |
| Compile | `python -m compileall -q apps packages connectors integrations scripts migrations` | exit 0 | n/a |
| Frontend lint/typecheck | `cd web-v2 && npm run lint && npm run typecheck` | passed | n/a |
| Browser E2E | `cd web-v2 && npm run test:e2e` | **29 passed, 1 skipped** | 16.1s |
| TypeScript SDK | `cd packages/rag-sdk-typescript && npm test` | **34 passed, 0 failed** | 130ms |
| Alembic heads | `alembic heads` | `j4e2f6a8c013 (head)` | n/a |
| Blank migration | `DATABASE_URL=sqlite:////tmp/ap_v4_migration_dr.db alembic upgrade head` | exit 0 through `j4e2f6a8c013` | n/a |
| Compose syntax | `docker compose -f <file> config --no-interpolate -q` | exit 0 for base/production/EC2 (previous snapshot) | n/a |
| Compose missing secrets | production `config -q` without required vars | exit 1, first missing image variable (previous snapshot) | n/a |

Logs (local, ephemeral): `/tmp/ap_v4_full_pytest_dr.log`,
`/tmp/ap_v4_migration_dr.log`. The full run above is authoritative. The single
XFAIL is `tests/security/test_known_provenance_integrity_gap.py`, a strict
marker for the known metadata-only provenance gap; if the gap is fixed, the
strict marker turns into an XPASS failure so the claim can be updated.

Playwright uses the real built `web-v2` UI with mocked API responses; it is not
a live control-plane integration test. The protection test now also asserts the
route-certificate `CERTIFIED`/`EXPIRED` display. No screenshots are claimed.

## 6. External resources and deployment status

| Question | Answer |
|---|---|
| Provider credentials or live test tenants used | **No** |
| Real LLM calls | **No** (no provider was called) |
| Real Redis/PostgreSQL/source/Guard/RAG Docker test | **No** in this pass; Redis cache tests use an in-memory test double |
| Docker images built | **No** (disk safety; ~7 GB free / 99% used) |
| Deployment | **Local only**; no staging or production deployment |
| Release image digests | **None**; no immutable release manifest exists |
| External approvals needed | Live provider test tenants, production credentials/deployment, load/HA testing, and any destructive migration drill |

## 7. Residual P0/P1/P2 findings and separate gates

- **P0:** Microsoft effective-permission truth (F08) is not independently
  certified; Microsoft Protect remains restricted.
- **P0:** Arbitrary route/cache/tool/memory bypass coverage (F14/F15) and
  independent live-user source oracle (F16) remain open. The registry now marks
  unsupported paths explicitly and the scanner detects static bypass patterns,
  but neither certifies runtime coverage.
- **P0:** Authorization-first retrieval is `UNIT_VERIFIED` only. No live
  PostgreSQL/pgvector deployment, customer vector store, or query-plan/latency
  evidence exists.
- **P0:** Release reproducibility (F09) and separated migration/rollback wiring
  (F10) remain open. The API still runs `alembic upgrade head` at startup.
- **P0:** Multi-worker/HA/load/DR/backup-restore and independent security
  assessment (F17) remain unverified.
- **P1:** No live provider revocation experiment exists, so the timeline and
  end-to-end histogram have no production sample. Route certificates are
  reference-Gateway-only and local.
- **P1:** PDF/attestation report package (F03), provider live validation (F12),
  license/metering (F25), onboarding/pilot evidence (F11/F20), and the
  remaining documentation artifacts.
- **P2:** Competitive, roadmap, and procurement artifacts require sourced,
  current evidence; none were fabricated in this pass.

**Google gate:** not met; no authorized live Google test tenant or independent
effective-access oracle was used.
**Microsoft gate:** not met and remains separately restricted; no Microsoft
Protect certification is implied.

## 8. Required documentation status

Delivered in this change set:

- `00_BASELINE.md`
- `01_FINDINGS_REGISTER.md`
- `03_FEATURE_AND_CAPABILITY_MATRIX.csv` (generated from the registry)
- `04_INTEGRATION_COMPATIBILITY.md`
- `10_CI_RELEASE_AND_MIGRATION.md`
- `12_EVIDENCE_AND_REPORT_VERIFICATION.md`
- `18_FINAL_V4_READINESS_REPORT.md` (this file)
- `19_AUTHORIZATION_FIRST_RETRIEVAL.md`
- `20_ROUTE_CERTIFICATION_AND_REVOCATION_EVIDENCE.md`

Not produced in this pass: `02_SECURITY_THREAT_MODEL.md`,
`05_SOURCE_AND_REVOCATION.md`, `06_LAYER1_LAYER2_PROVENANCE.md`,
`07_CACHE_MEMORY_STREAM_TOOL_COVERAGE.md`,
`08_INFRA_RELIABILITY_AND_RECOVERY.md`, `09_SECURITY_TEST_MATRIX.csv`,
`11_CUSTOMER_ONBOARDING_AND_PILOT.md`,
`13_COMPETITOR_FEATURE_COMPARISON.md`, `14_TRUST_AND_PROCUREMENT_PACKET.md`,
`15_PRODUCT_ROADMAP.md`, `16_DEPLOYMENT_AND_ROLLBACK_RUNBOOK.md`, and
`17_CUSTOMER_DEMO_SCRIPT.md`. Existing reports elsewhere in `docs/` were not
rewritten or deleted. This report does not substitute for those artifacts.
Coverage of retrieval, revocation, cache and capability evidence is documented
in `19_` and `20_`; `07_` remains unwritten as a separate artifact.

## 9. Final verdict

**LAB.** The scoped changes are suitable for continued local development and CI
validation: the active frontend builds and its browser suite passes, the
TypeScript SDK passes, the Python suite passes with one intentional strict
XFAIL, lint/type checks are clean, and the new migrations reach a single head
from blank and legacy SQLite databases. Authorization-first retrieval, signed
revisions, route certificates, the revocation timeline, bounded metrics, the
capability registry and the read-only scanner are implemented and covered by
local tests.

**Enterprise production: NO-GO.** The product still lacks independently
certified Google/Microsoft source truth, a live PostgreSQL/pgvector execution,
verified arbitrary-route and cache coverage, a live provider revocation
measurement, reproducible signed release images, a separated migration job with
tested rollback, PostgreSQL migration evidence, HA/DR/load evidence, and
independent security assessment. The new authorization and evidence features
improve fail-closed behavior and truthfulness; they do not close those gates.

## 10. Next actions

1. Execute the pgvector backend against an authorized PostgreSQL/pgvector
   deployment, record query plans and latency, and prove authorization-first
   behavior with real data (F14/F16).
2. Obtain a live customer route challenge with independent cutover evidence and
   a live provider revocation experiment so the timeline/histogram have real
   samples (F08/F16/F18).
3. Build the separated, idempotent migration job with backup verification,
   preflight head check, and a tested rollback/roll-forward drill; stop relying
   on API-startup migration (F10).
4. Execute PostgreSQL upgrade/rollback and production-Compose negative tests in
   a disposable authorized environment (F10, F17).
5. Produce one immutable release manifest with digests and SBOM for API,
   worker, Guard, Gateway, web-v2, and ingester (F09).
6. Expand verified route/cache/stream/tool coverage or keep each path explicitly
   unsupported and fail closed (F14/F15).
7. Run load, multi-worker, backup-restore, and failover tests (F17).
8. Produce the remaining `docs/v4/` artifacts from executed evidence (section 8)
   rather than narrative assumptions.
