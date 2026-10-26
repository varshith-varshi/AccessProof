# AccessProof V4 — Findings Register (F01–F28)

**Snapshot:** 2026-10-24 · checkout `ab59ffd`
**Legend:** `FIXED` = implemented and covered by tests in this change set;
`PARTIAL` = a verified subset is implemented but the original requirement is not
fully met; `OPEN` = not addressed in this change set; `LIMITED` = product is
intentionally restricted and the UI/backend must keep saying so.

No entry below claims production certification that was not executed. Items
requiring live tenants, live provider APIs, load tests, or approved production
actions remain open regardless of code quality.

A **deep-research wave** after the first V4 snapshot added authorization
revisions, scope-bound retrieval, cache reauthorization, route certificates,
the revocation timeline, bounded metrics, the capability registry/CSV, and a
read-only compatibility scanner. Rows changed by that wave are marked
**[DR]**. Live-provider, PostgreSQL/pgvector, arbitrary-route and independent
certification evidence is still absent.

| ID | Severity | Status | Evidence / residual risk |
|---|---|---|---|
| F01 | P0/P1 | **FIXED** | `.github/workflows/ci.yml` now runs `npm ci/lint/typecheck/build` and Playwright in `web-v2`; container job builds `web-v2/Dockerfile`; added TypeScript SDK job. Locally, `ruff`, `mypy`, and `compileall` are clean, Playwright is 29 passed/1 skipped, and the TS SDK is 34 passed. Residual: `docker-compose.yml` still keeps legacy `apps/web` under profile `legacy` (explicitly labelled), and `docker-compose.ec2.yml` still pins an image tag (see F09). |
| F02 | P0 | **FIXED** | `web-v2/app/protection/page.tsx` no longer renders a static Protect state. It loads `GET /api/v1/current/protection/overview`, which classifies each tenant-scoped application into an explicit state (`PROTECTED_VERIFIED`, `NOT_CONFIGURED`, `UNSUPPORTED`, `BLOCKED`, `STALE`, `VALIDATING`, `PROTECT_PENDING`, `SHADOW`, `DEGRADED`, `CERTIFICATION_EXPIRED`, `UNKNOWN`). Applications page also uses the backend state instead of inferring from `mode`. Residual: the overview is limited to 200 applications per tenant. |
| F03 | P1 | **PARTIAL** | Reports page now generates, lists, verifies, and downloads signed control-plane JSON reports. No PDF evidence package. Reports are metadata-only and expire after 30 days; storage is capped at 200 reports per tenant (HTTP 429 after that; no destructive auto-deletion). |
| F04 | P0 truth / P1 UX | **PARTIAL [DR]** | Guided integration UI keeps explicit “reference Docker route only” language and backend route-challenge gating. `scripts/compatibility_scan.py` now performs a read-only static scan for routes, identity, retrieval, cache, model, streaming, WebSocket, tool and background-worker evidence, always returning `NOT_CERTIFIED`. It does not automatically detect every runtime path or certify compatibility. |
| F05 | P0 truth | **PARTIAL [DR]** | `web-v2/app/integrations/setup/page.tsx` labels each cache choice as a reference adapter, names the opt-in Docker smoke as the only evidence, and states that selection is not production certification. `ProtectedRAG.verify_cached_answer()` now reauthorizes cache hits against the current employee and authorization revision. Real customer cache return-path coverage is still unproven. |
| F06 | P1 | **OPEN** | Source ingester document-type coverage was not changed. |
| F07 | P0 | **OPEN** | Shared-drive/group-change feed reconciliation and measured freshness were not changed. |
| F08 | P0 (Microsoft Protect) | **LIMITED** | Microsoft effective-permission certification remains a required failing check unless an independently issued certificate exists; Protect stays restricted. The capability registry marks Microsoft 365 `protect_eligible=false`. No live-tenant validation was performed. |
| F09 | P1 | **OPEN** | No immutable multi-image release manifest/digest pinning was implemented. `docker-compose.ec2.yml` still contains a fixed frontend tag. |
| F10 | P1 risk | **OPEN** | API startup migration behavior was not changed. Deployments still require an explicit migration/backup procedure. |
| F11 | Immediate | **MITIGATED (workflow only)** | No destructive cleanup or container builds were performed. Disk remains ~6.1 GB free / 99% used. |
| F12 | P1 | **OPEN** | Cloud model adapters were not live-provider validated; no credentials were spent. |
| F13 | P1/P2 | **OPEN** | No new custom-adapter conformance harness. UI continues to warn that non-compatible protocols need a reviewed adapter. |
| F14 | P0 route truth | **LIMITED [DR]** | Arbitrary streaming/WebSocket/tool-output coverage was not expanded. The capability registry explicitly marks native streaming, WebSocket, tools/agents and background workers `UNSUPPORTED`; only buffered HTTP is `SUPPORTED` and buffered SSE is `PARTIAL`. The compatibility scanner reports these paths as blockers. |
| F15 | P0 | **PARTIAL [DR]** | The scanner now detects direct model endpoints, cache paths without reauthorization, global ANN/post-filter risk, unsupported tool/worker/WebSocket paths and provenance gaps as static bypass findings. This is evidence for human review, not runtime enforcement or certification. |
| F16 | P0 source | **OPEN** | No independent live-user oracle in an authorized tenant. |
| F17 | P0 before broad Prod | **OPEN** | No multi-worker/HA/load/DR or independent security test evidence in this pass. |
| F18 | P1 | **PARTIAL [DR]** | Dashboard shows registered/verified/not-verified applications, Guard health buckets, source freshness, Layer 1/2 decision telemetry, and `NO DATA` when no decisions exist. A privacy-safe six-timestamp revocation timeline (`GET /api/v1/current/revocation-timeline`) and end-to-end histogram now measure provider-change-to-first-denial from retained evidence. Without live provider experiments the fields are `NOT_OBSERVED` and the histogram has no sample; no SLO is certified. |
| F19 | P1 | **PARTIAL** | Signed JSON reports, in-product verification, download, and `scripts/verify_control_plane_report.py` are implemented. No signed PDF package; offline verifier checks signature, schema, tenant/type/key expectations and expiry. |
| F20 | P1 | **OPEN** | Reason codes are surfaced in Protection UI and reports, but no new employee-facing privacy-safe diagnostic workflow was implemented. The revocation timeline is tenant-scoped admin evidence (`AUDIT_READ`), not an employee-facing diagnostic. |
| F21 | P1 | **PARTIAL [DR]** | `scripts/compatibility_scan.py` is a read-only scanner that never imports/executes target code, skips secrets/symlinks, and emits file:line evidence plus blockers. It is static-only; a clean scan is never `SUPPORTED` or `CERTIFIED`. |
| F22 | P1/P2 | **OPEN** | No new framework conformance packages/tests. |
| F23 | P1 | **PARTIAL [DR]** | New bounded metrics cover authorization decisions/latency, source/directory freshness, provider event lag, Guard revision lag, route certificate age/coverage, cache reauthorization, Layer 2 blocks and revocation timing, with no tenant identifiers. No production on-call/rollback exercise was performed. |
| F24 | P1 | **PARTIAL [DR]** | The capability registry and `03_FEATURE_AND_CAPABILITY_MATRIX.csv` provide a machine-readable, honest support matrix. No procurement/trust-center package or external attestation exists; the registry must not be presented as a certificate. |
| F25 | P2 | **OPEN** | No licensing/metering/billing UX. |
| F26 | P0/P1 | **OPEN** | No new independent customer-RAG demonstration with a real generative model. |
| F27 | P0 for legacy route | **OPEN / verify** | Legacy route remains uncertified. Final full Python suite result is recorded in `18_FINAL_V4_READINESS_REPORT.md`; the known provenance gap remains a strict XFAIL, not a bypass. |
| F28 | P1 | **FIXED (static scope) [DR]** | UI distinguishes verified vs asserted vs unobserved evidence, cache labels state reference-only status, and `03_FEATURE_AND_CAPABILITY_MATRIX.csv` is now generated from the canonical registry with evidence levels and explicit restrictions. The matrix contains no live provider/customer evidence. |

## Reproduction for fixed items

```bash
# Explicit protection state model
.venv/bin/python -m pytest tests/unit/test_protection_state.py -q

# Tenant-scoped overview, unsupported/blocked/unverified states
.venv/bin/python -m pytest tests/integration/test_protection_overview.py -q

# Signed reports: tamper, expiry, tenant isolation, NO DATA dashboard
.venv/bin/python -m pytest tests/integration/test_control_plane_reports.py -q

# Offline verifier
.venv/bin/python -m pytest tests/unit/test_verify_control_plane_report.py -q

# Deep-research wave: retrieval, revisions, route certificates, timeline, scanner
.venv/bin/python -m pytest \
  tests/security/test_authorized_retrieval.py \
  tests/unit/test_guard_authorization_scope.py \
  tests/unit/test_compatibility_scanner.py \
  tests/integration/test_capability_registry.py \
  tests/integration/test_route_certificate_state.py \
  tests/integration/test_rag_route_challenge_api.py \
  tests/integration/test_revocation_timeline_api.py \
  tests/integration/test_guard_revision_reporting.py \
  tests/integration/test_observability.py -q

# Capability matrix (regenerate; committed copy is checked in)
.venv/bin/python scripts/export_capability_registry.py --format csv \
  > docs/v4/03_FEATURE_AND_CAPABILITY_MATRIX.csv

# Frontend
cd web-v2 && npm run lint && npm run typecheck && npm run test:e2e
```

## Residual risks that block a broad production claim

1. `PROTECTED_VERIFIED` is a **time-bound backend observation**, not a universal
   security certificate. It does not cover bypass paths outside the enrolled
   route. A route certificate is reference-Gateway-only and expires after 24
   hours.
2. Report `guard_decisions` are customer-machine assertions unless the report
   says otherwise. The revocation timeline measures only retained evidence; a
   missing timestamp is `NOT_OBSERVED`, never inferred, and no live provider
   measurement or SLO exists.
3. Microsoft Protect remains restricted pending independently certified
   effective permissions.
4. Authorization-first retrieval and its pgvector backend are `UNIT_VERIFIED`
   only; no live PostgreSQL/pgvector or customer vector store was executed.
5. The capability registry contains no `LIVE_PROVIDER_VERIFIED`,
   `INDEPENDENT_CUSTOMER_VERIFIED`, `STAGING_VERIFIED`, or
   `PRODUCTION_OBSERVED` entries. `CONSTRAINED_PILOT` and `CERTIFIED_PROFILE`
   remain refused.
6. Release reproducibility, migration gating, HA/DR, and independent security
   assessment remain open P0/P1 gates.
