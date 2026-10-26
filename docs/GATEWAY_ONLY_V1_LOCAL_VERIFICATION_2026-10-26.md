# AccessProof Gateway-only V1: local verification report

**Date:** 26 October 2026
**Repository:** `/home/white-devil/Downloads/accessproof/f15`
**Private GitHub:** `varshith-varshi/AccessProof`
**Review branch:** `gateway-only-v1-20261026` (draft PR #1)
**Overall release decision:** **NO-GO for unscoped enterprise production Protect**.

## Refactor verified

- Gateway-only application creation enforced by both the input schema and server-side integration registry. All retired SDK and framework adapter types are rejected with HTTP 422.
- SDK/framework catalog removed from `web-v2` in favor of an AccessProof Gateway onboarding path. New application registration has a fixed Gateway route and only Google Drive source choices.
- Historical non-Gateway application records remain audit-visible but offer no Protect action in the UI and are never eligible for Protect by readiness gates.
- Public Python RAG SDK removed (`packages/rag_sdk`). Public TypeScript RAG SDK removed (`packages/rag-sdk-typescript`).
- Cryptographic source attestation, Layer 1, Layer 2, authorized retrieval and signed cache security remain as **private server-side Gateway engine** in `packages/rag_core`. No transparent proxy is claimed for opaque RAG paths.
- Framework wrappers no longer shipped; retired implementation references are archived outside the checkout for recovery.
- Customer Guard release bundle copies only its internal identity/HTTP dependencies; it does not contain a RAG SDK or the Gateway engine.
- SDK-specific TypeScript CI job removed **locally**, but no GitHub Actions workflow was uploaded due missing `workflow` account permission.

## Verified Python suites

| Scope | Passing test cases | Failure marks | Test log |
| --- | ---: | ---: | --- |
| `tests/unit` | **440** | 0 | `/tmp/ap-gateway-unit-suite.log` |
| `tests/security` | **335** | 0 | `/tmp/ap-gateway-security-suite.log` |
| `tests/integration` | **130** | 0 | `/tmp/ap-gateway-integration-suite.log` |
| `tests/contract tests/load` | **11** | 0 | `/tmp/ap-gateway-contract-load-suite.log` |
| New post-suite release-contract checks | **4** | 0 | `/tmp/ap-gateway-release-assertions.log` |

Total: **920 passing checks** across the sets above, including the new release-contract tests. The 4 new structural tests were added after the initial unit-suite run, so they are listed separately rather than counted twice.

An earlier combined full-suite invocation was interrupted after four now-resolved failures. Running each test directory separately on its own disposable SQLite database produced the passing results above. This avoids global-DB pollution and does not claim an uninterrupted combined run.

## Static and packaging checks

- `ruff check apps packages connectors integrations tests ...` — PASS.
- `mypy apps packages connectors integrations` — PASS, **139 source files**.
- Python internal Guard and Gateway compilation — PASS.
- `docker build -f apps/gateway/Dockerfile ...` — PASS using the current Gateway-only code.
- Executing Gateway entrypoint import inside the built nonroot image — PASS.
- Building synthetic-version Guard customer archive — PASS. Extracted import and SHA-256 manifest verification — PASS. Checked that archived package contains neither `rag_sdk` nor `rag_core`; disposable release artifacts removed.
- TypeScript typecheck, frontend ESLint and production Next.js build — PASS.
- Desktop Playwright and mobile Playwright run prior to the final source selector/read-only polish — desktop **14 pass, 3 intentional skips**, mobile **15 pass, 2 intentional skips**.
- Final desktop and mobile browser suite after all Gateway UI changes: 31 passed, 5 intentionally skipped, 0 failed. Evidence is recorded in /tmp/ap-gateway-all-browser-final2.log.

## Enterprise release gates still open

1. **Real Google Workspace/Drive customer tenant validation:** verified admin OAuth consent, provider-stable employee/group IDs, nested membership, effective inherited/shared-drive/limited-folder permissions and independent access checks.
2. **Measured revocation SLO:** real provider permission revoke to Guard denial, p50/p95/p99 under reasonable load and outages; tests do not establish instantaneous propagation.
3. **Actual customer RAG enforcement:** employee identity, trusted ingestion attestations, retrieval-to-model Layer 1, cached output and complete Layer 2 provenance; prove model tools and direct egress cannot bypass the agreed protected path.
4. **Operational readiness:** staging release, full migration/rollback and backup/restore exercises, credential rotation, incident drill, load performance, monitoring and external security review.
5. **GitHub CI:** Workflow in `.github/workflows/ci.yml` remains local and must be added after authorization grants the GitHub `workflow` scope. Until then, the GitHub PR itself has no hosted build evidence.

**No production deployment, real customer credentials, destructive database operation, or live enterprise certification was performed as part of this migration.** The PR remains draft until external release gates are met.
