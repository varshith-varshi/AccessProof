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


## Continued post-refactor Gateway hardening (26 October 2026)

- Restricted plaintext Gateway-to-Guard and Gateway-to-model upstream
  destinations to validated loopback, RFC1918, IPv6 ULA and single-label Docker
  service hostnames. Public/dotted names require HTTPS; metadata, link-local,
  wildcard and special-use IPs are rejected.
- Made Guard health query optionally application-specific, and made Gateway
  readiness require its own healthy, Protect-mode application binding and ACL
  freshness instead of trusting another application's Guard health.
- New security tests exercise public vs. private transport, metadata addresses,
  missing or Shadow application binding and healthy specific bindings.
- First focused regression run: **55 passed** (new tests and related Guard,
  Gateway, unit and real TCP integration checks), zero failures. Evidence:
  `/tmp/ap-gateway-scoped-hardening.log`.
- This does not eliminate arbitrary runtime RAG bypass; customer-side Docker
  egress isolation and employee-facing cutover remain external production gates.

### Extended post-hardening release evidence

- Whole Python unit directory rerun: **444 passing**; evidence:
  /tmp/ap-gw-next-unit.log (POST_HARDEN_UNIT_EXIT:0).
- Whole Python security directory rerun after transport and app-scoped health
  checks: **373 passing**, no failures; evidence:
  /tmp/ap-gw-next-security.log (POST_HARDEN_SECURITY_EXIT:0).
- Additional production-Guard revision installation gate was added after the
  broad suite began. Its independent 48-test focused rerun passed, including
  a production case with an enrolled Guard that refuses Protect until
  authorization revisions and identity mappings are installed; evidence:
  /tmp/ap-gw-prod-revision-gate.log (PROD_REVISION_GATE_EXIT:0).
- The complete selected 55-case app-scoped health / external HTTP / real TCP
  regression also passed before the final revision rule; evidence:
  /tmp/ap-gateway-scoped-hardening.log.
- Rebuilt nonproduction Gateway image 'accessproof-gateway:scoped-ready-20261026'
  and Guard image 'accessproof-guard:revision-gated-20261026'; each built and
  passed internal application import smoke checks. Nothing was deployed to
  any live endpoint.
- New code must remain in draft review until real Google Workspace and
  end-to-end customer RAG validation complete. These tests validate local
  contracts; they do not prove enterprise revocation propagation speed.
- Final cross-component Gateway/Guard OAuth, customer RAG, route certification,
  and upstream transport test set: **64 passed**, no failures, after the
  production revision gate was installed; evidence:
  /tmp/ap-gateway-protect-routes-final.log (PROTECT_ROUTES_EXIT:0).
