# AccessProof implementation status

Status date: 2026-10-02

Implemented and contract-tested do not mean real-provider validated. The last
column keeps that distinction explicit.

| Feature | Implemented | Automated validation | Local E2E/runtime | Real provider |
|---|---:|---|---:|---:|
| Password signup/login/logout, verification/reset/invitations | YES | Integration + security | YES | N/A |
| TOTP MFA, recovery codes, session revocation | YES | Unit + integration | YES | N/A |
| OIDC SSO and SCIM Users/Groups | YES | Unit + integration | YES | NO |
| SAML 2.0 | NO | — | NO | NO |
| RBAC, object authorization and tenant isolation | YES | Security tests | YES | N/A |
| Scoped/hashed API keys | YES | Security + integration | YES | N/A |
| PostgreSQL RLS and transaction context reapplication | YES | Automated + live non-owner role | YES | N/A |
| AES-GCM secrets, hashed credentials/recovery material | YES | Unit + security | YES | N/A |
| AWS KMS envelope backend | YES | Contract | NO | NO |
| Revocation capability planner | YES | Unit + connector contract | YES | N/A |
| Direct revoke, group removal, link revoke, parent ACL, delete, move | YES | Unit + 120-run soak | YES | NO |
| Direct grant and group-member addition propagation | NO | Unsupported-path test | NO | NO |
| Positive/negative controls and deterministic canaries | YES | Unit + E2E | YES | N/A |
| Answer/citation/retrieval/tool leak oracle | YES | Unit + E2E | YES | N/A |
| Source ground truth and propagation timing | YES | Unit + E2E | YES | NO |
| PASS/FAIL/INCONCLUSIVE/PRECONDITION_FAILURE/ERROR/CANCELED | YES | Unit + integration | YES | N/A |
| Cleanup records, retry janitor, ambiguous-delete replay protection | YES | Unit + integration + soak | YES | NO |
| Private runner registration, heartbeat, lease/reclaim/checkpoint | YES | Integration E2E | YES | NO |
| Mutation journal and crash replay protection | YES | Integration + unit | YES | NO |
| Microsoft 365/SharePoint safe subsets | YES | Connector contract | NO | NO |
| Google Drive safe subsets | YES | Connector contract | NO | NO |
| Confluence restriction-safe subset | YES | Connector contract | NO | NO |
| Slack private-channel membership subset | YES | Connector contract | NO | NO |
| Salesforce record/share configured subset | YES | Connector contract | NO | NO |
| Generic HTTP target GET/POST and auth modes | YES | Unit + security | YES | N/A |
| SSRF/DNS-rebinding/redirect/malformed-response controls | YES | Security tests | YES | N/A |
| JSON/HTML/PDF/JUnit/SARIF reports | YES | Unit + integration E2E | YES | N/A |
| Ed25519 report signing and tamper detection | YES | Unit + integration | YES | N/A |
| Historical comparison and release decisions | YES | Unit + integration | YES | N/A |
| Signed webhook outbox/retry | YES | Unit + integration | YES | NO |
| Transactional email outbox/retry | YES | Integration | YES | NO |
| Audit, alerts, retention and deletion receipts | YES | Security + integration | YES | N/A |
| Structured logs, correlation IDs, health and metrics | YES | Integration + live stack | YES | N/A |
| OTLP exporter | YES | Local no-op/contract | NO | NO |
| CLI and CI-friendly exit semantics | YES | Unit + integration smoke | YES | N/A |
| Next.js operator UI | YES | ESLint + TypeScript + build | YES | N/A |
| Chromium browser flows | YES | Playwright 3/3 | YES | N/A |
| PostgreSQL/Redis/API/worker/web Compose stack | YES | Health/runtime smoke | YES | N/A |
| API/worker/runner/web images | YES | All build; non-root inspect | YES | N/A |
| GitHub Action and GitLab template | YES | Static/local API contract | NO | NO |
| Kubernetes/Helm | DEFERRED | — | NO | NO |

## Current validation baseline

- Python: 131/131 tests pass; Ruff, strict MyPy (67 source files), and compileall pass.
- Frontend: npm audit has zero known vulnerabilities; lint, typecheck, optimized
  Next.js build/prerender and 3 Chromium E2E tests pass.
- Database: one Alembic head; blank PostgreSQL and previous-head upgrades pass;
  live non-owner RLS tenant filtering passes.
- Docker: four images build as non-root; the full local stack is healthy.
- Demo: expected FAIL at 110 seconds against a 30-second SLO.
- Soak: 120 runs, six mutation types, zero tracked leaks and duplicate mutations.

## External work still required

Run the provider pilot matrix in dedicated Microsoft, Google, Atlassian, Slack and
Salesforce test environments, plus a real OIDC IdP, KMS key, SMTP provider, OTLP
backend and external CI repositories. Provider-specific procedures and required
evidence are documented under `docs/`.
