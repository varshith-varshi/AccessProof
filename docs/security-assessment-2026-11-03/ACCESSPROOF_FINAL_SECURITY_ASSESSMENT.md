# SHAREPOINT PRODUCTION PROTECT — NOT VERIFIED

**AccessProof final security assessment — 2026-11-03** · commit `{{COMMIT}}`

The supported production RAG pipeline has **not** been proven to enforce
SharePoint authorization in production. This assessment had no access to
production or to the Microsoft tenant, and no live evidence has been
fabricated.

What it did establish:
* The code paths behind every required control held under adversarial testing
  in isolation.
* Five new defects were found and fixed locally, one of them a P1
  dependency exposure.
* None of these fixes is deployed.

## Execution levels
| Level | Performed | Notes |
|---|---|---|
| 1. Source analysis | Yes | All components in Part 3 |
| 2. Isolated adversarial testing | Yes | Synthetic tenants, identities, keys and documents |
| Staging | No | No staging environment exists; the production-shaped stand-in was used earlier (rehearsal) |
| 3. Live production | **No** | AWS STS `InvalidClientTokenId`; production hosts and `graph.microsoft.com` denied by network policy |
| Real Microsoft identities | **No** | Alice/Bob interactive sign-in requires the operator |

## Part 13 checklist
| # | Requirement | Status | Evidence / blocker |
|---|---|---|---|
| 1 | Real Microsoft tenant connection | BLOCKED | No Graph access |
| 2 | Correct employee authentication | PASS-LOCAL / live BLOCKED | 19-test negative matrix |
| 3 | Alice/Bob identity mapping | BLOCKED | Needs real sign-in |
| 4 | Real effective SharePoint permissions | BLOCKED | Gate C; certificate absent |
| 5 | Authorized document retrieval | PASS-LOCAL / live BLOCKED | Synthetic matrix |
| 6 | Unauthorized document rejection | PASS-LOCAL / live BLOCKED | Synthetic matrix, poisoning test |
| 7 | Guard authorization readiness | BLOCKED | Gate D failed on the stand-in (no live Guard) |
| 8 | Gateway enforcement readiness | BLOCKED | Gate E |
| 9 | Layer 1 | PASS-LOCAL / live BLOCKED | Gate F |
| 10 | Layer 2 | PASS-LOCAL / live BLOCKED | Gate G |
| 11 | Real RAG positive path | BLOCKED | No live answer produced |
| 12 | Real RAG negative path | BLOCKED | No live answer produced |
| 13 | Revocation | BLOCKED | No trial; latency unmeasured |
| 14 | Restoration | BLOCKED | No trial |
| 15 | Cache and in-flight controls | PASS-LOCAL / live BLOCKED | Every cache hit is re-authorized |
| 16 | Source certificate validity | BLOCKED | No certifier key; none issued |
| 17 | PostgreSQL tenant isolation | PASS-LOCAL and rehearsal / production BLOCKED | Switch needs approval and access |
| 18 | Production deployment verification | BLOCKED | Not deployed |
| 19 | Required regression tests | {{REGRESSION_STATUS}} | SQLite {{SQLITE}}; PostgreSQL {{PG}} |
| 20 | Reviewer approval | NOT RECORDED | Human decision |

## Fixes committed in this assessment (local only, not deployed)
* **RT-01 (P2):** post-login open redirect. Reproduced in Chromium; fixed.
* **RT-02 (P2):** Guard JWKS refetch amplification. 50 forged tokens caused 50
  IdP fetches; fixed.
* **RT-03 (P3):** TOTP replay. Fixed, with migration `v6f7a8b9c0d1`.
* **RT-04 (P1):** 60 dependency advisories (starlette, cryptography, OTel,
  certifi, pillow, dnspython). pip-audit is now clean.
* **Tests added** (permanent regression suites):
  * Cross-tenant route sweep (1,088 requests).
  * Entra negative-token matrix.
  * Account attack matrix.
  * Sharing-link and guest fail-closed tests.
  * Knowledge-poisoning test.

## Remaining blockers and the exact evidence that clears each
1. **Access:** valid AWS credentials for account 102076848988, plus network
   access to `graph.microsoft.com`, `api.accessproof.in` and
   `app.accessproof.in`. Alternatively, an operator runs the steps below.
2. **Deploy:** `ship_via_ssm.sh` at commit `{{COMMIT}}`. First re-rehearse it
   on the stand-in with the new migration and dependencies.
3. **Least-privilege switch:** owner approval, then
   `enable_least_privilege_db.sh … --approve-database-role-change`. Evidence:
   `db-runtime-audit.json` showing `accessproof_app`.
4. **Tenant configuration:** an app-registration export, admin consent and
   `Sites.Selected` grants, showing the app is limited to the lab site.
5. **Alice and Bob:** interactive Entra sign-in. Evidence: VERIFIED,
   tenant-bound identity mappings and Guard audit events.
6. **Matrix:** a direct SharePoint check as each employee, then AccessProof
   Layer 1 decisions, then live protected RAG answers (6 + 6 + 11 records).
7. **Revocation tests A–G:** an authorized trial on the lab site, with the 7
   timestamps for each.
8. **Certificate:** generate the key off-host, collect the 14
   `REQUIRED_CHECKS`, then `issue_source_certificate.py issue` and `import`.
9. **Gates:** `run_security_gates.sh <org> <app> evidence.json` must report
   `TECHNICAL_GATES_PASSED_PENDING_REVIEWER_APPROVAL`.
10. **Reviewer approval,** recorded.

Only when all twenty Part 13 items are satisfied can the verdict become
**SHAREPOINT PRODUCTION PROTECT — VERIFIED**.
