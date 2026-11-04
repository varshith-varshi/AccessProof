# Production release report: r37 (2026-11-04)

**Deployed:** `r37-universal-47cf857-47cf85792db9`, release commit `47cf85792db9c3ade4b7883f3c6c8020be152cff`, branch `claude/universal-rag`.
**Verified running:** api, web and worker images `r37-universal-47cf857-47cf85792db9`, all healthy. The database is unchanged at `w7a8b9c0d1e2` (no migrations). The restricted DB roles are preserved (api `accessproof_app`, worker `accessproof_rls_admin`). The r35 rollback is retained.
**Protect:** OFF. Gate J needs the owner's approval.

| Item | Result | Evidence |
|---|---|---|
| Production deployment | **Deployed and verified** (deploy script verification, an independent image check, and gates before and after) | `docs/evidence/production-r37-2026-11-04/deploy-r37.log`, `gates-*.json` |
| 100-minute endurance test | **PASS**: 12/12 scenarios, 23 refresh cycles, Bob's finance requests reached the model 0 times in 91 samples. One defect was fixed (`388238b`) and its scenario reran. | `docs/evidence/evidence-refresh-2026-11-04/` |
| SQLite regressions | **PASS**: 1638 tests, 0 failures, 0 errors | `.../evidence-refresh-2026-11-04/regressions.json` |
| PostgreSQL regressions | **PASS**: 1638 tests, 0 failures, 0 errors (least-privilege roles) | same |
| LangChain certification (subscription) | **PASS 14/14**: before deploy, and again after deploy against the r37 control plane | `.../production-r37-2026-11-04/remote-route-certification-langchain-post-deploy.json` |
| LlamaIndex certification (subscription) | **PASS 14/14**: before and after deploy | `...-llamaindex-post-deploy.json` |
| SharePoint live validation | **PASS**: effective permissions, group and inherited grants, revoke and restore, modification and deletion (soak). Production certificate renewed from fresh evidence. | `.../certificate-renewal-30day/` |
| Layer 1 authorization | **PASS** | renewal `layer1.json`, `rag-e2e.json`; route certifications |
| Layer 2 authorization | **PASS**, including the mid-request block during a live revocation | `revocation-A-route.json`; MIDREQUEST checks |
| Continuous evidence refresh | **PASS**: refresh, signed distribution, sequence and rollback checks, expiry fail-closed, outage and restart recovery | soak evidence |
| Gateway and Guard | **PASS**: TLS, signed requests, signed hash-chained audit matched to Guard audits, fail-closed, no bypass routes | route certifications, `gateway-signed-audit.jsonl` |
| Tenant isolation | **PASS** (application, source and manifest binding; regression sweep) | certifications, soak `cross_tenant` |
| Production gates A–I | **PASS** after deploy and with the new certificate | `gates-after-30day-certificate.json` |
| Source certificate | **Production-enforced**: 30-day validity accepted by r37, expires **2026-12-04 15:38:15 UTC** | renewal log |
| D-31 revision churn | **Fixed in production**: revision 997 stable for over 10 minutes (r35 churned every 1–2 minutes) | `d31-revision-stability-10min.txt` |
| Remote route certificate enforcement | **NOT DEPLOYED**: lab-signed only; the control plane does not import or enforce it | — |
| Protect activation | **OFF** | Gate J |

**Status of each layer:**
* **Implemented, locally tested and lab-certified:** remote Gateway exposure, signed audit, client and adapters, continuous refresh, remote route certification.
* **Production deployed:** the control plane (D-31 fix, 30-day certificates, owner-only certificate revoke). These Gateway features ship in the release but are off by default.
* **Production validated:** the SharePoint pipeline, Layer 1 and Layer 2, certificate import and the gates, all on r37.
* **Production certified:** the source certificate only.

**Remaining blockers:**
1. Protect activation needs the owner's approval (Gate J).
2. Remote route certificates are lab-signed and not enforced by the control plane.
3. Windows is NOT TESTED.
4. Physical cross-host is BLOCKED: the tunnel to the staging host was refused and needs approval.
5. The customer onboarding flow (Phase 7) was covered by regression tests only, not run live with a new tenant.
6. The automatic certificate-renewal timer is written but not installed (`deploy/certifier/`), because installation was blocked. Note that the renewal tooling lives on `claude/realtime-authz`.

**Rollback:** run `deploy/ec2-release/rollback_on_ec2.sh` via SSM to return to `r35-realtime-authz-a2f597312547`. The database needs no rollback because there is no schema change.
