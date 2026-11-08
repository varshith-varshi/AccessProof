# Master production-readiness checklist

Last updated 2026-11-08T10:05Z. Details are in the sibling reports. "Last PASS" dates come from earlier dated evidence when this session could not re-run the check.

| ID | Group | Requirement | Pri | Status | Evidence | Verified | Remaining dependency | Verdict |
|---|---|---|---|---|---|---|---|---|
| A | Infrastructure | API, web, DB and Redis healthy; release pinned; migration at head | P0 | VERIFIED_LIVE: `web-r54-tls-doctor-501a74cdb9a2`; 5 services up (api/db/redis/web healthy); DB `x8c9d0e1f2a3` = repo head; ZIP `9db1c5a9…`; disk 9 GB | deployer `--preflight` SSM `75149f4e…`; public `/health/ready` 200 | 08:58Z | — | PASS (host facts); formal gate A via F-003 |
| B | Identity | Entra OIDC verification, employee identity binding | P0 | Last PASS 2026-11-05; live Entra tokens verified (`VERIFIED alice/bob` oid/tid/iss) | gates 11-05; session logs | 11-05 | F-003 | NOT_VERIFIED (gate) |
| C | SharePoint source | Source certified for exact scope | P0 | CERTIFIED, about 27 d left (expires 2026-12-04) | `source_expiry_monitor` LIVE_READ_ONLY | 08:3xZ | renewal ~11-24 needs sessions | PASS |
| D | Guard | Guard reachable, fail-closed | P0 | Pilot Guard was failing closed (POLICY_SYNC_STALE, F-011), restarted, healthy; both Guards ready; watchdog now alerts on Guard readiness | /health, watchdog | 10:02Z | off-laptop alerting (R4) | PASS |
| E | Gateway / routes | Certified routes VALID | **P0** | CERTIFIED + VERIFIED_LIVE: VALID ×3, renewed 14/14, expire 2026-11-15 09:25–10:00Z | `route_status` read-only SSM | 10:01Z | next renewal ~11-11 (one sign-in) | PASS |
| F | Layer 1 | Retrieval filtered per employee | P0 | VERIFIED_LIVE in today's 3 route certifications | route certs | 10:00Z | — | PASS (route scope) |
| G | Final answer verification | Provenance and release gate | P0 | Last PASS 11-05 | gates | 11-05 | F-003 | NOT_VERIFIED today |
| H | Revocation and cache | In-flight revocation; no cross-employee cache reuse | P0 | VERIFIED_LIVE today: MIDREQUEST blocked with AUTHORIZATION_REVISION_CHANGED, revoked doc denied, cache replay prevented, SharePoint restored | route certs | 10:00Z | — | PASS (route scope) |
| I | Database security | RLS runtime role, tenant isolation | P0 | **TESTED_LOCAL on real PG 17** (two tenants, 50 tables, read/write/insert/GUC bypass, before and after restore; negative control fails as expected); live gate last PASS 11-05 | `evidence/postgres_isolation_restore_drill_2026-11-08.json` | 09:05Z | F-003 for live | PARTIAL |
| J | Activation | Owner approval recorded; Protect active | P0 | Approved 11-05; mode not visible to certifier | evidence dir | 11-05 | Owner dashboard confirm / F-003 | NOT_VERIFIED today |
| R1 | Reliability | Laptop-independent renewal | P0 (GA) | BLOCKED. The owner window for route renewal is reduced from about 46 h to about 1 h (F-001b) | F-002 | 09:10Z | owner + customer authorizations | BLOCKED |
| R2 | Reliability | Backup restore drill with RTO/RPO | P1 | Restore path TESTED_LOCAL (dump 0.31 s, restore 7.3 s, at synthetic scale); production data NOT_VERIFIED; no backup schedule found | drill evidence | 09:05Z | owner-approved production drill; targets | OPEN |
| R3 | Reliability | Rollback tested | P1 | Web-only release keeps the previous digest; no rollback drill recorded | deployer | 11-07 | drill | OPEN |
| R4 | Reliability | Off-laptop alerting | P1 | Local desktop only; EC2 watcher observes | — | — | alarm channel | OPEN |
| S1 | Security | Unit + security suite green | P0 | TESTED_LOCAL (see SECURITY_TEST_RESULTS) | pytest | 09:1xZ | — | PASS |
| S2 | Security | Mixed allow/deny partial answers | P1 | DEPLOYED (Gateway code unchanged since `501a74c`) + TESTED_LOCAL; live NOT_VERIFIED | `test_gateway_partial_cached_context.py` | 09:1xZ | live observation | OPEN |
| S3 | Security | Cross-tenant live test | P1 | NOT_VERIFIED live (one real tenant); DB-level cross-tenant isolation TESTED_LOCAL | drill | 09:05Z | second tenant | OPEN |
| G1 | Governance | No root use; MFA on admins | P1 | Root keys exist; MFA missing on infra-admin; root NOT used this session | F-004 | 11-08 | owner | OPEN |
| O1 | Onboarding | Fresh real customer journey | P0 (GA) | Partial | CUSTOMER_ONBOARDING_STATUS | — | real tenant consent + owner approval | OPEN |

## Gate re-run
After the owner runs `deploy/deployer/register_gates_document.sh` once:
```
deploy/deployer/ship_production.sh --gates 48ee8c86-d4d8-4cde-b00b-bc779f965f4f sharepoint-rag-staging
deploy/deployer/ship_production.sh --gates 0fb98b25-bd7d-445e-a192-4ff8ee730760 pilot-hr-rag
```
Exit 0 means TECHNICAL_GATES_PASSED_PENDING_REVIEWER_APPROVAL. Reviewer approval is still required.
