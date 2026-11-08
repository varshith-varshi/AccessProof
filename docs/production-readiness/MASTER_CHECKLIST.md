# Master production-readiness checklist

Last updated 2026-11-08T13:42Z. Details are in the sibling reports. "Last PASS" dates come from earlier dated evidence when this session could not re-run the check.

| ID | Group | Requirement | Pri | Status | Evidence | Verified | Remaining dependency | Verdict |
|---|---|---|---|---|---|---|---|---|
| A | Infrastructure | API, web, DB and Redis healthy; release pinned; migration at head | P0 | Live Gate A PASS both reference and pilot: host facts (API/worker/DB/Redis/web, migration, rollback); production release pinned R54 | `evidence/gates_live_20261108.json` | 12:16Z | — | PASS |
| B | Identity | Entra OIDC verification, employee identity binding | P0 | Live Gates B PASS both reference and pilot: verified employee mappings and tenant binding | `evidence/gates_live_20261108.json` | 12:16Z | — | PASS (existing apps) |
| C | SharePoint source | Source certified for exact scope | P0 | VERIFIED_LIVE Gate C PASS for both apps with original evidence matching each CURRENT source certificate digest; no certificate issued. | `evidence/gates_live_with_evidence_20261108.json` | ~12:4xZ | source renewal ~11-24 still laptop-dependent | PASS |
| D | Guard | Guard reachable, fail-closed | P0 | Pilot Guard was failing closed (POLICY_SYNC_STALE, F-011), restarted, healthy; both Guards ready; watchdog now alerts on Guard readiness | /health, watchdog | 10:02Z | off-laptop alerting (R4) | PASS |
| E | Gateway / routes | Certified routes VALID | **P0** | Pilot application route recertification succeeded with fresh Guard-audited challenge and employee cutover, then Gate E PASS. Reference Gateway remains DISCONNECTED / heartbeat expired and application certificate expired. | `evidence/pilot_10of10_live_20261108.json` | 13:22Z | reference needs fresh authorized Gateway pairing/presence and controlled route challenge | PILOT PASS; REFERENCE FAIL |
| F | Layer 1 | Retrieval filtered per employee | P0 | VERIFIED_LIVE in today's 3 route certifications | route certs | 10:00Z | — | PASS (route scope) |
| G | Final answer verification | Provenance and release gate | P0 | VERIFIED_LIVE Gate G PASS for both apps: observed releases plus original certificate-digest-matching in-flight/tamper evidence. | `evidence/gates_live_with_evidence_20261108.json` | ~12:4xZ | — | PASS (existing apps) |
| H | Revocation and cache | In-flight revocation; no cross-employee cache reuse | P0 | VERIFIED_LIVE Gate H PASS both apps using original certificate-digest-matching revocation/restoration/cache evidence. | `evidence/gates_live_with_evidence_20261108.json` | ~12:4xZ | — | PASS (existing apps) |
| I | Database security | RLS runtime role, tenant isolation | P0 | Live Gate I PASS both apps: non-superuser accessproof_app, NOBYPASSRLS, none of 59 tenant tables unprotected; local two-tenant PG17 restore drill previously passed | `evidence/gates_live_20261108.json` | 12:16Z | production-data restoration still separately pending | PASS (live roles/RLS) |
| J | Activation | Owner approval recorded; Protect active | P0 | Gate J PASS pilot, FAIL reference because its Gateway authenticated heartbeat/enforcement readiness is missing. | `evidence/gates_live_with_evidence_20261108.json` | ~12:4xZ | reference authorized Gateway pairing | PARTIAL |
| R1 | Reliability | Laptop-independent renewal | P0 (GA) | BLOCKED. The owner window for route renewal is reduced from about 46 h to about 1 h (F-001b) | F-002 | 09:10Z | owner + customer authorizations | BLOCKED |
| R2 | Reliability | Backup restore drill with RTO/RPO | P1 | Restore path TESTED_LOCAL (dump 0.31 s, restore 7.3 s, at synthetic scale); production data NOT_VERIFIED; no backup schedule found | drill evidence | 09:05Z | owner-approved production drill; targets | OPEN |
| R3 | Reliability | Rollback tested | P1 | Web-only release keeps the previous digest; no rollback drill recorded | deployer | 11-07 | drill | OPEN |
| R4 | Reliability | Off-laptop alerting | P1 | PARTIAL: independent EC2 status watcher v2 VERIFIED_LIVE for both organizations (2 source certificates, 3 routes); no external operator paging. | evidence/independent_status_v2_20261108.json | 11:16Z | approved alert channel | OPEN |
| S1 | Security | Unit + security suite green | P0 | TESTED_LOCAL (see SECURITY_TEST_RESULTS) | pytest | 09:1xZ | — | PASS |
| S2 | Security | Mixed allow/deny partial answers | P1 | DEPLOYED (Gateway code unchanged since `501a74c`) + TESTED_LOCAL; live NOT_VERIFIED | `test_gateway_partial_cached_context.py` | 09:1xZ | live observation | OPEN |
| S3 | Security | Cross-tenant live test | P1 | NOT_VERIFIED live (one real tenant); DB-level cross-tenant isolation TESTED_LOCAL | drill | 09:05Z | second tenant | OPEN |
| G1 | Governance | Root keys/MFA and administrator MFA | P1 | VERIFIED_LIVE: account root has zero access keys, root MFA enabled. Infra-admin has no enrolled MFA. The root connector was used only for a temporary, revoked, least-privilege Gates registrar grant. | AWS IAM account summary / ListMFADevices / F-017 | 12:16Z | owner enroll infra-admin MFA | PARTIAL |
| O1 | Onboarding | Fresh real customer journey | P0 (GA) | Partial | CUSTOMER_ONBOARDING_STATUS | — | real tenant consent + owner approval | OPEN |

## Latest verified pilot production gates

2026-11-08 13:22Z: `pilot-hr-rag` passed **10/10 live technical A–J gates** after an Owner-controlled, signed-Guard-audited route recertification and successful employee cutover. Evidence: `evidence/pilot_10of10_live_20261108.json`, SSM `6e4182cf-4758-4c37-a67b-0322902b69b5`. The synthetic SharePoint grant was restored. These checks do not replace reviewer approval or certify new organizations.

## Gate re-run
Registration COMPLETE on 2026-11-08 with a temporary root-granted registrar policy removed afterward. Both live gate commands were executed and returned NO-GO. Re-run after resolving Gate E and supplying matching signed source evidence:
```
deploy/deployer/ship_production.sh --gates 48ee8c86-d4d8-4cde-b00b-bc779f965f4f sharepoint-rag-staging
deploy/deployer/ship_production.sh --gates 0fb98b25-bd7d-445e-a192-4ff8ee730760 pilot-hr-rag
```
The earlier 2026-11-08 executions returned technical NO-GO, but the pilot was rerun after recertification and achieved 10/10 technical PASS. The reference has not passed; neither application is authorized for GA solely by these technical results. Exit 0 on future passes means TECHNICAL_GATES_PASSED_PENDING_REVIEWER_APPROVAL, and reviewer approval is still required.
