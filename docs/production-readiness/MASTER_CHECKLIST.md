# Master production-readiness checklist

Last updated 2026-11-08T08:35Z. Details are in the sibling reports. "Last PASS" dates come from earlier dated evidence when this session could not re-run the check.

| ID | Group | Requirement | Pri | Status | Evidence | Verified | Remaining dependency | Verdict |
|---|---|---|---|---|---|---|---|---|
| A | Infrastructure | API, web, DB and Redis healthy; release pinned | P0 | VERIFIED_LIVE (public health); release NOT re-verified | INFRASTRUCTURE_STATUS | 08:35Z | deployer `--preflight` | PARTIAL |
| B | Identity | Entra OIDC verification, employee identity binding | P0 | Last PASS 2026-11-05 | gates run 11-05 | 11-05 | gate re-run | NOT_VERIFIED |
| C | SharePoint source | Source certified for exact scope | P0 | CERTIFIED, 26 d left | `source_expiry_monitor` live | 08:3xZ | renewal ~11-24 needs sessions | PASS |
| D | Guard | Guard reachable, fail-closed | P0 | VERIFIED_LIVE via route attestation 05:31Z | attestation log | 05:31Z | — | PASS (attestation scope) |
| E | Gateway / routes | Certified routes VALID | **P0** | VALID, **expire 2026-11-11** | `route_status` live | 08:30Z | **F-001 owner action** | AT RISK |
| F | Layer 1 | Retrieval filtered per employee | P0 | Last PASS in route certs 11-05 | route certs | 11-05 | gate re-run | NOT_VERIFIED today |
| G | Final answer verification | Provenance and release gate | P0 | Last PASS 11-05 | gates | 11-05 | gate re-run | NOT_VERIFIED today |
| H | Revocation and cache | In-flight revocation; no cross-employee cache reuse | P0 | TESTED_LOCAL; live in route cert 11-05 | tests + certs | 08:35Z (tests) | gate re-run | NOT_VERIFIED live today |
| I | Database security | RLS runtime role, tenant isolation | P0 | Last PASS 11-05 | gates | 11-05 | in-container run | NOT_VERIFIED |
| J | Activation | Owner approval recorded; Protect active | P0 | Approved 11-05; mode not visible to certifier | evidence dir | 11-05 | Owner dashboard confirm | NOT_VERIFIED today |
| R1 | Reliability | Laptop-independent renewal | P0 (GA) | BLOCKED | F-002 | 08:3xZ | owner + customer authorizations | BLOCKED |
| R2 | Reliability | Backup restore drill with RTO/RPO | P1 | NOT_VERIFIED | — | — | isolated restore | OPEN |
| R3 | Reliability | Rollback tested | P1 | Web-only release has preflight and previous digest accepted; no rollback drill recorded | deployer | 11-05 | drill | OPEN |
| R4 | Reliability | Off-laptop alerting | P1 | Local desktop only; EC2 watcher observes | — | — | alarm channel | OPEN |
| S1 | Security | Unit + security suite green | P0 | TESTED_LOCAL 1630/9 skip/0 fail | SECURITY_TEST_RESULTS | 08:35Z | — | PASS |
| S2 | Security | Mixed allow/deny partial answers (`15b870a`) live | P1 | IMPLEMENTED + TESTED_LOCAL, not deployed | — | — | release + live verification | OPEN |
| S3 | Security | Cross-tenant live test | P1 | NOT_VERIFIED (one real tenant) | — | — | second tenant | OPEN |
| G1 | Governance | No root use; MFA on admins | P1 | Root keys exist; MFA missing on infra-admin | F-004 | 11-08 | owner | OPEN |
| O1 | Onboarding | Fresh real customer journey | P0 (GA) | Partial | CUSTOMER_ONBOARDING_STATUS | — | real tenant consent + owner approval | OPEN |

## Commands for gate re-run (owner or deployer; not runnable by the certifier identity)
Run inside the production API container:
`python scripts/production_security_gates.py --organization-id <org> --application-id <app> --stdin-bundle < bundle.json`
Run it for both `48ee8c86…/sharepoint-rag-staging` and `0fb98b25…/pilot-hr-rag`. Exit 0 means TECHNICAL_GATES_PASSED_PENDING_REVIEWER_APPROVAL.
