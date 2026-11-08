# Infrastructure status

Last verified 2026-11-08T10:56Z. Identities used: `accessproof-certifier` (read-only SSM document), `accessproof-infra-scoped` (Describe APIs), and `accessproof-production-deployer` for `--preflight` only, which cannot modify production. The root profile was not used.

| ID | Component | Status | Evidence | Verified |
|---|---|---|---|---|
| INF-01 | Public API `https://api.accessproof.in/health/ready` | VERIFIED_LIVE (HTTP 200, `database: ok`, `redis: ok`) | curl | 10:56Z |
| INF-02 | Dashboard `https://app.accessproof.in/login` | VERIFIED_LIVE (HTTP 200) | curl | 10:56Z |
| INF-03 | Production web release | VERIFIED_LIVE `web-r54-tls-doctor-501a74cdb9a2`. Served Gateway ZIP `9db1c5a9…` equals the R54 record and the `GATEWAY_ZIP_SHA` pin. Services: api healthy (up 30 h), db healthy, redis healthy, web healthy (up 18 h), worker up, nginx up. Earlier reports' R44 was wrong (F-008) | deployer `--preflight` SSM `37328ffe-5e8c-4cbb-b79b-d511d7b29f62` | 10:56Z |
| INF-04 | Production EC2 `i-0c11427d4d9c1b438` (t3.small), no EIP | DEPLOYED; EIP pending owner approval (F-005) | handoff doc | 2026-11-05 |
| INF-05 | Independent certifier EC2 `i-0af8a03948e7ba058` | VERIFIED_LIVE: running, system/instance checks ok, SSM Online | `describe-instance-status`, `describe-instance-information` | 08:3xZ |
| INF-06 | KMS key `0f040c1c-afc8-4227-9f9f-18aa014c5f10` | VERIFIED_LIVE: Enabled, ECC_NIST_EDWARDS25519, SIGN_VERIFY, allows `ED25519_SHA_512`. Not trusted; Sign denied | `kms describe-key`, `get-public-key` via infra-scoped read identity | 10:56Z |
| INF-07 | Two failed-stack KMS keys | PendingDeletion, scheduled 2026-11-15 | rollout doc | 2026-11-08 |
| INF-08 | Certifier laptop timers, tunnel, employee sessions | active; sessions near end (F-001) | systemctl, ps | 08:30Z |
| INF-09 | DB revision / RLS runtime role | Revision VERIFIED_LIVE `x8c9d0e1f2a3` = repo head. RLS runtime role: live gate I NOT_VERIFIED today (F-003); real-PostgreSQL isolation TESTED_LOCAL (F-009) | preflight; drill | 08:58Z |
| INF-10 | Backups and restore | Restore path TESTED_LOCAL (PG 17, 7.3 s restore at synthetic scale). Production backup schedule not found in repo, so RPO NOT_VERIFIED (F-007) | drill evidence | 09:05Z |
| INF-11 | Monitoring and alarms | VERIFIED_LIVE 2026-11-08: independent EC2 hourly read-only watcher v2 covers reference + pilot source certification and all three valid routes. No signing/import/renewal rights. No external paging channel yet; monitoring is not renewal. | SSM install 91d9ff06; evidence/independent_status_v2_20261108.json | 11:16Z |
| INF-12 | Disk headroom on production | VERIFIED_LIVE 9 GB free (threshold 8 GB; about 1 release) (F-006) | preflight | 08:58Z |

## Ongoing cost items (independent certifier)
NAT Gateway, EIP for NAT, t3.small EC2, 30 GB encrypted EBS, KMS key. No new AWS resources were created this session. A local disposable Postgres drill container (`ap-drill-pg`, network `ap-drill-net`) was used and then removed.

## Laptop-independence
Not achieved. See FINDINGS F-002 for the five prerequisites.
