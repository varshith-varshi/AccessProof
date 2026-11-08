# Infrastructure status

Last verified 2026-11-08T08:35Z. Identities used: `accessproof-certifier` (read-only SSM document) and `accessproof-infra-scoped` (Describe APIs). The root profile was not used.

| ID | Component | Status | Evidence | Verified |
|---|---|---|---|---|
| INF-01 | Public API `https://api.accessproof.in/health/ready` | VERIFIED_LIVE (HTTP 200, TLS valid) | curl | 08:35Z |
| INF-02 | Dashboard `https://app.accessproof.in/login` | VERIFIED_LIVE (HTTP 200, TLS valid) | curl | 08:35Z |
| INF-03 | Production web release | DEPLOYED `web-r44-challenge-0788ca3a1bc0`, Gateway ZIP `bab5f15f…` | 2026-11-05 deploy record; **not re-verified today** (needs deployer `--preflight`) | 2026-11-05 |
| INF-04 | Production EC2 `i-0c11427d4d9c1b438` (t3.small), no EIP | DEPLOYED; EIP pending owner approval (F-005) | handoff doc | 2026-11-05 |
| INF-05 | Independent certifier EC2 `i-0af8a03948e7ba058` | VERIFIED_LIVE: running, system/instance checks ok, SSM Online | `describe-instance-status`, `describe-instance-information` | 08:3xZ |
| INF-06 | KMS key `0f040c1c-afc8-4227-9f9f-18aa014c5f10` | VERIFIED_LIVE: Enabled, ECC_NIST_EDWARDS25519, SIGN_VERIFY. Not trusted; Sign denied | `kms describe-key` | 08:3xZ |
| INF-07 | Two failed-stack KMS keys | PendingDeletion, scheduled 2026-11-15 | rollout doc | 2026-11-08 |
| INF-08 | Certifier laptop timers, tunnel, employee sessions | active; sessions near end (F-001) | systemctl, ps | 08:30Z |
| INF-09 | DB revision / RLS runtime role | NOT_VERIFIED today (gate I needs an in-container run) | — | 2026-11-05 |
| INF-10 | Backups and restore | NOT_VERIFIED (F-007) | — | — |
| INF-11 | Monitoring and alarms | Partial: local user-systemd watchdogs with desktop notification, plus the EC2 status watcher. No paging to an off-laptop channel | unit files | 08:30Z |
| INF-12 | Disk headroom on production | NOT_VERIFIED; 8 GB free at R44 equals the release minimum (F-006) | — | 2026-11-05 |

## Ongoing cost items (independent certifier)
NAT Gateway, EIP for NAT, t3.small EC2, 30 GB encrypted EBS, KMS key. No new resources were created this session.

## Laptop-independence
Not achieved. See FINDINGS F-002 for the five prerequisites.
