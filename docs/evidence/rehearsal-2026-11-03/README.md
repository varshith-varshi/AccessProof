# Production rehearsal evidence — 2026-11-03

**This is NOT production evidence.** Every file here comes from a local,
production-shaped stand-in running in a Claude Code cloud container. This
environment has no AWS credentials and no network path to the production
host (i-0c11427d4d9c1b438), so the real host was never touched.

## Stand-in
* Same `docker-compose.ec2.yml`.
* Same `/home/ubuntu/accessproof` and `/home/ubuntu/accessproof-releases` layout.
* postgres:17-alpine, redis:7-alpine, read-only API root filesystem.
* Started on release r21 (DB `r2b3c4d5e6f7`) with two seeded tenants.
* Owner accounts use a rehearsal-only password; no real customer data.

## Sequence (each step ran the real release scripts)
| # | Step | Result | File |
|---|------|--------|------|
| 1 | `deploy_on_ec2.sh` r22 (first attempt) | aborted at preflight (D-09: hex-only revision check). Fixed. | — |
| 2 | `deploy_on_ec2.sh` r22 | DEPLOYMENT VERIFIED, DB `u5e6f7a8b9c0` | `deploy-r22-*.log` |
| 3 | `enable_least_privilege_db.sh` (first attempt) | failed: API uid could not read secrets (D-10). ERR trap restored .env/compose byte-for-byte. Fixed. | — |
| 4 | `enable_least_privilege_db.sh` | ACTIVE; every role verified by connecting as it | `db-roles-verification-r22.json`, `db-runtime-audit.json` |
| 5 | HTTP probe as `accessproof_app` | 20/20 (login, reads, writes, cross-tenant 403, metrics read-only role) | `http-probe-r23.json` |
| 6 | `run_security_gates.sh` | first attempt failed: read-only rootfs (D-11). Fixed. | — |
| 7 | r23 deploy on top of least privilege | DEPLOYMENT VERIFIED. This exposed D-12: `accessproof_app` cannot run DDL, so later migrations would have failed. Fixed. | `deploy-r23-*.log` |
| 8 | Gates on r23 | NOT VERIFIED; A and I PASS live; B–H and J FAIL/BLOCKED (no real Entra/SharePoint/Guard/Gateway) | `gates-r23-least-privilege.json` |
| 9 | Forced post-switch failure (before D-13 fix) | **Outage:** password divergence locked the API out, yet the log said "RESTORE complete" | `forced-failure-before-D13-fix.log` |
| 10 | `RECOVERY=1` re-sync | recovered, passwords reused from .env | `recovery-D13.log` |
| 11 | Forced post-switch failure (after fix) | restore healthy, still `accessproof_app` | `forced-failure-restore.log` |
| 12 | `rollback_on_ec2.sh` r23 → r22 | healthy, still `accessproof_app`, probe 20/20 | `rollback-r23-to-r22.log` |

Before commit, every file was scanned for the generated role passwords,
session tokens and bearer headers. None were present.
