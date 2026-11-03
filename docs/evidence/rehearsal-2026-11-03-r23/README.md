# r23 release rehearsal — 2026-11-03

**Not production evidence.** Staging instance `i-0e6d2256a1e5a6f67` (t3.small,
same AMI and SSM instance profile as production, own security group with no
inbound rules), account 102076848988, eu-north-1. Synthetic secrets and two
synthetic tenants only; no production data was copied.

## Baseline parity with production
* `docker-compose.ec2.yml` reconstructed from production; its sha256 prefix
  `f974984aa0700502` matches production byte for byte.
* Source `e76a89a` (r22), images tagged `r22-least-privilege-e76a89a87267`,
  DB `u5e6f7a8b9c0`, API on the owner role — the same state production is in.
* Difference: no nginx/TLS (deploy never touches it; public checks disabled
  in rehearsal mode).

## Sequence (real release scripts, real SSM path)
| # | Step | Result | File |
|---|---|---|---|
| 0 | `ship_via_ssm.sh d5d035d u5e6f7a8b9c0 r23-rt-fixes` (rehearsal mode) | DEPLOYMENT VERIFIED, DB `v6f7a8b9c0d1`; POSIX wrapper ran under /bin/sh | `00-*` |
| 1 | Probe on r22 baseline | 22/23; **RT-03 replay accepted (200/200)** — confirms the live defect | `01-*` |
| 2 | Probe after upgrade | 23/23; RT-03 replay rejected (200/401) | `02-*` |
| 3 | `enable_least_privilege_db.sh` (first attempt) | **failed at line 94 (D-14)**; restore healthy on owner credentials | — |
| 4 | D-14 fixed (`765c1b8`), shipped as r23b, switch re-run | ACTIVE: api=`accessproof_app`, worker=`accessproof_rls_admin`; audit non-superuser, NOBYPASSRLS, 58 tables | `03-*` |
| 5 | D-15 fixed (`400c73e`), shipped as r23c under least privilege | DEPLOYMENT VERIFIED; probe 23/23 as `accessproof_app` | `04-*` |
| 6 | `rollback_on_ec2.sh` r23 → r22 (migration downgrade) | r22 healthy, DB `u5e6f7a8b9c0`, **roles preserved** | `04-*` |
| 7 | Forced failure after migration (injected `false`) | auto-rollback: downgrade to `u5e6f7a8b9c0`, r22 healthy, `accessproof_app` kept | `05-*` |
| 8 | `ship_via_ssm.sh 400c73e u5e6f7a8b9c0 r23d-rt-fixes` under least privilege | DEPLOYMENT VERIFIED; probe 23/23; RT-03 rejected | `06-*` |
| 9 | Release lock | rollback and LP switch both exit 75 while the lock is held | below |

Lock test output (SSM `8793bbc5-e405-4f04-8f1f-834a78ed3143`):
```
rollback while locked exit=75
another release operation holds the host release lock: holder pid=24599 test-holder
LP switch while locked exit=75
```

## Observations
* RT-04: `POST /api/v1/auth/login` with a JSON body and no `Content-Type`
  returns 422 on **both** r22 and r23. The release note claiming a new
  requirement is not supported for this route.
* An earlier rehearsal output in this session displayed an `accessproof_app`
  audit that came from the committed 2026-11-03 rehearsal evidence inside the
  extracted source tree, not from the run. It is not used here; every audit
  above is read from `$REL/deployment-logs/db-runtime-audit.json`.
