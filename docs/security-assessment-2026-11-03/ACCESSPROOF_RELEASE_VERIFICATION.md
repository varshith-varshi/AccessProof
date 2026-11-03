# AccessProof release verification — 2026-11-03

## Production: NOT DEPLOYED, NOT VERIFIED
* **Last independently verified production release:** `r21-research-a08af47f53b`
  (reported in the mission brief; not re-observed from this session).
* **Why nothing was deployed:**
  * AWS STS rejects the session credentials (`InvalidClientTokenId`).
  * `api.accessproof.in` and `app.accessproof.in` are denied by the network
    policy.
  * The Part 10 preflight (exact running images, DB revision, active DB role,
    backups, disk) could not be observed. A deploy without it would break the
    mission's own rules.
* The P0-01 least-privilege database switch also requires explicit owner
  approval. It was not run.

## What is verified for the candidate release
| Check | Result | Where |
|---|---|---|
| Source commit | `6aadb6af917b` on `claude/modest-bell-tazupa` | git |
| Full suite, SQLite | 1401 passed, 0 failed, 10 skipped (1411 tests) | JUnit XML |
| Full suite, PostgreSQL 17 as `accessproof_app` | 1407 passed, 0 failed, 4 skipped (1411 tests) | JUnit XML |
| Migrations | head `v6f7a8b9c0d1`; new migration verified up/down/up on PostgreSQL 17 | this assessment |
| Dependency audit | pip-audit 0; npm prod 0 | this assessment |
| Deploy, least-privilege switch, forced failure, rollback | Rehearsed on a production-shaped stand-in (r22/r23, before this assessment's fixes) | `docs/evidence/rehearsal-2026-11-03/` |
| Web build and redirect regression | Chromium: old build reproduces RT-01; fixed build passes | `web-v2/e2e/post-auth-redirect.spec.ts` |
| Full Playwright suite (fixed build, desktop + mobile) | 85 passed, 5 skipped, 0 failed | `web-v2/e2e/` |

**Not re-rehearsed after this assessment's fixes.** The new migration
(`v6f7a8b9c0d1`) and the dependency upgrade have not been through
`deploy_on_ec2.sh` on the stand-in. Do that before production.

## Release notes for operators
1. **Database migration** `v6f7a8b9c0d1`: adds `mfa_methods.last_totp_step`.
   It's additive, and its downgrade drops the column.
2. **Dependency upgrade** to FastAPI 0.162 / Starlette 1.10 and cryptography
   50.0.2. JSON requests **must** carry `Content-Type: application/json`, or
   they get a 422. Tell customers whose RAG integrations call the Gateway
   directly.
3. **Pass the expected revision explicitly.** `deploy_on_ec2.sh` defaults
   `EXPECTED_DB_REVISION` to `r2b3c4d5e6f7`. Pass the live value (for example
   `u5e6f7a8b9c0` if r22/r23 was ever deployed).
4. **Rebuild customer Guard/Gateway images** to inherit the patched
   dependencies. Guard tarball 0.1.5 predates the upgrade.
5. **Least-privilege switch.** `enable_least_privilege_db.sh` now checks that
   the RLS policies exist (at least 58) rather than a revision list. It still
   requires `--approve-database-role-change`.

## Exact operator sequence
```bash
bash deploy/ec2-release/ship_via_ssm.sh
```
Then, on the host, with owner approval:
```bash
sudo bash /home/ubuntu/accessproof-releases/<release>/enable_least_privilege_db.sh <release> --approve-database-role-change
```
Then:
```bash
sudo bash /home/ubuntu/accessproof-releases/<release>/run_security_gates.sh <org-id> <application-id> [evidence.json]
```
