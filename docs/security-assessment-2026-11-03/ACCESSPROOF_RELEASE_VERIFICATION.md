# AccessProof release verification — 2026-11-03 (updated 13:25 UTC)

## Production: r23 DEPLOYED and verified; SharePoint Protect NOT VERIFIED
The release is running and checked. That does **not** change the security
verdict, which stays **SHAREPOINT PRODUCTION PROTECT — NOT VERIFIED** (see
`ACCESSPROOF_FINAL_SECURITY_ASSESSMENT.md`).

| Item | Value |
|---|---|
| Previous release | `r22-least-privilege-e76a89a87267`, deployed by the operator's ChatGPT session (SSM `5eb1e3a0-…`, DB `u5e6f7a8b9c0`) |
| Current release | `r23-rt-fixes-400c73ebb7be` |
| Source commit | `400c73ebb7be1c22600d7c76dadf0386d5258807` (= `87e6a83` application code + release-tooling fixes) |
| Artifact sha256 | `35f90f3f37dce58c2308023de025df47e20c698a305d0ba16e8571586786636c` (identical to the rehearsed r23d) |
| Deploy | SSM `db1329c5-fcda-40d6-920d-b317c62fbf8d`, 13:14:49 → 13:17:50 UTC, "DEPLOYMENT VERIFIED" |
| DB revision | `v6f7a8b9c0d1`; `mfa_methods.last_totp_step` present; pre-deploy dump verified (78 table-data entries) |
| Independent check | SSM `1bd98b52-…`: api/worker/web on r23; FastAPI 0.162.0, Starlette 1.10.0, cryptography 50.0.2; 0 worker errors, 0 API 5xx; data intact (3 orgs, 3 users) |
| Public | `/health/ready` 200 ready; app `/login` 200; unauthenticated `/api/v1/guards` 401 |
| DB role | **still the owner `accessproof` (superuser, BYPASSRLS).** The least-privilege switch needs separate owner approval. |

**Not verified in production:**
* RT-03 (TOTP replay) was not exercised in production; that needs a production MFA account. The same artifact rejected the replay on staging, and was shown accepting it on r22.
* RT-01 is a client-side redirect check covered by Playwright; an HTTP 200 on `/login?next=//evil` proves nothing either way.

## Rehearsal
`docs/evidence/rehearsal-2026-11-03-r23/` covers:
* staging parity with production;
* the deploy over the real SSM path;
* the least-privilege switch;
* rollback with a migration downgrade;
* a forced failure with automatic rollback;
* a redeploy under least privilege;
* lock contention.

It found two defects, both fixed before production:
* **D-14 (P1, release process):** `enable_least_privilege_db.sh` aborted on every first run. The restore worked, but the switch could never succeed in production. Fixed in `765c1b8`.
* **D-15 (P2):** `rollback_on_ec2.sh` restored the whole pre-release `.env`, silently reverting a later least-privilege switch to superuser credentials. It also never failed when the API was unhealthy. Fixed in `400c73e`.

Plus the tooling defects the r22 rollout exposed (fixed in `d5d035d`):
* the SSM wrapper used `set -o pipefail` under `/bin/sh`;
* the expected DB revision defaulted to a stale value and never reached the instance;
* the release-ID prefix was hard-coded;
* host scripts were taken from the working tree rather than the pinned commit;
* there was no release lock.

## Tests
| Check | Result |
|---|---|
| Full suite, SQLite (tree at `d5d035d`) | 1428 tests: 1418 passed, 0 failed, 10 skipped |
| Release-tooling tests (`tests/unit/test_ec2_release_ssm_wrapper.py`, at `400c73e`) | 20 passed; the D-14 test fails on the previous script |
| Staging HTTP probe, r23 under `accessproof_app` | 23/23 (login, tenant reads/writes, cross-tenant 403, BOLA 404, RT-03 replay 401) |
| PostgreSQL 17 restricted-role suite | not re-run in this session (last: 1407 passed / 4 skipped at `6aadb6a`) |

## Release notes for operators
1. **Migration** `v6f7a8b9c0d1` adds `mfa_methods.last_totp_step`. It is additive; its downgrade drops the column.
2. **Content-Type correction:** the earlier note said JSON requests "must now" carry `Content-Type: application/json`. On staging, `POST /api/v1/auth/login` without it returns 422 on **both** r22 and r23. Keep sending the header; this route's behaviour did not change. Gateway clients should send it anyway.
3. **New ship syntax:** `bash deploy/ec2-release/ship_via_ssm.sh <commit> <current-db-revision> <release-label>`. Read the current revision first with a read-only SSM check. A rehearsal against a staging instance uses `ACCESSPROOF_REHEARSAL_INSTANCE=<id>`.
4. **Customer Guard/Gateway** must be rebuilt to get the patched dependencies; the Guard tarball 0.1.5 predates them. The lab Guard and Gateway were upgraded to images built from `d5d035d`.
5. **Least-privilege switch** (needs owner approval):
   `sudo bash /home/ubuntu/accessproof-releases/r23-rt-fixes-400c73ebb7be/enable_least_privilege_db.sh r23-rt-fixes-400c73ebb7be --approve-database-role-change`

## Update 14:08 UTC — r24 deployed
| Item | Value |
|---|---|
| Release | `r24-identity-fixes-908ca7da1dc9` (commit `908ca7da1dc95e72dd39dd231ea6c8d7d96cbd9c`), artifact sha256 `217cb3087df92770cb9f48795a1a84b48dcdfd997429be2fb28d6cb34e869910` |
| Deploy | SSM `74ce96fc-34f6-4af3-8894-81cad096f7ff`, 14:05:20 → 14:07:24 UTC, DEPLOYMENT VERIFIED; rehearsed first on staging under `accessproof_app` (SSM `b198107b-…`, probe 23/23) |
| Contents | D-16 Guard identity-setting precedence; D-17 Gateway adopt-existing keeps heartbeat credential; D-18 certified Microsoft sources can satisfy `PRODUCTION_OIDC_READY`; live employee-identity tool |
| Tests | Full SQLite suite 1437 tests: 1427 passed, 0 failed, 10 skipped |
| Post-deploy | api/worker/web on r24, DB `v6f7a8b9c0d1`, 0 worker errors, 0 API 5xx; DB role still owner (`accessproof`) pending approval |
| Gates | A PASS; B–J FAIL/BLOCKED (unchanged; need live identity, pairing, certificate, DB switch) |

Tenant change (operator-approved): stale `fullcontrol` grant for first-party app "Microsoft Graph" removed from the lab site; AccessProof's own `fullcontrol` is required (GetUserEffectivePermissions needs EnumeratePermissions).
