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

## Update 15:27 UTC — r25 deployed (D-19 certification window)
| Item | Value |
|---|---|
| Release | `r25-cert-window-ff7656eed119` (commit `ff7656eed119ae414a8865db44fad5015e80cd51`), artifact sha256 `312153e30bd3349a86c8ac3b2d2e5f145f496be34e0b8aa92fe5e00648b77ae3` |
| Deploy | SSM `4d8f91ed-3c18-43a8-b611-824b222bee64`, 15:23:10 → 15:25:13 UTC, DEPLOYMENT VERIFIED; rehearsed on staging under `accessproof_app` (SSM `210111b8-…`, probe 23/23) |
| Contents | D-19 certification window (control plane + Guard), live test harnesses, fixture tool |
| Tests | Full SQLite suite 1455 tests: 3 failures in one test stub (missing new cache method), fixed in `ff7656e`; all others passed |
| Live check | Lab Guard (r25 image) binding: mode protect, source_acl_healthy 0, certification_window 1; `/health` ready=false; Gateway `/health/ready` 503 GUARD_NOT_READY; 0 identity mappings, so every employee request is still refused |
| DB role | still owner `accessproof`: the switch was blocked by the session's safety controls pending an explicit operator "approved" |

Lab changes: synthetic group `AP-Lab-Group-Finance-Readers` (alice), `group_finance_alice.txt`, `Inherited-Alice/inherited_finance_alice.txt` (SharePoint REST confirms the file inherits); lab sign-in app `9d031e10-4bed-4ab9-a98d-3eef237c4a56` (single-tenant public client, delegated openid/profile/offline_access/User.Read/Files.Read, admin consent); lab Guard audience = that app, subject claim `oid`, tenant pinned. The lab index sync failed closed after the fixtures were added (it required exactly 3 documents); it now accepts exactly the approved fixture set.

## Update 16:25 UTC — r26 deployed (D-20 Guard refusal semantics)
| Item | Value |
|---|---|
| Release | `r26-guard-errors-f34b033cacfe` (commit `f34b033cacfee6cf4d8f83b0e8f7367d625a7eba`), artifact sha256 `b0375aafd139c638c7fa1233b1644ccf40c9499a3a424e78356d33d5064a54d8` |
| Deploy | SSM `16f1b45c-66ec-4629-8d6e-3984b365321a`, 16:21:40 → 16:23:45 UTC, DEPLOYMENT VERIFIED; rehearsed on staging as `accessproof_app` (SSM `ff6ed560-…`, probe 23/23) |
| Tests | SQLite 1460 tests: 0 failed, 10 skipped. PostgreSQL 17 as `accessproof_app` (r25 tree): 1455 tests, 0 failed, 4 skipped |
| D-20 live | forged employee token via lab Gateway: before 503 GUARD_REQUEST_FAILED, after 401 IDENTITY_REJECTED; 0 model calls both times |
| DB role | still owner `accessproof` (switch awaits an explicit operator "approved") |

## Update 19:10 UTC — r27 and r28 deployed (automatic identity resolution, D-22, D-23)
| Release | Commit | Deploy SSM | DB | Notes |
|---|---|---|---|---|
| `r27-auto-identity-c5758058756b` | `c575805` | `9e823c69-…` | `w7a8b9c0d1e2` | automatic directory-verified identity resolution, migration w7 (rehearsed incl. rollback w7→v6f7 under `accessproof_app`) |
| `r28-revocation-delta-0357b5c6107e` | `0357b5c` | (ship 19:05Z) | `w7a8b9c0d1e2` | D-23 Graph sharing-change delta, reconciliation audit, gzip Guard envelope; rehearsed (probe 23/23) |

Tests at r28: SQLite 1492 tests, 0 failed, 10 skipped; PostgreSQL 17 as `accessproof_app` 1492 tests, 0 failed, 4 skipped.

Live (lab tenant, production control plane):
* The 18:18:33Z directory sync created VERIFIED `directory_verified` bindings for Alice and Bob automatically; manual mapping API calls: 0.
* Layer 1 Guard matrix 10/10, including the group and inherited fixtures.
* SharePoint's own effective-permission matrix 10/10; AccessProof agrees on every cell.
* Protected RAG E2E-01..06, 10, 11: 8/8 pass after the D-22 Guard fix; model-context witness shows denied documents never reached the model.
* Revocation A **FAILED before D-23** (no detection in ~26 min); fixed in r28 and to be re-measured.

## Update 2026-11-04 04:35 UTC — r29 and r30 deployed (D-24, D-25: SharePoint ACL sync recovery)
| Release | Commit | Deploy SSM | DB | Result |
|---|---|---|---|---|
| `r29-delta-resync-b1ee8c7d4fcc` | `b1ee8c7` | `31156872-…` 03:34→03:36Z | `w7a8b9c0d1e2` | DEPLOYMENT VERIFIED; ACL cursor **still degraded** (`ACL_SYNC_INCOMPLETE`) — see D-25 |
| `r30b-d25-resync-a4f8020dc663` | `a4f8020` | 04:02→04:04Z | `w7a8b9c0d1e2` | DEPLOYMENT VERIFIED; ACL cursor `connected` at 04:04:18Z, 0 failures since |

* **D-25:** `bounded_idempotent_request` calls `raise_for_status()`, so Graph's 410 surfaced as `httpx.HTTPStatusError` inside `_request`. The D-24 `status_code == 410` check after it was unreachable. The D-24 test had faked `acl_delta_page` entirely; new tests drive the real adapter through an HTTP mock transport and fail without the fix. The worker now logs an ACLSyncError's cause type.
* **Automatic recovery observed in production:** the cursor had been degraded since 2026-11-03 19:13:59Z. It resynchronized the whole approved subtree on the first r30 cycle (revision 1007→1008, 7 resources, no spurious grant changes) without operator action.
* The first `r30-…` attempt was refused by the deploy preflight (7 GB free, 8 GB required) before any change. Unused Docker build cache older than 24 h was pruned (1.9 GB) and the same commit shipped as `r30b-…`.
* **Tests:**
  * r29 full suites: SQLite 1493 tests, 0 failed, 0 errors, 10 skipped (exit 0, JUnit). PostgreSQL 17 as `accessproof_app`: 1493 tests, 0 failed.
  * r30 (two-file change): unit, security and contract 1324 tests, 0 failed, 0 errors. Affected adapter and worker tests: 109, 0 failed.
  * The earlier 10 SQLite OIDC failures came from non-hermetic real DNS lookups in two integration tests, reproduced exactly by forcing DNS failure and fixed in `b1ee8c7`. A DNS-down audit still shows 9 tests that need DNS: 8 resolve `localhost` for real local TCP, and 1 webhook test resolves a public hostname. All pass with normal DNS.
* **Staging (accessproof_app):**
  * r29 and r30 rehearsed with DEPLOYMENT VERIFIED; security probe 23/23 on each (22 PASS plus the RT-04 observation), 0 API and 0 worker errors.
  * Rollback rehearsal r30→r29 kept `accessproof_app` / `accessproof_rls_admin` and the API healthy (D-15 verified again).
* **Live on r30, real Entra delegated API tokens (scp=access_as_user):**
  * Layer 1 Guard matrix 10/10, plus 4 negative controls: ID token → 401, tampered signature → 401.
  * Protected RAG E2E-01..06, 10, 11: 8/8.
  * Buffered release: all 6 released answers had a Guard Layer 2 allow for the same decision.
* **Revocation on r30** (seconds from t0; t6 = 5 consecutive denials spanning ≥60 s):

| Trial | t1 source | t2 detected | t3 revision | t4 Guard ack | t5 first denial | t6 stable |
|---|---|---|---|---|---|---|
| A direct grant | 8.0 | 78.6 | 82.3 | 82.4 | 83.3 | 152.3 |
| E restore of A | 7.4 | 259.8 | 263.5 | 263.6 | 274.2 (allow) | 342.6 |
| A (route run) | 8.1 | 201.8 | 151.1* | 151.2* | 226.2 | 295.2 |
| E restore (route run) | 7.1 | 228.8 | 232.8 | 232.9 | 243.9 (allow) | 312.6 |

  \* That revision change was unrelated (it preceded detection); t5 is the authoritative enforcement time. Detection is bounded by the 300 s ACL sync interval, so expect up to about 5 minutes from source change to denial.
* **F in-flight:** a request that passed Layer 1 under revision 746 had its answer withheld by **Guard Layer 2 at 04:21:32Z (`AUTHORIZATION_REVISION_CHANGED`, revision 747)**. 0 responses containing the document were released after detection. The harness's first in-run verdict (FAIL) counted three releases that finished before AccessProof detected the revocation; those are propagation latency. The rule was corrected and the original counts are kept in the evidence.
* **G cache:** the cached baseline route returns 503 `UNPROTECTED_BASELINE_DISABLED`; protected answers are never cached (`cache_hit:false` on repeats); after revocation the pre-revocation answer is not returned.
* **E2E-07:** after stable denial, the protected route never sent the document to the model.
* **Security gates on r30 (read-only, 04:11Z):** PASS A infrastructure, B identity, F Layer 1. FAIL C (no independent certificate yet), D and E (Guard not ready, which waits on C), I (runtime DB role is still the owner `accessproof`), J (activation). BLOCKED G and H (they require certified evidence). Verdict: **NOT VERIFIED**. Protect remains inactive.

## Update 2026-11-04 06:05 UTC — revocation B–D, least-privilege, r31, certificate, gates; D-27 open in production
* **Revocation on r30** (seconds from t0):

| Trial | t1 source | t2 detected | t5 first denial | t6 stable | Restore stable |
|---|---|---|---|---|---|
| B group membership | not observed* | 412.3 | 430.6 | 494.9 | 912.2 (detected 838.4) |
| C inherited folder grant | 7.9 | 25.4 | 40.4 | 108.3 | 333.3 |
| D deletion | 7.9 | 242.5 | 255.1 | 317.8 | n/a |

  \* SharePoint's own GetUserEffectivePermissions did not reflect the group removal within the window, although AccessProof denied. Group changes travel by directory sync (900 s on r30), which explains the 412 s. r31 makes it 300 s, and directory evidence older than 900 s fails closed. Inside the window the Guard serves its last verified snapshot (bounded staleness).
* **Least-privilege database (P0-01):** production switched at 05:16Z (api `accessproof_app`, worker `accessproof_rls_admin`, metrics `accessproof_metrics`). Runtime audit: not superuser, no BYPASSRLS, owns nothing, 58/58 tables have policies. 0 worker errors and 0 API 5xx afterwards. Rollback under these roles was rehearsed on staging (r30→r29, roles preserved). r31 deployed over them and kept them.
* **r31 `r31-cache-freshness-8df06ebd7b4a`** (05:19→05:21Z): cached-chunk version freshness, signed memory/tool context, 300 s directory sync. SQLite 1523/0, PostgreSQL 17 (`accessproof_app`) 1523/0, staging probe 23/23.
* **Certificate:**
  * Certifier public key `ap-certifier-2026-11` pinned in api and worker (backup of compose and `.env` kept).
  * Scope `sharepoint_list_item_effective` / `c63d3b90…`.
  * Certificate issued from 14 live checks (evidence digest `a3499fe7…`), imported, and accepted by the API.
  * Guard `ready:true`, certification window closed, Gateway ready.
* **Gates on r31 with the certificate evidence (05:33Z):** A, B, C, D, F, G, H, I **PASS**. E FAIL (`route_certified` MISSING, D-26). J FAIL (route challenge, cutover and Guard Protect acknowledgement). Verdict **NOT VERIFIED**. Protect is **inactive** (`protect_pending`).
* **Live on r31:**
  * Layer 1 10/10 with indexed versions.
  * Stale and missing content version refused (8/8 controls).
  * RAG E2E 8/8.
* **D-27 (P1, open in production):**
  * What happened: after trial D deleted a document, the 05:32Z synthetic content edit made the ACL sync re-read the deleted item (Graph 404). Every sync has failed since 05:30:32Z, and the Guard fails closed (503 / `ready:false`).
  * Fix: `51f4204`, reproduced and verified against the real lab drive. Unit/security/contract 1354/0; staging rehearsal and probe 23/23.
  * **The production deploy was refused by the disk preflight (7 GB free, 8 GB required). Freeing space was blocked by this session's safety controls, so operator action is needed.**
  * The document-update freshness trial could not complete for the same reason (`pass:false`). It did record that no stale chunk reached the model (the route failed closed throughout).

## Update 2026-11-04 06:40 UTC — r32 deployed (D-27), freshness trial PASS, D-26 implemented
* **Disk:** the operator pruned build cache older than 6 h (5.3 GB reclaimed, 11 GB free).
* **r32 `r32b-d27-deleted-51f42048d777`** (06:10→06:12Z, DEPLOYMENT VERIFIED):
  * The Microsoft ACL cursor **recovered automatically at 06:12:09Z** on the first cycle; 0 sync failures since.
  * Roles still `accessproof_app` / `accessproof_rls_admin`; certifier trust intact.
  * Guard `ready:true`.
  * The `r32-…` directory from the disk-refused attempt was left in place; the deploy used a fresh label.
* **Live document-update freshness trial on r32: PASS** (`document-update-freshness-r32.json`). The r31 attempt, which failed under D-27, is kept unchanged.
  * t0, synthetic edit: 06:13:07Z.
  * t2, lab re-index to the new version: 06:14:53Z. From then until t1, chunks at the new version were refused because the Guard did not know that version yet; the document was kept out of model context.
  * t1, Guard installs the new version: 06:18:04Z. From then on the old version is refused (`SOURCE_CONTENT_VERSION_STALE`), and the document was served at the new version at 06:18:07Z.
  * Before t1 (≈ 5 min, the ACL sync interval) the old version was still served: bounded staleness, as documented.
* **D-26 implemented (ADR-0008), r33 candidate `2ff2376`:**
  * The route fingerprint binds configuration only; a Guard policy rollback invalidates the certificate.
  * The `layer2_revoke` outcome must equal the Guard-audited reason (403 `LAYER2_ACCESS_REVOKED` or 503 `AUTHORIZATION_REVISION_CHANGED`).
  * The agent timeout is configurable.
  * 48 route and challenge tests pass. PostgreSQL 17 as `accessproof_app`: 1540 tests, 0 failed, 0 errors. Staging rehearsal and probe 23/23.
* **Gate E still needs a live route challenge against a Gateway installed by the reference installer.** The lab Gateway was paired manually and has no installer manifest, so the agent cannot verify deployment hashes or egress isolation. That is the remaining engineering step before E and J can pass. Protect stays inactive.
* **r33 `r33-d26-route-2ff237699756` deployed** (06:42→06:44Z, DEPLOYMENT VERIFIED). SQLite 1540 tests, 0 failed, 0 errors; PostgreSQL 1540 tests, 0 failed, 0 errors. Afterwards: roles kept, ACL and directory sync connected, 0 sync failures, Guard ready.
* **Gates on r33 with the certificate evidence (06:46Z):** A, B, C, D, F, G, H, I **PASS**. E FAIL (`route_certified` MISSING: no live challenge yet). J FAIL (route challenge, cutover, Protect acknowledgement). Verdict **NOT VERIFIED**. Protect inactive.

## Update 2026-11-04 09:37 UTC — r34 SECURITY BASELINE: Gate E verified, gates A–I PASS
* **Lab deployment migrated to the reference installer.** The RAG, model and Guard run in one reference Compose project, and the Gateway is staged and applied by `accessproof_gateway.installer`. The agent's static isolation check reports `static_egress_isolated: true`. The live pipeline re-passed through it: Layer 1 10/10 plus 8 controls, RAG E2E 7/7.
* **D-28 deployed in r34:** Protect requires an explicit owner approval recorded after the route certificate. Production SQLite 1544/0 and PostgreSQL 1544/0; staging probe 23/23.
* **Route challenge (Gate E), run 10, challenge `4286f0b7-…`:**

| Probe | Result |
|---|---|
| allow | 200; Layer 1 allow + Layer 2 allow |
| deny | 403 `NO_AUTHORIZED_RESOURCES` |
| tamper | 503 `SOURCE_CONTENT_ATTESTATION_FAILED` |
| layer2_revoke | 503 `AUTHORIZATION_REVISION_CHANGED` (Layer 1 allowed; Alice's grant revoked in SharePoint while the model answer was held; Layer 2 blocked the same decision) |

  Control plane `tested_awaiting_customer_cutover`, **6 Guard audit records matched**. Cutover then verified as `customer_cutover_verified`, **38 Guard audit records matched**.
* **Earlier runs, kept as evidence:**
  * Runs 1–4: timing mismatches with r34's 300 s sync cycle. Refused correctly by the agent, never accepted.
  * Run 5: D-29 (submitted before the Guard uploaded its Layer 2 record).
  * Run 7: verified, but the cutover nonce was not persisted.
  * Runs 8–9: shot timing; one transient fixture-listing gap.
  * The runner now holds requests through a lab model "hold" hook instead of freezing the container (freezing broke the Gateway's model connection and caused a 503 before Layer 2), persists the nonce at 0600, and waits for Guard audit delivery before submitting.
* **Production gates (06:36 → 09:36Z):** A, B, C, D, **E**, F, G, H, I **PASS**. J FAIL only on `HUMAN_ACTIVATION_APPROVAL_REQUIRED` and `protect_acknowledged_by_guard` (which follows approval). **Protect is NOT active.** No further technical gate is open on r34.
