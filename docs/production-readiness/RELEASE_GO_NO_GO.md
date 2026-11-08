# Release go / no-go

Decided 2026-11-08T14:38Z (supersedes earlier November 8 status).

## Verdict

**General availability: NO-GO.**

**Existing pilot: 10/10 TECHNICAL PASS pending reviewer approval; still exact-route only, not GA approval.** On 2026-11-08, pilot controlled recertification completed a fresh nonce-bound Guard challenge, signed Gateway probes and real employee cutover; the temporary SharePoint permission was restored. Live read-only production gates A–J all passed via SSM command `6e4182cf-4758-4c37-a67b-0322902b69b5` (`evidence/pilot_10of10_live_20261108.json`). The reference Gateway heartbeat remains expired and its application route certificate is not renewed. Do not onboard new customers or claim general Protect readiness. Existing traffic must continue to fail closed on unverified routes. Independent remote-route renewal remains laptop-dependent and due again in November.

Production API/worker release `api-r57-monitor-health-retry-9f2da01b1584` verified by SSM on 2026-11-08 14:12Z. The web retains `web-r54-tls-doctor-501a74cdb9a2`; DB, Redis, Nginx unchanged. Live postrelease pilot 10/10 gates and reference 8/10 gates. Watcher v3 installed on isolated certifier EC2, reports reference DEGRADED.

## Blocking items (ordered)
1. ~~F-001~~ resolved 10:01Z. Recurring: one sign-in about every 3–7 days until F-002.
2. **F-017/F-018 (P0):** Read-only gates A–J are registered and now accept exact certified source evidence. Pilot achieved 10/10 technical PASS after controlled route recertification; reviewer approval is still required. Reference Gates E and J remain blocked by expired Gateway heartbeat and application-level route certificate. See `evidence/pilot_10of10_live_20261108.json` and `evidence/gates_live_with_evidence_20261108.json`. The three separately signed remote routes are valid but cannot substitute.
3. **F-002 (P0 for GA):** renewal still depends on the owner laptop, and the KMS trust transition is not done.
4. **F-007 (P1 for GA):** no restore drill on production data, and no recorded backup schedule or RPO. The local real-PostgreSQL restore passes.
5. **O1 (P0 for GA):** fresh real-customer Microsoft consent and new-app owner approval are unproven.
6. **G1:** Live AWS IAM GetAccountSummary returned `AccountAccessKeysPresent=0`, `AccountMFAEnabled=1`; root access keys do not exist and root MFA is enabled. `accessproof-infra-admin` still has zero MFA devices (owner action).

## Recurring owner action: route renewal (about 1 hour, between 2026-11-11 and 2026-11-14)
```bash
cd ~/Projects/AccessProof-universal
pkill -f "employee_identity.py serve"
AP_SESSION_HOURS=6 AP_RECERTIFY_AFTER_SIGNIN=1 scripts/live/start_employee_sessions.sh
```
1. Alice and Bob each complete the sign-in link printed by the command; it is also in `~/.ap-id/<actor>.log`.
2. As soon as both are signed in, `accessproof-route-attestation.service` starts by itself. All 3 routes are ≤4 days from expiry, so it recertifies them early. The run includes one live revocation, which is restored, and brief stops of the lab Gateway and Guard.
3. Keep the laptop awake, on AC power, with `accessproof-remote-rag-tunnel` active, until the run finishes. Allow up to about an hour.
4. Check the result:
   ```bash
   journalctl --user -u accessproof-route-attestation | grep '"trigger"'
   ```
   Each route should show `recertify+import`, `"ok": true`, `"trigger": "early"`.

The same command worked on 2026-11-08. If an early run fails, its existing certificate stays valid and the route is still attested. Fix the cause, then rerun with `systemctl --user start accessproof-route-attestation.service` while the sessions are still alive. Before running, the watchdog should show no `GUARD_NOT_READY` warnings.

## Other owner authorizations required
| Item | Command / action |
|---|---|
| Gates A–J (F-017/F-018) | Registration and exact certificate-digest-matching evidence transport COMPLETE. Pilot Gate E resolved; remediate only reference's authenticated Gateway heartbeat/new pairing and expired app-route certificate. Then rerun reference Gates E/J. Rerun evidence-backed gates under existing restricted deployer; do not bypass expired certificate checks. |
| Production restore drill (F-007) | Approve a deployer-taken `pg_dump`, restored on an isolated host using `scripts/drills/postgres_isolation_restore_drill.py` checks. Set RTO/RPO targets |
| KMS trust transition (F-002) | Register the KMS key alongside the laptop key, test rejection and rollback, then grant `kms:Sign` |
| Root keys / MFA (F-004) | Root key absence and root MFA verified live through AWS. Enroll MFA for `accessproof-infra-admin` with the human operator's device. |
| Elastic IP (F-005) | Approve EIP allocation and the DNS update at GoDaddy |
| Source renewal ~2026-11-24 | Same sign-in step as F-001; the source renewal timers need live sessions |

## Active Protect 24-hour route renewal correction — DEPLOYED AND VERIFIED PILOT
The P0 fix for `ACTIVE_PROTECT_REQUIRES_CONTROLLED_RECERTIFICATION` shipped as API/worker r55 under F-019. Interactive pilot Owner-controlled recertification completed with Guard challenge 202, employee-route cutover 202, SharePoint restoration and live Gates A–J 10/10 technical PASS. No route certificate expiry was extended or security gate bypassed. The manual reference Gateway still needs fresh pairing and authenticated presence before its own new challenge.


## Monitoring r56 rollback incident — 2026-11-08
A read-only status extension for F-020 was attempted as API release `api-r56-monitor-app-route-0347e33632f1` but FAILED the public API health check during the recreate. The deployment script rolled back the API/worker; independent read-only CLI schema and production preflight confirmed the former release, and pilot Gates A–J still passed 10/10. Monitoring v3 remains NOT deployed. The local release script now has bounded public readiness retries and single-pass rollback traps (F-021); live release retry requires full unchanged authorization/disk/rollback gates.


## Post-R57 and independent EC2 status — 2026-11-08 14:38 UTC
The repaired API release script passed R57 restricted rollout (SSM `416de5e6-cadb-4e75-9e84-005b14eacc8f`). Production source/remote route monitoring API now returns separate 24h application certificate and authenticated Gateway presence fields. Postrelease Gates A–J:
- **pilot-hr-rag**: 10/10 technical PASS, SSM `6c2d873e-0153-41fb-9a53-7675876aa802`; still pending independent reviewer approval. App-level route expiry is 2026-11-09 13:20 UTC; remote certificate renewal is separately scheduled.
- **sharepoint-rag-staging**: 8/10 technical PASS, SSM `6fc3e673-7ad7-4577-96e1-7358781d8159`; reference E/J remain FAIL due to missing real authenticated Gateway presence and expired app certificate.

The isolated EC2 watcher v3 is installed with its hourly timer ENABLED/ACTIVE. Its initial report is `DEGRADED` rather than v2's misleading `UP`, correctly showing the reference failure; the systemd service intentionally exits 2 on DEGRADED while the timer has a scheduled next invocation. No independent certificate signing or customer-secret transfer was enabled. Evidence: `evidence/gates_post_r57_20261108.json`, `evidence/independent_watcher_v3_20261108.json`. No external paging destination is configured.

**GA verdict remains NO-GO.** Owner-approved fresh reference pairing, application challenge, independent renewable employee credentials, production-data restore, fresh-customer consent/Owner Protect approval, admin MFA, and human reviewer approval remain dependencies.

## Post-R57 follow-up — November 8, 2026, 15:20 UTC

**Existing pilot: 10/10 live technical PASS again; reviewer approval outstanding. Reference: 8/10. GA: NO-GO.** This supersedes the earlier 14:38 UTC evidence without changing the underlying R57 API/web deployment.

- The pilot's first controlled recertification retry encountered transient Microsoft Graph/DNS loss during SharePoint grant restoration; the recovery record was retained and the grant was restored with source, effective-access and Guard ALLOW verified. The second run failed its Layer 2 in-flight revocation probes (no verified refusal); it issued no certificate and restored the grant. A subsequent bounded retry with longer revocation lead completed a real Owner-controlled Guard challenge and employee-route cutover, **HTTP 202 / 202**, with signed audit delivery and restored SharePoint grant. No bypass, manual expiry editing, or synthetic PASS was used.
- Production read-only route status confirmed the new **pilot application route certificate expires 2026-11-09 15:12:37.759928 UTC (20:42 IST)** and authenticated Gateway presence is CONNECTED and enforcement ready. This short-lived application certificate requires another valid authorized renewal before it expires; the independent watcher cannot renew it.
- Restricted deployer post-renewal evidence-backed A–J gates: **pilot 10/10 PASS** (SSM 20d39515-73da-42f4-8deb-095f65c5cdc0, evaluated 15:18:45 UTC); **reference 8/10** (SSM 235310de-b411-4100-ba25-227de03f3721, evaluated 15:19:31 UTC), exactly E_GATEWAY and J_ACTIVATION FAIL because reference Gateway heartbeat and application route certificate remain expired. Both remote signed route certificates remain valid but do not substitute for the app-level certificate.
- Both laptop source-certificate renewal units were retried under the restricted certifier role; each returned SUCCESS / NOT_DUE (source certificates have ~26 days remaining). Their existing timers remain enabled. The earlier SSM error was not used to bypass any certification rule.
- Independent certifier watcher v3 re-read production at **15:20:20 UTC**: pilot application route CERTIFIED (~23.87 hours remaining); reference application route NOT_CERTIFIED and Gateway HEARTBEAT_EXPIRED; overall **DEGRADED**. The dedicated EC2 timer is enabled and active. The DEGRADED systemd run deliberately returns code 2; this is an operational alarm, not independent renewal. Signing, KMS trust promotion and automatic renewal remain disabled.
- SharePoint revocation restoration code was hardened to retry transient Graph transport errors, avoid duplicate grants, bind recovery records to the exact organization/source/application and retain interrupted recovery evidence. 14 focused tests passed; commit a66443d pushed. The production API/worker and website were **not redeployed** for this local certification harness change.

**Evidence:** docs/production-readiness/evidence/r57_followup_20261108.json includes challenge outcomes and fresh restricted A–J gate records. Outstanding: reference Owner-authorized exact-route Gateway pairing, app challenge and recheck; recurring pilot app certificate renewal; independent signer/employee consent and signed route evidence; approved production restore drill; fresh-customer onboarding; off-host external paging; admin MFA; reviewer/governance approval. Keep all unverified routes fail closed and GA NO-GO.
