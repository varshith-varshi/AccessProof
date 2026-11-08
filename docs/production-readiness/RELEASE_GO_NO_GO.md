# Release go / no-go

Decided 2026-11-08T13:42Z (supersedes earlier November 8 status).

## Verdict

**General availability: NO-GO.**

**Existing pilot: 10/10 TECHNICAL PASS pending reviewer approval; still exact-route only, not GA approval.** On 2026-11-08, pilot controlled recertification completed a fresh nonce-bound Guard challenge, signed Gateway probes and real employee cutover; the temporary SharePoint permission was restored. Live read-only production gates A–J all passed via SSM command `6e4182cf-4758-4c37-a67b-0322902b69b5` (`evidence/pilot_10of10_live_20261108.json`). The reference Gateway heartbeat remains expired and its application route certificate is not renewed. Do not onboard new customers or claim general Protect readiness. Existing traffic must continue to fail closed on unverified routes. Independent remote-route renewal remains laptop-dependent and due again in November.

Production API/worker release `api-r55-controlled-recert-a26eeb8d5555` was verified by SSM on 2026-11-08 13:12Z. The web retains `web-r54-tls-doctor-501a74cdb9a2`; DB, Redis, Nginx unchanged.

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
