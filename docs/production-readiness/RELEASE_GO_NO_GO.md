# Release go / no-go

Decided 2026-11-08T10:05Z (supersedes 09:15Z).

## Verdict

**General availability: NO-GO.**

**Existing pilot: CONDITIONAL / exact-route only, not new production approval.** All 3 independently certified remote routes were renewed and remain valid to 2026-11-15 (14/14 checks), but fresh formal gates A–J do NOT pass for either application (F-017). The reference Gateway heartbeat is expired, and both application-level route certificates are expired. Do not onboard new customers or claim general Protect readiness. Existing traffic must continue to use only genuinely enforced, currently certified routes, failing closed otherwise. The next renewal needs one owner sign-in by approximately 2026-11-14 unless independent renewal is completed.

No production web or API release is needed or pending. Production runs `web-r54-tls-doctor-501a74cdb9a2`. No shipped component changed after `501a74c` (F-008).

## Blocking items (ordered)
1. ~~F-001~~ resolved 10:01Z. Recurring: one sign-in about every 3–7 days until F-002.
2. **F-017/F-018 (P0):** Read-only gates A–J are registered and now accept exact certified source evidence. Formal live rechecks pass 9/10 pilot gates and 8/10 reference gates. Pilot Gate E fails on the expired application-level route certificate. Reference Gates E and J fail on expired Gateway heartbeat plus expired application-level route certificate. See `evidence/gates_live_with_evidence_20261108.json`. The three separately signed remote routes are valid but cannot substitute.
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
| Gates A–J (F-017/F-018) | Registration and exact certificate-digest-matching evidence transport COMPLETE. Remediate app-level Gate E route certificates for both apps and reference's authenticated Gateway heartbeat/route pairing. Gate J then needs recheck. Rerun evidence-backed gates under existing restricted deployer; do not bypass expired certificate checks. |
| Production restore drill (F-007) | Approve a deployer-taken `pg_dump`, restored on an isolated host using `scripts/drills/postgres_isolation_restore_drill.py` checks. Set RTO/RPO targets |
| KMS trust transition (F-002) | Register the KMS key alongside the laptop key, test rejection and rollback, then grant `kms:Sign` |
| Root keys / MFA (F-004) | Root key absence and root MFA verified live through AWS. Enroll MFA for `accessproof-infra-admin` with the human operator's device. |
| Elastic IP (F-005) | Approve EIP allocation and the DNS update at GoDaddy |
| Source renewal ~2026-11-24 | Same sign-in step as F-001; the source renewal timers need live sessions |
