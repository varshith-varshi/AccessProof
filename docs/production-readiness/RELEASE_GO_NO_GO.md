# Release go / no-go

Decided 2026-11-08T09:15Z (second session of the day; supersedes 08:35Z).

## Verdict

**General availability: NO-GO.**

**Existing pilot (2 protected apps, 3 certified routes): CONDITIONAL.** The pilot stays protected only if the route certificates are renewed before **2026-11-11 17:02 UTC** (F-001). When a route certificate lapses, Gate E fails closed. No content leaks, but service to those apps stops.

No production web or API release is needed or pending. Production runs `web-r54-tls-doctor-501a74cdb9a2`. No shipped component changed after `501a74c` (F-008).

## Blocking items (ordered)
1. **F-001 (P0, deadline 2026-11-11 17:02Z):** route recertification needs Alice and Bob to sign in. The owner action is now short; see below.
2. **F-003 (P1):** gates A–J were last passed on 2026-11-05. The new read-only gates document must be registered once by the owner.
3. **F-002 (P0 for GA):** renewal still depends on the owner laptop, and the KMS trust transition is not done.
4. **F-007 (P1 for GA):** no restore drill on production data, and no recorded backup schedule or RPO. The local real-PostgreSQL restore passes.
5. **O1 (P0 for GA):** fresh real-customer Microsoft consent and new-app owner approval are unproven.
6. **G1:** root access keys still exist; MFA is missing on `accessproof-infra-admin` (F-004).

## Owner action for F-001 (recommended, about 1 hour)
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

If this is not done before 2026-11-09 17:23Z, the original fallback still applies: sessions that are alive during the 2026-11-09 17:23Z and 2026-11-10 05:23Z timer runs.

## Other owner authorizations required
| Item | Command / action |
|---|---|
| Gates A–J (F-003) | One time: `deploy/deployer/register_gates_document.sh` (non-root admin). Then `deploy/deployer/ship_production.sh --gates <org> <app>` for both apps |
| Production restore drill (F-007) | Approve a deployer-taken `pg_dump`, restored on an isolated host using `scripts/drills/postgres_isolation_restore_drill.py` checks. Set RTO/RPO targets |
| KMS trust transition (F-002) | Register the KMS key alongside the laptop key, test rejection and rollback, then grant `kms:Sign` |
| Root keys / MFA (F-004) | Delete root access keys; enroll MFA on root and `accessproof-infra-admin` |
| Elastic IP (F-005) | Approve EIP allocation and the DNS update at GoDaddy |
| Source renewal ~2026-11-24 | Same sign-in step as F-001; the source renewal timers need live sessions |
