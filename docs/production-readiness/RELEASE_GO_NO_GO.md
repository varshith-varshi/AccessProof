# Release go / no-go

Decided 2026-11-08T10:05Z (supersedes 09:15Z).

## Verdict

**General availability: NO-GO.**

**Existing pilot (2 protected apps, 3 certified routes): CONTINUE, still operator-dependent.** All 3 routes were renewed and are VALID to 2026-11-15 (14/14 checks each). The next renewal needs one owner sign-in by about 2026-11-14, using the early window that opens 2026-11-11.

No production web or API release is needed or pending. Production runs `web-r54-tls-doctor-501a74cdb9a2`. No shipped component changed after `501a74c` (F-008).

## Blocking items (ordered)
1. ~~F-001~~ resolved 10:01Z. Recurring: one sign-in about every 3–7 days until F-002.
2. **F-003 (P1):** gates A–J were last passed on 2026-11-05. The new read-only gates document must be registered once by the owner.
3. **F-002 (P0 for GA):** renewal still depends on the owner laptop, and the KMS trust transition is not done.
4. **F-007 (P1 for GA):** no restore drill on production data, and no recorded backup schedule or RPO. The local real-PostgreSQL restore passes.
5. **O1 (P0 for GA):** fresh real-customer Microsoft consent and new-app owner approval are unproven.
6. **G1:** root access keys still exist; MFA is missing on `accessproof-infra-admin` (F-004).

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
| Gates A–J (F-003, F-012) | Attach `deploy/deployer/iam-policy-gates-document-registrar.json` to `accessproof-infra-admin`; `aws login --profile accessproof-infra-admin`; `deploy/deployer/register_gates_document.sh`. Then `ship_production.sh --gates <org> <app>` for both apps |
| Production restore drill (F-007) | Approve a deployer-taken `pg_dump`, restored on an isolated host using `scripts/drills/postgres_isolation_restore_drill.py` checks. Set RTO/RPO targets |
| KMS trust transition (F-002) | Register the KMS key alongside the laptop key, test rejection and rollback, then grant `kms:Sign` |
| Root keys / MFA (F-004) | Delete root access keys; enroll MFA on root and `accessproof-infra-admin` |
| Elastic IP (F-005) | Approve EIP allocation and the DNS update at GoDaddy |
| Source renewal ~2026-11-24 | Same sign-in step as F-001; the source renewal timers need live sessions |
