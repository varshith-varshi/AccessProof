# Release go / no-go

Decided 2026-11-08T08:35Z.

## Verdict

**General availability: NO-GO.**

**Existing pilot (2 protected apps): CONDITIONAL.** It stays protected only if F-001 is resolved before 2026-11-11 17:02 UTC. When a route certificate expires, the route fails closed: Gate E fails, so content is not leaked, but service to those apps stops.

## Blocking items
1. **F-001 (P0, by 2026-11-10 05:27Z at the latest):** the route recertification needs fresh Alice and Bob sessions.
2. F-002 (P0 for GA): certificate renewal is laptop-bound.
3. F-003 / gates A–J not re-verified since 2026-11-05.
4. F-007: no backup restore or rollback drill.
5. Fresh real-customer onboarding is unproven: Microsoft consent and new-app owner approval.
6. `15b870a` (mixed allow/deny partial answers) is not deployed or live-verified.

## Owner actions for F-001 (choose A or B)

**A. Let the timers recertify (recommended, lowest-touch)**
1. Make sure the laptop runs this worktree's updated `scripts/live/employee_identity.py`. It already does, because the units use this path.
2. Shortly before 2026-11-09 17:00Z, restart the sessions with enough lifetime:
   ```bash
   pkill -f "employee_identity.py serve"; AP_SESSION_HOURS=40 scripts/live/start_employee_sessions.sh
   ```
3. Alice and Bob each complete the sign-in link written to `~/.ap-id/<actor>.log`.
4. Keep the laptop awake, on AC power, with `accessproof-remote-rag-tunnel` active, through the 2026-11-09 17:27Z and 2026-11-10 05:27Z timer runs.
5. Confirm all three routes with:
   ```bash
   journalctl --user -u accessproof-route-attestation | grep recertify
   ```
   Each route should show `recertify+import ok: true`.

**B. Supervised early recertification now.** This needs explicit owner authorization because it imports new certificates into production, briefly stops the lab Gateway and Guard, and runs one live SharePoint revocation that is then restored. While the current sessions are alive, or after fresh sign-ins, run:
```bash
AWS_PROFILE=accessproof-certifier uv run --extra dev python -u scripts/certifier/remote_route_attestation.py --recertify-days 4
```

## Other owner authorizations required
- KMS trust transition and `kms:Sign` grant (F-002).
- Production gate run inside the API container (F-003).
- Root access-key removal and MFA enrollment (F-004).
- Elastic IP (F-005).
- Restore drill (F-007).
- The next web release, to ship `15b870a`. Run it off-host with the deployer profile; disk cleanup comes first.
