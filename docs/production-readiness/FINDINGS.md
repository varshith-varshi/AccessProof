# Findings register

Last updated: 2026-11-08T08:35Z. Branch `claude/universal-rag`, base commit `15b870a` (working-tree changes listed under F-001).
Status vocabulary: IMPLEMENTED · TESTED_LOCAL · DEPLOYED · VERIFIED_LIVE · CERTIFIED · BLOCKED · NOT_VERIFIED.
This file contains no secrets, tokens, passwords or document content.

---

## F-001 — Route recertification for the 2026-11-11 expiry depends on employee sessions that end before it runs

| Field | Value |
|---|---|
| Priority | **P0** (all three certified routes lapse to Gate E failure on 2026-11-11 17:02–19:00 UTC) |
| Status | Partly fixed (monitoring and preflight). Renewal itself is **BLOCKED** on owner action |
| Evidence source | `ps` start time and arguments of the session processes; kernel `PM: suspend` journal; `/proc/<pid>/stat`; live `route_status` through the read-only SSM document; `journalctl --user -u accessproof-route-attestation` |
| Verified | 2026-11-08T08:30Z |

**What we observed**
- All three certified routes are VALID in production. Expiry times: crossserver-langchain 2026-11-11T17:02Z, pilot-langchain 18:02Z, crossserver-llamaindex 19:00Z. Attestations succeeded at 05:31Z today.
- `remote_route_attestation.py` only runs a full recertification when ≤2 days remain. The timer runs at about 05:27Z and 17:27Z. The first recertification falls on the 2026-11-09 17:27Z run, and the others on the 2026-11-10 05:27Z run.
- A full recertification asks live Alice and Bob questions through `~/.ap-id/{alice,bob}.sock`.
- The session processes started 2026-11-07 11:03 IST with `--max-hours 12`. They had used about 11.5 h of their 12 h awake-time budget at 08:30Z, so they will exit around 09:00Z today.

**Root cause**
- `employee_identity.serve` measured its deadline with `time.monotonic()`. CLOCK_MONOTONIC stops while the laptop is suspended. That turned a "12 h" session into about 27 h of wall time, and nobody could predict when it would really end.
- Nothing compared session lifetime against the recertification schedule. The watchdog only checked that the socket files existed, so it reported `local_dependencies_present: true`.
- If the recertification had started without sessions, it would only have failed partway through the run.

**Remediation implemented (working tree, local certifier host only — not a production release)**
1. `scripts/live/employee_identity.py`: the deadline now uses wall-clock time, so a session ends at the time it states. The session also answers a non-secret `session` query that returns `session_expires_at`. Token queries are unchanged.
2. `scripts/certifier/renewal_watchdog.py`: computes when the employee sessions are needed. That is the latest pending recertification time plus one 12 h timer period, for routes ≤96 h from expiry. It then queries each socket with only the non-secret `claims` and `session` requests. It raises `EMPLOYEE_SESSION_UNAVAILABLE`, `EMPLOYEE_SESSION_LIFETIME_UNKNOWN` or `EMPLOYEE_SESSION_EXPIRES_BEFORE_RECERTIFICATION`. The probe refuses token queries.
3. `scripts/certifier/remote_route_attestation.py`: a due recertification is refused before it starts, logged as `EMPLOYEE_SESSION_UNAVAILABLE:<actor>`, when either session is down. It never stops Gateway or Guard, and never revokes SharePoint access, without live sessions. This fails closed. Nothing is extended.

**Tests**
- 9 new regression tests in `tests/unit/test_certifier_renewal_watchdog.py`, `test_route_attestation_observation_retry.py` and `test_live_employee_identity_tool.py`.
- Full `tests/unit` + `tests/security` suite: 1630 passed, 9 skipped, 0 failed.
- Ruff: clean.
- Live watchdog run now reports `EMPLOYEE_SESSION_LIFETIME_UNKNOWN:alice,bob` (these are legacy processes) and that sessions are needed until 2026-11-10T07:01Z.

**Note:** the installed user units run from this worktree path (`%h/Projects/AccessProof-universal`). The new preflight and watchdog checks therefore take effect on their next timer run, even though the changes are not committed.

**Remaining dependency (owner):** see F-001 actions in `RELEASE_GO_NO_GO.md`. Restart the employee sessions with the new code and `AP_SESSION_HOURS` long enough to cover 2026-11-10T07:00Z. Alice and Bob must sign in. Keep the laptop awake and the tunnel up across the 2026-11-09 17:27Z and 2026-11-10 05:27Z runs. Alternatively, authorize an early supervised recertification with `--recertify-days 4`.

**Verdict:** OPEN — P0 until new route certificates are imported and VERIFIED_LIVE.

---

## F-002 — Certificate renewal is laptop-bound (single point of failure)

| Priority | P0 for GA (P1 for the current pilot) | Status | BLOCKED |
|---|---|---|---|

- **Evidence:** `docs/INDEPENDENT_CERTIFIER_AWS_ROLLOUT_2026-11-08.md`. The laptop suspends nightly; 4 suspends since 2026-11-07, per the kernel journal.
- **What exists:** the independent EC2 `i-0af8a03948e7ba058` is running with checks ok and SSM Online (checked 08:3xZ). KMS key `0f040c1c…` is Enabled, ED25519 SIGN_VERIFY. A read-only status watcher is installed on the EC2. Signing is disabled and the key is not trusted in production.
- **Remaining:** a delegated employee-token lifecycle off the laptop, an always-on customer Gateway and Guard, a remote evidence protocol, and the KMS trust transition. All need owner and customer authorization.

**Verdict:** BLOCKED.

## F-003 — Production gates A–J not re-run this session

| Priority | P1 | Status | NOT_VERIFIED (last PASS evidence 2026-11-05) |
|---|---|---|---|

- `scripts/production_security_gates.py` must run inside the production API container.
- The only identities available here are the certifier read-only SSM document (8 fixed operations, no gates) and the infra-scoped role, whose production SendCommand is denied.
- **Needs:** the deployer or owner runs the gates. The commands are in `MASTER_CHECKLIST.md`.

## F-004 — Default AWS CLI profile is the account root

| Priority | P1 (governance) | Status | OPEN |
|---|---|---|---|

- No root credentials were used in this session.
- `ssm_ops.run()` already refuses to run without `AWS_PROFILE=accessproof-certifier`.
- **Remediation (owner):** remove or disable the root access keys and enroll MFA on root and on `accessproof-infra-admin`. MFA for that user was NOT ENROLLED as of the 2026-11-08 rollout doc.

## F-005 — Production has no Elastic IP; DNS is at GoDaddy

| Priority | P2 | Status | OPEN (awaiting owner approval, per the 2026-11-05 handoff) |
|---|---|---|---|

- Guards and Gateways resolve public DNS. A changed instance IP degrades them until DNS updates.

## F-006 — Host disk headroom equals the release minimum

| Priority | P2 | Status | NOT_VERIFIED this session |
|---|---|---|---|

- 8 GB free after R44, against an 8 GB release requirement.
- Clean old images before the next web release (deployer-run).

## F-007 — Backup restore and rollback not exercised recently

| Priority | P1 for GA | Status | NOT_VERIFIED |
|---|---|---|---|

- Tooling exists (`scripts/database_backup.py`, `docs/backups.md`).
- No restore drill evidence was found dated after 2026-11-01.
- **Needs:** a restore into an isolated database, with RTO and RPO measured and recorded.
