# Findings register

Last updated: 2026-11-08T09:10Z. Branch `claude/universal-rag`. Production runs `web-r54-tls-doctor-501a74cdb9a2` (commit `501a74c`, an ancestor of this branch; verified by deployer `--preflight` at 08:58Z).
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

**Update 2026-11-08T09:10Z (second session)**
- The F-001 changes above are committed in `86c9aec`.
- At 08:46Z the legacy sessions were still answering, but they had used about 11.8 h of their 12 h monotonic budget (27.2 h of wall time minus 15.4 h of suspend, from the kernel journal). They cannot report their lifetime (`LIFETIME_UNKNOWN`). An early `--recertify-days 4` run was **deliberately not started**. Each route takes several minutes, and losing a session midway would only produce a failed run after a live revocation and a Gateway stop.
- **New remediation (F-001b, local certifier tooling, TESTED_LOCAL):**
  1. `remote_route_attestation.py` gains an *opportunistic* early-recertification path. A route ≤ `--opportunistic-days` (4) from expiry is recertified on any run where **both** sessions report a known wall-clock end ≥ `--session-margin-hours` (3) away. Legacy and short sessions never qualify.
  2. A failed early attempt falls back to the normal live attestation, so the route does not go stale. A failed *due* (≤2 d) recertification behaves exactly as before.
  3. New `scripts/certifier/recertify_after_signin.py`, plus `AP_RECERTIFY_AFTER_SIGNIN=1` in `start_employee_sessions.sh`. Once both sign-ins complete, the attestation service starts once. It polls only the non-secret `claims` and `session` queries.
  - **Effect:** the owner's commitment shrinks from keeping sessions and an awake laptop alive for about 46 h, across two timer windows, to one sign-in plus about 1 h awake. All 3 routes are ≤4 days from expiry now, so a single run renews all of them.
  - Tests: 6 new (`test_route_attestation_observation_retry.py` ×4, `test_recertify_after_signin.py` ×2).
- The new code takes effect on the next timer run, because the user units run from this worktree. Without fresh sessions, that run attests normally, so behaviour is unchanged.

**Resolution 2026-11-08T10:01Z:** the owner signed in with `AP_RECERTIFY_AFTER_SIGNIN=1`.
- crossserver-llamaindex was renewed at 09:25Z on the first run.
- crossserver-langchain and pilot-langchain failed first (F-010, F-011, F-013), then were renewed at 09:57Z and 10:00Z after the fixes.
- All three are VALID in production through 2026-11-15, verified with read-only `route_status`.
- Both new certifications passed 14/14 checks. MIDREQUEST passed with a genuine `503 AUTHORIZATION_REVISION_CHANGED`.
- SharePoint restore: verified (see CERTIFICATION_STATUS).

**Verdict:** CLOSED for this cycle. The next renewal is due by about 2026-11-11; the early window opens then, with the same one-command sign-in.

---

## F-002 — Certificate renewal is laptop-bound (single point of failure)

| Priority | P0 for GA (P1 for the current pilot) | Status | BLOCKED |
|---|---|---|---|

- **Evidence:** `docs/INDEPENDENT_CERTIFIER_AWS_ROLLOUT_2026-11-08.md`. The laptop suspends nightly; 4 suspends since 2026-11-07, per the kernel journal.
- **What exists:** the independent EC2 `i-0af8a03948e7ba058` is running with checks ok and SSM Online (checked 08:3xZ). KMS key `0f040c1c…` is Enabled, ED25519 SIGN_VERIFY. A read-only status watcher is installed on the EC2. Signing is disabled and the key is not trusted in production.
- **Remaining:** a delegated employee-token lifecycle off the laptop, an always-on customer Gateway and Guard, a remote evidence protocol, and the KMS trust transition. All need owner and customer authorization.

**Verdict:** BLOCKED.

## F-003 — Production gates A–J have no non-root execution path

| Priority | P1 | Status | NOT_VERIFIED (last PASS evidence 2026-11-05). Remediation IMPLEMENTED, awaiting owner registration |
|---|---|---|---|

- **Root cause:** `scripts/production_security_gates.py` must run inside the production API container. Every non-root identity is bounded by design:
  - the certifier: 8 fixed read operations, no gates;
  - the deployer: only the Release and Preflight documents, and denied `ssm:CreateDocument`;
  - infra-scoped: production SendCommand denied.
  So the gates could only run through an interactive owner session, and they went un-run.
- **Remediation (IMPLEMENTED + TESTED_LOCAL):**
  - New generated SSM document `AccessProof-Deployer-ProductionGates` (`deploy/deployer/build_ssm_documents.py` → `ssm/AccessProof-Deployer-ProductionGates.json`). It is pinned to the production instance and takes only two regex-validated ENV_VAR parameters. It streams host facts into the read-only API container and has no write, restart or migrate verbs.
  - The deployer IAM policy is regenerated to allow SendCommand on that document only. All denies are unchanged.
  - `ship_production.sh --gates <org> <app>` exits 0 only on `TECHNICAL_GATES_PASSED_PENDING_REVIEWER_APPROVAL`.
  - The owner registers it once with `deploy/deployer/register_gates_document.sh`, which refuses both root and the deployer.
  - Tests: `tests/unit/test_deployer_gates_document.py` (4).
- **Remaining (owner):** run `register_gates_document.sh` once from a non-root admin session. Then:
  `ship_production.sh --gates 48ee8c86-d4d8-4cde-b00b-bc779f965f4f sharepoint-rag-staging` and
  `ship_production.sh --gates 0fb98b25-bd7d-445e-a192-4ff8ee730760 pilot-hr-rag`.

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

## F-006 — Host disk headroom is near the release minimum

| Priority | P2 | Status | VERIFIED_LIVE 2026-11-08T08:58Z |
|---|---|---|---|

- Deployer `--preflight` reports `DISK_FREE_GB=9`, against the 8 GB release threshold.
- Each web release costs about 1 GB, so only one more release fits before cleanup.
- No release is pending, because no shipped component changed after `501a74c` (see F-008).

## F-007 — Backup restore and rollback not exercised on production data

| Priority | P1 for GA | Status | Restore path TESTED_LOCAL on real PostgreSQL 17. Production-data drill NOT_VERIFIED |
|---|---|---|---|

- **New drill tool:** `scripts/drills/postgres_isolation_restore_drill.py`.
  - It refuses any non-loopback host and any database whose name lacks "drill" (tests: `tests/unit/test_postgres_isolation_drill_guard.py`).
- **Local run, 2026-11-08 ~09:05Z** (evidence: `evidence/postgres_isolation_restore_drill_2026-11-08.json`):
  - Fresh PG 17.11 → `alembic upgrade head` (`x8c9d0e1f2a3`, 1.4 s).
  - Runtime roles provisioned and verified.
  - 2 synthetic tenants seeded across 50 of 59 tenant tables.
  - `pg_dump -Fc`: 0.31 s, 386 KB.
  - Restore into a new database plus grant re-apply: **7.3 s**.
  - Row counts, Alembic revision, 59 forced-RLS tables and 118 policies are identical after restore.
  - All isolation checks pass again on the restored database.
- **Not covered:**
  - production volume and timing;
  - the RPO of the real backup schedule. No scheduled production backup job was found in this repository, so it is NOT_VERIFIED;
  - decrypting provider secrets with the separately stored key;
  - a web/API rollback drill.
- **Needs (owner/deployer):**
  - a production `pg_dump` taken with the deployer, restored on an isolated host with this drill's checks;
  - RTO and RPO targets set by the owner. They are not invented here.

## F-008 — Readiness reports named the wrong production release; `15b870a` was mis-scoped as a release blocker

| Priority | P2 (evidence accuracy) | Status | FIXED in reports 2026-11-08T09:10Z |
|---|---|---|---|

- **Observed:** the live Gateway ZIP is `9db1c5a9…` and web has been up 17 h. That matches `web-r54-tls-doctor-501a74cdb9a2` (`docs/GATEWAY_HEARTBEAT_RECOVERY_2026-11-07.md`), not R44 as earlier reports said.
- `git diff 501a74c HEAD` touches no shipped component (`apps/`, `packages/`, `web-v2/`, `connectors/`, `integrations/`, `migrations/`).
- `15b870a` changes only the local human-validation demo RAG, which is not production SaaS, plus a test.
- The Gateway partial-context behaviour (mixed allowed and denied chunks give a partial answer) is exercised by `tests/security/test_gateway_partial_cached_context.py` against **unchanged, deployed** Gateway code.
- **Result:** no web release is required. The behaviour is DEPLOYED + TESTED_LOCAL. Live observation is still NOT_VERIFIED.

## F-009 — PostgreSQL tenant isolation had only mocked automated coverage

| Priority | P1 | Status | FIXED (tooling) / TESTED_LOCAL on real PostgreSQL |
|---|---|---|---|

- **Observed:** `tests/security/test_rls_context.py` uses a mocked dialect, and `provision_database_roles.py --verify` counts rows only on an empty database.
- **Fix:** the drill (F-007) seeds two tenants and checks the following as the restricted runtime role `accessproof_app`:
  - no tenant context → 0 rows;
  - tenant A sees only A;
  - cross-tenant UPDATE and DELETE affect 0 rows;
  - cross-tenant INSERT is rejected by RLS WITH CHECK;
  - `SET LOCAL accessproof.rls_bypass='on'` has no effect.
  It covers 50 tenant tables, before and after restore.
- **Negative control:** the same checks run as the superuser flag all four violation classes, which proves the checks can fail.
- **Remaining:** live gate I on production, through F-003.

## F-010 — Mid-request Layer 2 search ended on a tunnel drop (crossserver-langchain UNOBSERVABLE)

| Priority | P0 (blocked renewal) | Status | FIXED + TESTED_LOCAL 2026-11-08T09:35Z |
|---|---|---|---|

- **Observed (run `crossserver-langchain.run-20261108T091707Z`):**
  - Attempt 1 was admitted by Layer 1 and held, but the Guard had not flipped yet. The response was then lost with `ROUTE_UNREACHABLE:RemoteDisconnected`.
  - Attempt 2 failed immediately with `ROUTE_UNREACHABLE:URLError` and produced no Guard rows.
  - The SSH-over-SSM tunnel had hit its keepalive timeout at 09:20:10Z and restarted at 09:20:43Z (restart counter 121).
- **Root cause:** the straddle loop treated "no Layer 1 allow row" as proof that Layer 1 already excluded the document, and stopped. A transport failure therefore ended observation.
- **Fix:** `straddle_next_step()` in `scripts/live/remote_route_certification.py`.
  - The search stops only on positive exclusion evidence: a Layer 1 non-allow row, or a model call whose context lacks the document.
  - A transport failure with no Guard evidence is retried within the existing 300 s budget.
  - The PASS/FAIL criteria are unchanged, and UNOBSERVABLE still blocks certification.
- **Tests:** `tests/unit/test_route_cert_midrequest_straddle.py` (4).
- **Comparison:** the llamaindex run used the same logic and PASSED: its second attempt was blocked with `AUTHORIZATION_REVISION_CHANGED` (HTTP 503).

## F-011 — Pilot Guard failed closed for hours undetected (POLICY_SYNC_STALE)

| Priority | P0 (availability; not a leak) | Status | Remediated + monitoring FIXED 2026-11-08T09:40Z |
|---|---|---|---|

- **Observed:**
  - The pilot recertification run went NOT_CERTIFIED, with basic checks UNOBSERVABLE and `503 GUARD_REQUEST_FAILED`.
  - The pilot Guard `/health` reported `ready:false`, `policy_fresh:false`, `sync_error: ConnectError`.
  - Inside the container, DNS for `api.accessproof.in` failed (`gaierror`), while the host resolved it.
  - This is the known stale embedded-DNS upstream after a laptop network change.
- Every protected pilot request failed closed. The FAIL entries (forged/cache/audit) are evidence gaps caused by the Guard returning 503, not leaks.
- **Remediation:** `docker restart ap-pilot-guard`. Afterwards: `ready:true`, `policy_fresh:true`, and a live Guard decision for Alice on the trial document of ALLOW.
- **Monitoring fix:** `renewal_watchdog.py` now probes each loopback Guard's `/health` used by the certified routes and raises `GUARD_NOT_READY:<port>:<sync_error>` or `GUARD_UNREACHABLE`. It also no longer counts failed per-run `*.run-*` outputs as active certificates.
- **Tests:** 3 new in `tests/unit/test_certifier_renewal_watchdog.py`.
- **Remaining:** the alert is still local to the laptop (R4).

## F-012 — Gates registration script fell back to the expired root login

| Priority | P1 | Status | FIXED (script) / BLOCKED on owner IAM grant |
|---|---|---|---|

- **Root cause:** `env -u AWS_PROFILE aws …` strips the profile, so the CLI used the `default` profile. That profile is a root `aws login` session.
- **Fix:** `register_gates_document.sh` now behaves as follows.
  - It requires an explicit profile (`AP_REGISTRAR_PROFILE`, default `accessproof-infra-admin`).
  - It refuses `default`, root ARNs and the deployer, and strips any ambient credentials.
  - It verifies the identity with STS.
  - It runs read-only permission probes and exits 3, naming each missing permission, before making any change.
  - It skips the IAM update if the deployer policy already allows the gates document.
  - Tests: `tests/unit/test_register_gates_identity.py` (4), using a stub `aws` that never contacts AWS.
- **Finding:** no non-root identity in the account can create this document or change the deployer policy. `accessproof-infra-admin` can only assume the certifier-bootstrap role, which is scoped to certifier resources. This is intentional least privilege.
- **Owner action:** attach `deploy/deployer/iam-policy-gates-document-registrar.json` (one document ARN plus the deployer role's inline policy) to `accessproof-infra-admin`. Then run `aws login --profile accessproof-infra-admin` and `deploy/deployer/register_gates_document.sh`.
- The auto-mode classifier blocks Claude from running the registration, so the owner runs it.

## F-013 — Positive checks and the straddle search ended on one transient fail-closed response

| Priority | P0 (blocked renewal) | Status | FIXED + VERIFIED_LIVE 2026-11-08T10:00Z |
|---|---|---|---|

- **Observed (09:40–09:49Z reruns):**
  - Pilot: the first allowed question hit a transient Guard 503 (`GUARD_REQUEST_FAILED`). `ask_allowed` retried only on `AUTHORIZATION_REVISION_CHANGED`, so `AUTHORIZED_ACCESS_RELEASED` and `TRUSTED_PROVENANCE_VERIFIED` went UNOBSERVABLE.
  - crossserver-langchain: the hold loop treated a Guard `HTTP_503` (ACL resync after revocation) as "flipped". Layer 2 then answered 503, which the Gateway reports as `GUARD_REQUEST_FAILED`, and that single ambiguous attempt ended the search.
  - The `ALTERNATE_ROUTES_PROTECTED` and `FAIL_CLOSED_GATEWAY_UNAVAILABLE` FAILs had `http_status: null` (tunnel dropped 09:42:56–09:43:28Z). Nothing was returned, so these were not leaks.
- **Fix in `scripts/live/remote_route_certification.py`:**
  1. `positive_request_retryable()`: positive checks only retry a revision change, a Guard 503 or `ROUTE_UNREACHABLE`. Every attempt is recorded. Denial checks never retry.
  2. Only an explicit `DENY` counts as the flip during the hold. Guard 503s are recorded as `guard_unavailable_during_hold`.
  3. An ambiguous block keeps the search going; it is reported as UNOBSERVABLE only if no clean outcome follows.
  - PASS still requires a Layer 2 block with a revocation reason plus a matching Gateway audit entry, and FAIL still stops immediately.
- **Tunnel:** `RestartSec` lowered from 20 to 3 and `StartLimitIntervalSec=0`, in the repo template and the installed unit (daemon-reload only). It had restarted 123 times.
- **Tests:** `test_route_cert_midrequest_straddle.py`, now 6 tests.
- **Live result:** both routes CERTIFIED 14/14 on the next run.
- **Remaining (P2):** the Gateway collapses every Guard 503 into `GUARD_REQUEST_FAILED`, which hides the reason (contrary to D-20). Changing it means a new Gateway image, which changes route bindings and needs a planned release plus recertification. Deferred deliberately.
