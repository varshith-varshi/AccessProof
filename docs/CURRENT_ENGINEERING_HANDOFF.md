# AccessProof — Current Engineering Handoff

Updated: 2026-11-05 ~21:00 IST. No secrets in this file. Supersedes release status in older 2026-11-05 reports.

## Production (verified live, read-only)
| Item | Evidence |
|---|---|
| Running web release | `web-r43-installer-eee230d1acf2` (commit `eee230d`), SSM `1f39f76c-8074-4008-babb-57add39209ca` = Success 20:24 IST |
| Web image | `sha256:03cecc6fe1cd608cccac5917e185d0aadb61627d81c0deec8395c6dfcb2b0a62`; API/worker/db/redis/nginx containers unchanged |
| Gateway ZIP served (inside running web container, via `ship_production.sh --preflight`) | `32942af578681ad69820351a15dbffacd6a326919bde57e686645048a93501b0` (= reviewed R43 digest; bind mount repointed to R43 folder) |
| Downloads gated | ZIP + SDK wheel return 307 without session |
| API | `GET /health/ready` → ready (db ok, redis ok). Note `/health` is 404 by design. |
| DB revision | `x8c9d0e1f2a3` |

## Applications (read-only certifier queries, 2026-11-05 ~20:45 IST)
| App | Org | Route certificate(s) |
|---|---|---|
| `pilot-hr-rag` | `0fb98b25…` | langchain `0e6f1d19…` VALID, attested 05:30 UTC, expires **2026-11-11 18:02 UTC** |
| `sharepoint-rag-staging` | `48ee8c86…` | llamaindex `43ff9de5…` VALID (exp 11-11 19:00 UTC), langchain `85071fd8…` VALID (exp 11-11 17:02 UTC); old llamaindex `942c2b4c…` INVALIDATED (config change, superseded) |

`PROTECTED_VERIFIED` dashboard state for both apps was last evidenced in `docs/evidence/protect-activation-2026-11-05/`; the certifier's allowed read-only operations do not expose `mode`, so confirm on the dashboard (Owner login).

## Source certificates
| Org/source | Status | Expires | Renewal window opens (10 d) |
|---|---|---|---|
| pilot `0fb98b25…`/`4eb6863f…` | verified; acl+directory connected | 2026-12-04 21:59 UTC | ~2026-11-24 |
| reference `48ee8c86…`/`2fa9562b…` | verified; acl+directory connected | 2026-12-04 15:38 UTC | ~2026-11-24 |

## Automatic verification: 25 checks (apps/api/accessproof_api/app.py `_automatic_activation_checklist`)
21 base checks + CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED + CUSTOMER_RAG_CUTOVER_NOT_VERIFIED + Gateway presence + HUMAN_ACTIVATION_APPROVAL_REQUIRED.
For a fresh app on a certified SharePoint source the 7 that cannot pass before certification are exactly:
LAYER1_INTEGRATION_CONFIRMED, LAYER2_INTEGRATION_CONFIRMED, PROVENANCE_READY, BUFFERED_RESPONSE_GATE_READY (all satisfied by a valid route certificate), CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED, CUSTOMER_RAG_CUTOVER_NOT_VERIFIED, HUMAN_ACTIVATION_APPROVAL_REQUIRED.
=> 18/25 is correct fail-closed state, not a defect (derived from code; the synthetic run's per-check JSON was not saved).

## Renewal dependencies (all run as user systemd units on the owner's laptop)
- `accessproof-route-attestation.timer` 05:23/17:23 UTC, Persistent. Full re-certification at ≤2 days remaining → ~2026-11-09. Needs laptop on, `accessproof-remote-rag-tunnel` active, employee sessions.
- `accessproof-cert-renewal{,-pilot}.timer` daily. Needs laptop on, `~/.ap-id/alice.sock` and `bob.sock` live employee sessions, Guard on 127.0.0.1:8080.
- 2026-11-05 10:36 IST pilot renewal run failed (AWS CLI exit 255 on read-only status call, transient). Harmless (>10 d remaining); next run retries daily.
- State at 20:45 IST: both sessions present, tunnel active, all timers active, Guard ready.
- Deployer cert expiry 2027-02-03 not re-verified this session.

## Changes this session — committed `fe213b4` (on `claude/universal-rag`)
Tests: `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TMPDIR=/dev/shm .venv/bin/python -m pytest -p pytest_asyncio.plugin tests/unit tests/security` → 1510 passed, 9 skipped (54 s). Without /dev/shm the suite is disk-bound and appears hung.
Final synthetic install not re-run: live ZIP is byte-identical (`32942af5…`) to the one that passed the clean synthetic install at ~20:15 IST; re-running would create production resources in the pilot org.
1. `apps/gateway/accessproof_gateway/challenge_cli.py`: `--challenge` accepts the control-plane challenge response as-is (`nonce`→`challenge_nonce`, app match, expiry/state check). Previously the API response was rejected by the CLI ("Unsupported fields"). Tests: `tests/unit/test_gateway_challenge_cli.py`.
2. `tests/security/test_account_attack_matrix.py`: regression test — Admin and Owner-created API key are refused by `/protection/approve`.
Not deployed: (1) ships inside the Gateway ZIP; needs a new ZIP digest + web release when the owner chooses.

## Human authorization blockers (not automatable, by design)
- Microsoft admin consent + selected-site grant for each new customer tenant (customer Global/Privileged Role admin).
- Route certification with real employee identities (operator + customer employees).
- Owner approval (`APPROVE PROTECT <app>`) by the real organization Owner.

## Next actions
1. Commit this session's changes after the test run completes.
2. Keep laptop on / sessions live through ~2026-11-09 (route recert) and ~2026-11-24 (source renewal); confirm `journalctl --user -u accessproof-route-attestation` shows `recertify+import ok`.
3. Decide whether to ship the challenge CLI fix (requires new Gateway ZIP digest in `ship_production.sh`).

## 2026-11-05 ~21:10 IST — R44 candidate work (ChatGPT/Desktop Commander)

**Current production remains R43 until an independent successful R44 deployment result and live artifact comparison are recorded.**

- Fixed R43→R44 packaging gap: `scripts/build_gateway_connector_zipapp.py` now replaces `challenge_cli.py` inside the customer ZIP, so `fe213b4` is actually shipped. The runtime archive and verified runtime manifest remain unchanged.
- Prepared customer ZIP at the operator's local `~/.ap-id/release-cache/accessproof-gateway-connector-v6.zip`; **approved candidate SHA-256** `bab5f15f62c5186235677e489d7020654e72600d1f999a83554fa160a5dd91d9`; runtime digest `00e0b8c57ed39719c6896457f37fc4c0ca8286f5e6684db322ae6f42bd3bb834`.
- Updated approved web-only deployer pin/default source to v6; previous R43 digest remains accepted at preflight for safe upgrade. Deploy label: `web-r44-challenge`. No API or Guard update required.
- Added read-only `scripts/smoke_customer_onboarding.sh` and `scripts/smoke_gateway_customer_zip.py`. Exact v6 ZIP check passed; local installer/challenge + isolated Guard/Gateway/route HTTP tests passed (51 tests). **No new live fresh install** run for this release. See `docs/CUSTOMER_ONBOARDING_SMOKE_R44.md`.
- Full unit+security run exited 0, 9 expected skips (log `/tmp/accessproof-r44-unit-security.log`, may not survive reboot); Ruff and shell syntax checks passed.
- Examined renewal timers. Existing laptop prerequisites all present (3 timers, Alice/Bob sockets, tunnel, private signer file). Added read-only `scripts/certifier/check_renewal_dependencies.py` and tested its failure detection. **Moving certificate renewal to an always-on host is NOT complete**; needs explicit review of independent signer key custody, Microsoft delegated employee authentication and customer-approved RAG access. See `docs/RENEWAL_HOST_MIGRATION_PLAN_2026-11-05.md`.
- Next: commit changes, run deployer dry-run/build and authorized isolated web release (if supported), verify live ZIP, public routes and `pilot-hr-rag`. Never mark customer ready from offline smoke alone.

### R44 first deployment attempt — failed safely; fix prepared

First attempted web-only release `web-r44-challenge-4c1dc60bd68c` (SSM `4590af5f-a56d-4219-8862-e2baa23168b1`) **FAILED BEFORE SWITCHING THE WEB IMAGE**: server-side `deploy_web_only_on_ec2.sh` still compared the new v6 ZIP against the old R43 digest. Production remained R43; no customer traffic changed. Corrected the pinned SHA in BOTH `deploy_web_only_on_ec2.sh` and `deploy_on_ec2.sh`. Added `tests/unit/test_installer_release_digest_parity.py` to require identical reviewed SHA across client and server deploy scripts. New deployment must use a NEW commit/release ID, never rerun the old RID.

### R44 deployed successfully — final authoritative state (2026-11-05)

- Final deployment **SUCCESS** via approved web-only releaser: `web-r44-challenge-0788ca3a1bc0` (commit `0788ca3a1bc0c1020b6fa71bd6ac6ad2b9314cec`); production SSM `bf42e0be-ded0-4051-8a23-31d2a312a317`. Output: `WEB-ONLY RELEASE VERIFIED`, API/worker/db/redis/nginx container IDs unchanged, new installer bind mount verified, unauthorized customer downloads refused.
- Independent post-release preflight SSM `5fb3c17a-1948-4d40-8762-e13d55e6ff36`: Success, live running ZIP SHA-256 `bab5f15f62c5186235677e489d7020654e72600d1f999a83554fa160a5dd91d9`, DB revision `x8c9d0e1f2a3`, web+API+DB+Redis healthy, disk **8 GB free** (at the release minimum; avoid further large deploys without assessing disk headroom).
- Public `https://app.accessproof.in/login` and `https://api.accessproof.in/health/ready` HTTP 200, valid TLS; unauthenticated Gateway ZIP HTTP 307 (refused).
- Separate permitted read-only route-status checks returned `VALID` for pilot-langchain; reference app had current VALID and an older INVALIDATED certificate. Dashboard's `PROTECTED_VERIFIED` mode is **not independently visible** to this identity after release; Owner must confirm.
- **Customer-facing R44 challenge CLI is packaged and live**. Offline smoke plus 51 targeted HTTP/unit regressions passed. Fresh physical customer installation and real employee route certification were not repeated after R44.
- **Renewal migration not done**. Existing timers and laptop prerequisites were healthy at inspection, but real customer-safe off-laptop migration is blocked by authorized signing-key, Microsoft session and network custody decisions (see migration plan).

This is a documentation-only update after deployment. Do **not** confuse the current repository HEAD with the deployed R44 commit above if further docs commits occur.

### 2026-11-05 ~21:58 IST — renewal continuity hardening (ChatGPT / Desktop Commander)

- Confirmed prior R44 production deployment, route certificate evidence and current local certifier prerequisites without disturbing protected applications. The certifier laptop's three renewal/attestation timers, its authorized RAG tunnel and both employee Unix sockets were active.
- Added a **read-only renewal watchdog** and isolated tests: `scripts/certifier/renewal_watchdog.py`, `tests/unit/test_renewal_watchdog.py`, plus user systemd timer/service and best-effort desktop warning service in `deploy/certifier/accessproof-renewal-watchdog*`. The timer is enabled on the owner's Ubuntu laptop (~6-hour cadence). First service run succeeded (OK: 3 certified routes, no stale attestation, all local prerequisites present). The desktop notifier is conditional on a running graphical session; journal remains source of truth.
- Independently queried source certificate status through the already authorized `AccessProof-Certifier-ProductionReadOnly` SSM document, with no new production writes: **reference source verified (~28.97 days remaining)** and **pilot source verified (~29.23 days remaining)**.
- External one-time ChatGPT reminders created for **2026-11-09** (route recertification) and **2026-11-24** (source renewal). These remind the owner; they do not run renewal scripts.
- **NOT COMPLETE:** off-laptop signing migration, real customer Microsoft consent, employee sign-in certification, Owner Protect approval, and Owner-authenticated dashboard `PROTECTED_VERIFIED` confirmation. The existing laptop continues to be the only certifier host; do not copy signing keys, customer tokens or tunnel credentials to EC2 without explicitly approved isolated key/session custody and network design. See `docs/RENEWAL_HOST_MIGRATION_PLAN_2026-11-05.md` and `docs/CERTIFICATE_CONTINUITY_WATCHDOG_2026-11-05.md`.
- No production deployment needed or performed for this monitoring-only follow-up.

## Post-R44 certificate operational hardening (local host, 2026-11-05)

- Added `scripts/certifier/renewal_watchdog.py`, a read-only route certificate/attestation expiry monitor. Deployed its `accessproof-renewal-watchdog.timer` every 2 hours to the owner's *user* systemd (linger already enabled); manual one-shot PASS: three route certificates valid ~6 days remaining; latest route attestation ~11h old and successful; local timer/employee sockets/tunnel/signing-file permissions present. Emits warning journal and exits nonzero on missing dependencies, stale attestation, invalid route cert or near expiry. **Not an off-laptop signer migration.**
- Added `scripts/certifier/source_expiry_monitor.py`, a daily authorized SSM **read-only** monitor for reference and pilot source certificate expiry, with installed `accessproof-source-expiry-monitor.timer`. Initial invocation hit delayed SSM and timed out; repeat finished PASS with both certificates verified for ~29 days. Set service timeout to 8 min to tolerate SSM queue delays. No certificate issued, imported or changed.
- Hardened `scripts/certifier/ssm_ops.py` `read_only()` to retry AWS CLI exit 255 transient transport errors twice with bounded backoff, but refuse AccessDenied/invalid tokens and never retry import or any mutation. Unit tests cover transient, terminal and non-idempotent cases.
- `docs/FINAL_CUSTOMER_HUMAN_STEPS_2026-11-05.md` lists the minimal Owner/Microsoft admin/customer IT/operator actions for an independently certified real customer pilot.
- These changes are **local certifier host only**, not production API/Gateway changes; no new application release is required. Off-laptop signing remains blocked by explicit key custody/employee session/tenant access decisions.
