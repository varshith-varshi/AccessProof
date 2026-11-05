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

## Changes this session (uncommitted until noted)
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
