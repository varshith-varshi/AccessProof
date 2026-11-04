# Release r35 (candidate): validated Gateway security + near-real-time authorization

**Status: awaiting owner approval. Not deployed to production.**
Candidate: branch `claude/realtime-authz` @ `c0947ca`, which is r34 (`727733e`) plus the real-time authorization work plus the r34 Gate E evidence.

## 1. What is in the release (product code only)
| Change | Files | Why |
|---|---|---|
| Guard wakes on authorization-state change; long-poll held for the whole window | `apps/api/accessproof_api/app.py` (`_authorization_state_token`, policy-notifications `state_token`), `apps/guard/accessproof_guard/{app,sync}.py` | Removes the ~8 s + ~12 s Guard propagation delay measured live |
| Microsoft Graph receiver + lifecycle | `apps/api/accessproof_api/event_sync.py`, `app.py` (`POST /api/v1/provider-events/microsoft`) | Authenticated notification intake (hints only) |
| Graph subscription manager + channel-aware resync | `apps/worker/accessproof_worker/{graph_subscriptions,main}.py` | Drive root (with security webhooks), granted groups' members, users; renewal and lifecycle handling |
| D-29 verifier | `apps/api/accessproof_api/rag_challenge_verifier.py` | A Layer 2 audit not yet uploaded is retryable, not a failed proof |
| Metrics | `apps/api/accessproof_api/observability.py` | Intake, resync latency, failures, subscription operations |

- No database migration; existing tables are reused.
- All r34 fixes are present: D-24…D-28, the cache freshness work, and least-privilege compatibility. Verified with `git merge-base` for every fix commit.
- The r34 branch gained no product code after the split.

## 2. Evidence so far
- **Regression on the candidate code (`665ce22`; the later commits are documentation and the merge):**
  - SQLite: 1572 tests, 0 failed, 0 errors.
  - PostgreSQL 17 as `accessproof_app`: 1572 tests, 0 failed, 0 errors.
- **New tests:**
  - Graph receiver, manager and worker routing: 25.
  - Guard wake-up: 2.
  - D-29: 1.
- **Staging (`i-0e6d2256…`, restricted roles):**
  - Deployment verified; security probe 23/23; 0 API and 0 worker errors.
  - Graph validation handshake: 200.
  - Receiver end to end under row-level security: valid → 202 plus a journal row. Forged clientState, cross-tenant and another drive → 401.
  - The worker took the hint at once and attempted the authoritative re-read. The synthetic source has no credentials, so it went to retry with no authorization change: fail closed.
  - Rollback rt1 → r34 kept `accessproof_app` / `accessproof_rls_admin`, all services healthy, data retained. Candidate redeployed afterwards.
- **r34 production security baseline (09:36Z):** gates A–I PASS, including E (route challenge: 6 Guard audits; cutover: 38). J waits only on the owner approval (D-28).

## 3. Not yet proven (needs deployment): live latency
Live Graph notifications require a public HTTPS receiver, i.e. production `api.accessproof.in`. Before/after numbers must therefore be measured after approval:
- **Before (r30/r34, polling), measured from source change:**
  - Direct grant: first denial 83–226 s.
  - Inherited grant: 40 s.
  - Deletion: 255 s.
  - Group membership: 431 s.
  - Restore: 244–843 s.
  - Guard propagation share: ~8 s (policy) + ~12 s (revision).
- **Target after:** notification receipt → Guard enforcement under 15 s at p95 in the lab. Source change → stable denial is bounded by Microsoft's delivery: driveItem averages under 1 min with a documented 6 h maximum, and group/user latency is unpublished. The fallback stays at 300 s polling, unchanged.

## 4. Owner decisions required
1. **Deploy approval** for r35 (control plane: API, worker, web) through the standard SSM pipeline with automatic rollback.
2. **Microsoft permission:** Microsoft documents `Files.ReadWrite.All` (application) as the minimum for driveItem subscriptions. The AccessProof app has read scopes and `Sites.Selected`. Options:
   - (a) grant it, so drive-root notifications work;
   - (b) don't grant it: drive changes stay on 300 s polling, and group/user subscriptions still work with the existing directory read permissions.
3. **Enable notifications** by adding `ACCESSPROOF_MICROSOFT_NOTIFICATION_URL=https://api.accessproof.in/api/v1/provider-events/microsoft` to the **worker** environment. The production compose file needs a passthrough line; it is backed up and restored automatically on failure, the same procedure as the certifier key.
4. **Guard upgrade (customer side; lab only today):** rebuild the lab Guard image from r35 to get the wake-up fix. The Gateway is unchanged.

## 5. Deployment sequence (after approval)
1. Ship r35 to staging, run the probe (done for rt1b); ship r35 to production with `ship_via_ssm.sh` (preflight, backup, health gates, automatic rollback).
2. Verify the restricted roles and certifier trust; ACL and directory sync connected; Guard ready.
3. Rebuild and restart the lab Guard on r35 (Gateway untouched); re-run Layer 1 and E2E.
4. Add the worker environment variable (owner decision 3); confirm the subscriptions are created. Expect a recorded 403 on the drive subscription if decision 2 is (b).
5. **Phase 4 live certification:**
   - Revocation trials A–D plus group and restore, recording T0–T8 with T2 as notification receipt.
   - In-flight revocation (Layer 2).
   - Cache/version freshness.
   - Route challenge and cutover. The configuration fingerprint is unchanged (same app, Guard, source and adapter), so the r34 route certificate stays valid unless the configuration changes; it is re-run anyway for the new release.
   - Production gates.
6. Report before/after latency with min, median, p95, maximum, failed trials and missing notifications. No p99 from small samples.

## 6. Rollback
`rollback_on_ec2.sh` restores r34 images. Verified on staging. No schema change. To disable notifications only, unset the worker variable: subscriptions stop renewing and expire, and unknown subscriptions are rejected at intake. The Guard change is backward compatible in both directions.
