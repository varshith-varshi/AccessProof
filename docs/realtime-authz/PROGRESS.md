# Near-real-time authorization — durable progress log

Branch `claude/realtime-authz` (worktree `../AccessProof-realtime`, based on `727733e`).
The r34 / Gate E certification runs from the main worktree; this work never touches its scripts, processes or lab containers.

## Status
- [x] Isolated worktree created; Gate E run 5 left running.
- [x] Repository audit
- [x] Graph documentation check (limits recorded in OPERATIONS.md)
- [x] Microsoft webhook receiver + lifecycle (383a6c1)
- [x] Subscription manager: drive root, granted groups, users (383a6c1)
- [x] Event-driven reconciliation, channel-aware (383a6c1)
- [x] Guard propagation fix: state-token wake-up and full-window long-poll (6c8bc97)
- [x] D-29 verifier: missing Layer 2 audit is retryable (cc5d275)
- [x] Freshness contract and operations guide (665ce22)
- [x] Metrics (4ebed4d)
- [x] Full regression on 665ce22: SQLite 1572 tests, 0 failed, 0 errors; PostgreSQL 17 (`accessproof_app`) 1572 tests, 0 failed, 0 errors

- [x] Staging (rt1/rt1b): probe 23/23, receiver end to end under row-level security, rollback to r34 verified
- [x] Integrated r34 baseline (c0947ca); all r34 fix commits present
- [x] Release plan (RELEASE_PLAN.md), awaiting owner approval
- [ ] Live validation and benchmark (after approved deployment)

## Audit findings (2026-11-04)
1. **Discovery today:** polling only for Microsoft. The worker checks every 30 s (`ACCESSPROOF_SOURCE_SYNC_CHECK_SECONDS`) whether ACL sync is due (300 s since last success) and runs a Graph drive delta with the `deltashowremovedasdeleted, deltatraversepermissiongaps, deltashowsharingchanges` preferences (D-23). D-24/D-25 cover 410 resync; D-27 covers deleted descendants. An hourly bounded reconciliation also runs (`ACCESSPROOF_MICROSOFT_ACL_RECONCILE_SECONDS=3600`).
2. **Group membership:** directory sync only, every 300 s since r31 (900 s before). Measured live (trial B on r30): 412 s to detection.
3. **Provider-event infrastructure exists:** `provider_event_subscriptions` (channel_id, provider_resource_id, encrypted_channel_token, expires_at) and `provider_event_journal` (dedupe, retry, lease). The receiver exists for Google Drive only (`/api/v1/provider-events/google-drive`, `event_sync.accept_google_notification`).
4. **Microsoft Graph subscriptions:** none exist.
5. **Journal processing:** `claim_one_provider_event` does an atomic UPDATE…RETURNING lease, reclaims abandoned leases after 5 min, retries with exponential backoff up to 8 attempts, then `failed`. `process_provider_event` calls `synchronize_acls` for the source and is provider-agnostic.
6. **Guard learning:** the existing long-poll `/policy-notifications` (0.25 s server loop) plus a full policy fetch. Observed live: policy committed 07:43:11 → Guard received 07:43:19.7 (8.6 s); authorization revision installed 07:43:31 (another 12 s). Needs investigation.
7. **Layer 2:** `consume_contexts_with_recheck` rechecks decisions and revision hash. During propagation the Guard returns 503 `SOURCE_ACL_STALE` while events are unresolved (fail closed).
8. **Cache:** signed manifests bound to the authorization revision, plus version freshness (r31).
9. **Freshness actually enforced:** control plane ACL age 900 s and directory age 900 s (r31) through source health; production gates use the same; Guard max policy age (verify).
