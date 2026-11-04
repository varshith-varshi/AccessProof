# Near-real-time authorization: operations guide and freshness contract

Branch `claude/realtime-authz`. Status: implemented and tested locally. **Not deployed.** Live Microsoft notifications require a public HTTPS receiver, which needs owner approval to deploy.

## 1. What changes, end to end
```
SharePoint / Entra change
 -> Microsoft Graph change notification (hint only)
 -> POST /api/v1/provider-events/microsoft   (authenticate, journal, coalesce)
 -> worker: authoritative re-read            (drive delta + permissions | directory sync)
 -> permission graph + Guard pipeline        (effective access, policy rows)
 -> Guard woken (AUTHORIZATION_STATE_CHANGED or POLICY_UPDATE_AVAILABLE)
 -> Guard fetches + verifies full envelope; new authorization revision installed
 -> Layer 1 denies new requests; Layer 2 blocks in-flight responses
```
Periodic synchronization is unchanged and remains the safety net:
- ACL sync every 300 s; worker checks every 30 s.
- Directory sync every 300 s.
- Bounded ACL reconciliation every 3,600 s.

## 2. Guard propagation fix (independent of Microsoft)
Measured live on r30 and r34:
- Policy commit to Guard install took about 8 s.
- The new authorization revision arrived about 12 s after that.

The cause: the Guard long-polled for only 1 s and then slept 10 s, and source-health and revision changes never woke it.

Now the Guard holds the long-poll for the whole sync window. The control plane wakes it whenever its `authorization_state_token` changes. The token covers policy version, unresolved permission events, outstanding distributions, source cursor state and the identity set. The Guard always re-fetches and verifies the full signed envelope. The wake-up carries no data. Older Guards keep the previous behaviour.

## 3. Microsoft Graph subscriptions (official documentation, checked 2026-11-04)
| Channel | Resource | changeType | Max lifetime | Documented notification latency |
|---|---|---|---|---|
| acl | `drives/{drive-id}/root` (only the root of a drive's folder hierarchy is supported) | `updated` | 42,300 min | average < 1 min, **maximum 6 hours** |
| directory | `groups/{id}/members`, one per group that carries a grant, at most 40 | `updated,deleted` | 41,760 min | **unknown** (not published) |
| directory | `users` | `updated,deleted` | 41,760 min | **unknown** |

- **Quotas:** group and user subscriptions are limited to 100 per app and tenant and 1,000 per tenant across all apps.
- **Security webhooks:** drive-root subscriptions send `Prefer: includesecuritywebhooks`, which is documented for OneDrive for Business and SharePoint security events. A June 2026 community report says the header was silently ignored. The manager logs `graph_security_webhooks_not_applied` when `Preference-Applied` does not echo it. **AccessProof never assumes a file notification covers every effective-permission change.** Every notification triggers a full authoritative delta and permission re-read.
- **Lifecycle notifications:** for these resources Microsoft documents only `reauthorizationRequired`, **not** `missed` or `subscriptionRemoved`.
  - `reauthorizationRequired` → `PATCH /subscriptions/{id}`, which renews and reauthorizes.
  - Any `missed` or `subscriptionRemoved` that does arrive → mark the subscription for replacement and resync.
  - Because silent loss is possible, periodic sync stays mandatory.

**Permissions to review before deployment.** Microsoft documents `Files.ReadWrite.All` (application) as the minimum for driveItem subscriptions. The production AccessProof Entra app was consented for read scopes and `Sites.Selected`. Creating the drive subscription may fail with 403 until the owner grants it. Failure is recorded (`graph_subscription_operations{operation="failed"}`) and polling continues; it never affects authorization. Group and user subscriptions need `GroupMember.Read.All` / `User.Read.All` (or `Directory.Read.All`), which directory sync already uses.

## 4. Receiver security (`event_sync.accept_microsoft_notifications`)
- **Validation:** `?validationToken=` is echoed as `text/plain`, up to 4,096 characters.
- **Per-item authentication:**
  - The subscription ID must be known and the subscription active and unexpired.
  - `clientState` must match the 96-character random per-subscription secret, stored encrypted and compared in constant time.
  - `tenantId` must equal the subscription's tenant.
  - The resource must lie within the subscribed scope; another drive or group is refused.
- **Rejections are counted and logged by code, not by content:** forged, unknown, expired or retired subscription, cross-tenant, out of scope, unsupported change type, malformed batch, or body over 1 MB.
- **The payload is never authorization data.** `resourceData` is ignored. The worker re-reads Microsoft.
- **Coalescing instead of content deduplication.** Graph drive notifications carry no unique ID, so identical payloads are normal for distinct changes. A new hint joins a still-pending event for the same subscription; if a resync is already in progress, a follow-up event is queued. A replayed notification can only cause an extra authoritative read.

## 5. Freshness contract (what is enforced, by whom)
| Measure | Threshold | Enforced by | On breach |
|---|---|---|---|
| Source ACL evidence age | 900 s (`ACCESSPROOF_SOURCE_ACL_MAX_AGE_SECONDS`) | control plane source health; Guard binding health | Guard 503 `SOURCE_ACL_STALE` (fail closed) |
| Directory evidence age | 900 s (r31+) | same | same |
| Unresolved permission events / outstanding distributions | must be 0 | same | `SOURCE_ACL_STALE` until resolved |
| Authorization revision | must match between Layer 1 and Layer 2 | Guard | `AUTHORIZATION_REVISION_CHANGED` |
| Document content version | must be a current provider version | Guard Layer 1 (r31+) | `SOURCE_CONTENT_VERSION_STALE/UNKNOWN/REQUIRED` |
| Source certificate | ≤ 7 days, exact scope | control plane | not certified, so no Protect binding |
| Route certificate | `CERTIFICATE_TTL`, configuration fingerprint, no policy rollback (D-26) | control plane | not certified |

These measures are distinct: a healthy Guard heartbeat is **not** proof of source freshness, and none of them bounds Microsoft's own notification latency.

## 6. Monitoring (Prometheus; no tenant, user, document or token labels)
- `accessproof_provider_notifications_total{provider,result}`: accepted and rejected.
- `accessproof_provider_event_reconcile_seconds{channel}`: notification receipt to completed authoritative resync.
- `accessproof_provider_event_failures_total{channel,outcome}`: retries and dead letters (8 attempts, exponential backoff up to 300 s).
- `accessproof_graph_subscription_operations_total{channel,operation}`: created, renewed, retired, failed.

**Alert on:**
- any dead letter;
- `failed` subscription operations;
- no accepted notifications for a source for longer than its usual change cadence (a silently dead subscription);
- source health `SOURCE_ACL_STALE` lasting longer than 15 min.

## 7. Configuration
- `ACCESSPROOF_MICROSOFT_NOTIFICATION_URL=https://api.accessproof.in/api/v1/provider-events/microsoft`. When unset, there are no subscriptions and polling only (today's behaviour).
- `ACCESSPROOF_MICROSOFT_SUBSCRIPTION_CHECK_SECONDS` (default 900): how often subscriptions are created, renewed and retired. Renewal happens 2 days before expiry.

## 8. Rollback
- No schema change: the existing `provider_event_subscriptions` and `provider_event_journal` tables are reused.
- To roll back, unset the URL (subscriptions are no longer renewed and expire on their own) or deploy the previous release. Unknown subscriptions are rejected at intake.
- The Guard change is backward compatible in both directions.
