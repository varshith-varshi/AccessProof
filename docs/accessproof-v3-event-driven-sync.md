# AccessProof V3 event-driven authorization synchronization

## What is implemented

A supported Google Drive `changes.watch` channel can be registered by the
Google Drive adapter. Its callback is received at:

```text
POST /api/v1/provider-events/google-drive
```

The callback receives no policy content and is never treated as an access
allow or deny. AccessProof validates the registered channel ID, encrypted
channel token using constant-time comparison, returned provider resource ID,
channel lifecycle state, expiration, notification size, and decimal Google
message number. It then creates one durable, tenant-and-source-bound journal
entry. Duplicates are idempotent. Invalid, expired, malformed, or source-
mismatched notifications cannot enqueue authorization work.

The worker claims journal entries with restart recovery, uses the existing
source-scoped ACL cursor, fetches authoritative provider changes through
`changes.list`, applies the existing monotonic revision rules, and lets the
existing policy pipeline distribute resulting policies. A failed provider call
becomes a retry with exponential backoff; it is never recorded as a successful
permission update. Periodic ACL and directory synchronization remain enabled
as missed-event recovery.

## Guard delivery

An enrolled Guard opens an authenticated outbound long-poll request to the
control plane. The long-poll endpoint can only announce a newer policy version;
it contains no permissions, documents, prompts, or answers. On notification,
the Guard performs its normal machine-authenticated policy fetch, rejects
rollbacks, installs the policy atomically, and acknowledges installation. The
existing periodic poll remains the fallback after connection errors, restarts,
and missed notifications.

## Provider coverage

| Provider capability | Status | Notes |
|---|---|---|
| Google Drive `changes.watch` registration | EVENT_SUPPORTED | Requires an HTTPS callback and a supported authorized Drive context. |
| Google Drive notification receipt | EVENT_SUPPORTED | Notification is a wake-up only; `changes.list` remains authoritative. |
| Google Drive direct file/permission/content/move/delete changes | EVENT_SUPPORTED_WITH_LIMITATIONS | Covered only to the extent supplied by Drive changes and the configured source boundary. |
| Google shared drives / inherited permissions | EVENT_SUPPORTED_WITH_LIMITATIONS | Existing ACL reconciliation handles supported metadata; a live tenant validation is required. |
| Google Workspace users/groups | RECONCILIATION_ONLY | This change does not claim `users.watch` or group-audit coverage. Periodic directory reconciliation remains required. |
| Microsoft Graph event notifications | RECONCILIATION_ONLY | Existing durable delta synchronization remains the supported path. |

## Data and privacy

The callback stores only provider channel metadata and delivery sequence state.
No raw document content, employee prompts, cached answers, or model responses
are included in provider-event records or Guard wake-up notifications.

## Operations

Channel registration must persist the returned Google channel ID, resource ID,
encrypted token, and expiry before accepting callbacks. Renewal must create a
replacement channel before the existing one expires and stop the old channel
only after the replacement is durable. Live Google Workspace consent, webhook
reachability, renewal behavior, quotas, and revocation latency require an
administrator-controlled pilot before production claims.
