# ADR-0007: Automatic, directory-verified Microsoft identity resolution

**Status:** accepted · 2026-11-03 · implemented in `09eb5c6`, `4212475` and later.

## Problem
Before this change, an employee could use the protected RAG only after an
administrator created a `GuardIdentityMapping` for them by hand: issuer,
subject, tenant → synchronized source principal. That cannot work for 1,000
or 100,000 employees.

## What the audit found
| Fact | Where |
|---|---|
| Microsoft directory sync reads every user from Graph with the **source's own tenant-bound credentials** (`/users`, `accountEnabled`). | `connectors/directory.py`, `directory_sync.py` |
| The stored principal id is the Graph user `id`, which is the Entra **object id (`oid`)** that Entra writes into that employee's signed tokens. | live: Alice `67b731fb…` is the same in the token and in `guard_subjects` |
| SharePoint ACL ingestion keys grants to the same Graph `id` (`grantedToV2.user.id`). This is Microsoft's own principal correspondence, not a UPN derivation. | ACL ingestion, live grants |
| The Guard envelope sends `source_subject_id = provider_subject_id`. For Microsoft, a manual mapping was literally `(iss, oid, tid) → oid`. | `app.py` `guard_policies` |

So the manual mapping added **no information** beyond "this `oid` is an
active member account of the source's tenant directory". AccessProof already
holds that, authoritatively.

## Decision
After every Microsoft directory sync, in the same transaction,
`identity_resolution.reconcile_microsoft_bindings` upserts **`directory_verified`**
rows in the existing `guard_identity_mappings` table:

```
(issuer = https://login.microsoftonline.com/<tid>/v2.0, subject = <oid>, tenant = <tid>)
        → guard_subjects row (provider microsoft365, provider_tenant_id = <tid>, account_kind = member, status = active)
```

* The Guard, `resolve_identity()`, the activation checklist, gate B and the
  audit trail are unchanged. They consume rows exactly as before.
* **A binding grants no document access.** Authorization still needs current
  effective-access evidence for that principal from ACL sync.
* No Graph call is added at login or at request time.

### Trust boundaries
1. **Token:** the Guard verifies signature (tenant JWKS), issuer (exact v2.0
   string), audience, tenant (`ACCESSPROOF_GUARD_IDENTITY_TENANT_ID`), expiry
   and the `oid` subject claim (`ACCESSPROOF_GUARD_IDENTITY_SUBJECT_CLAIM=oid`).
   With `ACCESSPROOF_GUARD_REQUIRED_SCOPE=access_as_user` it accepts only a
   **user-delegated access token for the RAG API**. ID tokens and app-only
   tokens are rejected.
2. **Binding:** issued only by the control plane from Graph directory data read
   with the source's credentials. Callers, RAG apps and tokens cannot create
   or alter one.
3. **Authorization:** the Guard's effective-access decisions, fed by ACL and
   directory sync, and the source certificate (D-19) are unchanged.

### Fail-closed rules
* Only `active` **member** accounts are bound. Guests (`userType=Guest` or
  `#EXT#` UPN), disabled, removed and unclassifiable accounts are not.
  Existing automatic bindings move to `SUSPENDED`.
* Principals with no recorded tenant, or from another tenant, are never
  bound. A principal re-read under a different tenant aborts the sync
  (`DIRECTORY_TENANT_CONFLICT`).
* A manual mapping that contradicts directory evidence becomes **`CONFLICT`**,
  which is denied and audited. It is never silently rewritten.
* Any administrator decision is sticky. `PATCH` records `verified_by_user_id`
  and automation never touches administrator-owned rows.
* Source credentials with no valid tenant mean no automatic binding
  (`TENANT_UNKNOWN`).

### States
`VERIFIED` (usable), `SUSPENDED` (directory says not eligible), `CONFLICT`
(contradiction; denied), `REVOKED` (administrator). "Not resolved" means no
row, and the Guard denies (`IDENTITY_MAPPING_UNRESOLVED`, HTTP 403 via D-20).
"Directory unavailable" and "stale" are reported per source by
`GET /api/v1/current/identity-resolution`.

### Scale
* Directory sync: users, groups and memberships are prefetched once. It was one
  query per user, group and membership before.
* Reconciliation: two indexed queries plus changed rows only. Unchanged
  re-syncs write nothing. The `uq_guard_identity_mapping_principal` unique
  constraint makes concurrent workers safe: the loser rolls back and the
  next cycle converges.
* Guard delivery: the Guard offers `identity_version` and receives the mapping
  set **only when it changed**. A full refresh is forced at least every 300 s,
  so a change the fingerprint could miss cannot persist. Older Guards keep
  receiving the full set.
* Measurements: `docs/evidence/identity-scale/`.

### First login and new hires
There is no per-login step. A new hire becomes resolvable at the **next
directory sync** (`ACCESSPROOF_DIRECTORY_SYNC_SECONDS`, default 900 s). Until
then they are denied with `IDENTITY_MAPPING_UNRESOLVED`. On-demand resolution
at first login is not implemented: it would need the Guard to send employee
identifiers to the control plane, which the current design deliberately
avoids.

## Limitations (explicit)
* **One Microsoft tenant per AccessProof organization.** `guard_subjects` is
  scoped to the organization. A second tenant aborts sync
  (`DIRECTORY_TENANT_CONFLICT`) instead of mixing directories.
* **Guests** are not bound automatically. A resource-tenant guest object is
  not the guest's home identity. Use an explicit manual exception after
  review.
* **v1.0 tokens** (`iss = https://sts.windows.net/<tid>/`) are not matched.
  Configure the RAG API for v2.0 access tokens (`requestedAccessTokenVersion = 2`).
* **SharePoint-only principals** (site users or SharePoint groups with no Entra
  object) are outside automatic resolution. Their grants do not map to an
  employee and so grant nothing.
* New-hire latency is bounded by the directory-sync interval (above).

## Rollback
Migration `w7a8b9c0d1e2` is additive (two nullable columns and indexes), and
its downgrade drops them. Automatic rows use the existing table and method
value. Revoking or suspending them, or rolling back to a release without
reconciliation, leaves manual mappings untouched.
