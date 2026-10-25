# SharePoint/OneDrive continuation — revocation and source-boundary hardening
Date: 2026-10-22. Existing repository: /home/white-devil/Downloads/accessproof/f15.
Active UI: web-v2. Scope excludes multi-source RAG per founder decision.
Production changes: NONE.

## Security defects found and reproduced
1. **Group revocation events collided across employees.**
   An ACL tombstone for a group with two members generated the same event
   `dedupe_key` for both members and failed a database unique constraint. This
   prevented a complete revocation sweep. Reproduced in
   `tests/security/test_microsoft_group_multi_member_revocation.py`.
   Fixed by including each `subject_id` in the event's stable idempotency key.
2. **Reconciliation could preserve a document after it moved outside the
   approved SharePoint source folder.** It fetched the old item's permissions
   but did not verify its current source ancestry. A legitimately readable
   file outside the approved source is not permitted for this source.
   Reproduced in `tests/security/test_microsoft_reconcile_moved_out.py`.
   Fixed by checking source ancestry before importing permissions; moved-out
   items are marked deleted and affected employees receive revocation events.
   Orphaned no-member group grants are retired to prevent later resurrection.
3. **Graph remoteItem shortcuts could be mistaken for local protected files.**
   `remoteItem` links may refer to another drive or tenant. The inventory,
   root validation, ancestry checks, and incremental ACL synchronization now
   exclude or revoke such objects instead of importing their grants.
   Regressions: `tests/security/test_microsoft_remote_item_boundary.py`.
4. **Sparse delta retyped folders to documents.** A provider change event
   carrying only an `id` caused an existing folder's type to be overwritten.
   Subsequent inherited ACL changes could miss nested descendants.
   Reproduced in `tests/security/test_acl_delta_folder_metadata_preservation.py`.
   Fixed by retaining trusted previous resource type unless the provider
   explicitly supplies a file or folder facet.

## Validation
See `/tmp/accessproof_sharepoint_continue_20261022_final.log` for the
last complete Python test run. Focused new tests, Ruff, mypy, compile checks
and Docker Compose configuration checks pass.
No Microsoft tenant / credentials accessed; tests use mocked Graph responses.
web-v2 is unchanged in this pass. Its prior full Playwright suite passed
25 tests, with 1 skipped. Previous web-v2 production build passed.

## Critical remaining blockers
- Native SharePoint site/library, SharePoint-group, guest, sharing-link and
  broken/reinherited ACL semantics are **not certified**. Microsoft explicitly
  describes permission inheritance and unique scopes:
  https://learn.microsoft.com/en-us/sharepoint/understanding-permission-levels
- `GetUserEffectivePermissions` is currently a **diagnostic-only**, not an
  authoritative employee-scoped authorization engine. There is evidence that
  O365 group changes can be reflected with delay in that endpoint; manual
  tenant validation must independently resolve transitive identities and
  revocations before any ALLOW is released.
- Need a real authorized SharePoint/OneDrive tenant with live Entra users,
  group and SharePoint-specific ACL variants, site/library/list-item metadata,
  separate SharePoint-audience credentials and independent allowed/denied
  employee access checks.
- Graph app-only admin consent still needs a registered real Entra
  application, callback configuration, scopes and test-tenant validation.
- Single-source Guard bindings remain intentional. No multi-source RAG
  protection was added.
- **Microsoft SharePoint remains Shadow-only. Protect gate must not be lifted
  until effective ACL proof, live provider revocation and end-to-end RAG tests.**

Nothing was committed or deployed.
