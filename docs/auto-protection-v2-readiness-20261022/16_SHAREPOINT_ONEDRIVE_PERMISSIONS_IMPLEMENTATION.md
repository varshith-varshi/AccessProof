# SharePoint/OneDrive effective rights — actual implementation boundary

`connectors/microsoft365/adapter.py` lists a configured drive/root, consumes bounded Graph delta pages, processes moved/deleted items, and ingests drive-item sharing permissions into existing ACL graph. Directory sync includes Entra users/groups/transitive members with stable immutable IDs. This is a **preview** and does not constitute SharePoint's complete effective-ACL oracle.

`connectors/microsoft365/sharepoint_effective.py` performs a diagnostic, read-only `GetUserEffectivePermissions` query for an exact list item and independently verified SharePoint LoginName using a separate SharePoint-audience token. It requires integration with a trustworthy site/library/drive/list-item ID mapper, native SharePoint group/scope inheritance analysis, role masks, link possession and freshness-aware policy publishing before Protect.

Source profile requirement introduced in `source_certification.py`: a Microsoft source with site+list IDs can only match `sharepoint_list_item_effective`, while a personally owned drive with owner object ID can only match `onedrive_owner_and_sharing_effective`. An ambiguous Microsoft drive cannot self-classify as safe. Exact source/tenant/root/drive scope and expiry are part of the signed certificate. That certificate verifier is not an actual provider-validation engine and there is currently no issuer.

Missing: native site/library/folder/item role definitions and inheritance breaks/restores, SharePoint groups with siteUser ID mapping, permissions from non-sharing paths, specific/organization/anonymous/guest links, external auth, OneDrive inherited personal-drive/owner rules, list-item mapping, rights masks under real SharePoint REST and live source→policy→Guard revocation comparisons. Therefore **no production Microsoft Protect ALLOW is certified**.


## 2026-10-25 dual-provider onboarding hardening (local source changes)

**Implemented in this repository (not deployed):**
- The Sources UI now exposes distinct `google-drive`, `sharepoint`, and
  `onedrive` profiles, plus the legacy `microsoft365` preview. New Microsoft
  sources collect Entra tenant, drive, and approved root IDs; SharePoint also
  collects the exact Graph site ID and document-library GUID; OneDrive collects
  the drive owner's Entra object GUID. Without a supplied token, creation
  begins the existing admin-consent flow.
- The API validates explicit SharePoint/OneDrive profile identifiers, binds
  them to the tenant and source, and rejects an attempted silent profile
  change during credential rotation. The Microsoft admin-consent fingerprint
  now includes site/list/owner identifiers.
- The Microsoft adapter independently checks the SharePoint folder's
  `sharepointIds.siteId` (SPSite collection GUID), `webId` (SPWeb GUID),
  `listId`, and site URL hostname against the Graph site profile, and checks
  OneDrive drive type and owning Entra object ID. Missing provider facets
  result in denial rather than guessing. Legacy unprofiled Microsoft sources
  remain preview-only.
- Existing provider authorization freshness, Guard fail-closed readiness,
  source effective certification, Layer 1, and Layer 2 were **not** weakened.
  Passing mocked Graph calls is not SharePoint effective-ACL certification.

**Release blockers remain (P0):**
1. Obtain an administrator-approved, dedicated Google Workspace tenant and
   Microsoft 365/SharePoint test tenant with real, separately verified
   employee/guest accounts, groups, and permission mutations.
2. For SharePoint, independently verify native SharePoint role assignments,
   limited access, broken/restored inheritance, SharePoint groups and item
   effective permissions; Graph `/driveItem/permissions` is *not* a complete
   effective-ACL oracle. Bind the verification evidence to the exact
   site, list, item, tenant, and principal before issuing any scoped
   provider-live certificate. No automatic source certificate issuer is
   present in this tree.
3. Test revocations through both delta and complete reconciliation, including
   missing Graph notifications, expired credentials, OAuth failures,
   SharePoint site/library ACL updates, OneDrive ownership, and returned
   cached/tool/streamed answers. Gate Protect on complete policy propagation.
4. Run staging schema migration and rollback rehearsals with production-like
   tenant isolation, source ACL seed, policy install, and mandatory negative
   end-to-end authorized/revoked probes. **No live production deployment,
   SharePoint Protect certification, or real-provider revocation SLO is claimed.**

Useful primary documentation:
- https://learn.microsoft.com/en-us/graph/api/driveitem-list-permissions
- https://learn.microsoft.com/en-us/graph/permissions-selected-overview
- https://learn.microsoft.com/en-us/graph/api/driveitem-delta
