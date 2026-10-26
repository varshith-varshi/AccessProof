# AccessProof SharePoint/OneDrive continuation — implementation and validation
Date: 2026-10-22. Project root: /home/white-devil/Downloads/accessproof/f15.
Frontend: web-v2 (not legacy apps/web). Local files only, no live credentials or production deployment.

## Requested scope
Implement all feasible SharePoint/OneDrive hardening and onboarding **without** multi-source RAG protection. Retain one authorization source per AI application. Do not promise universal SharePoint authorization until independently validated.

## Newly implemented in this continuation
1. **Removed** the experimental `MultiSourceProtectedRAG` SDK class and export created at the beginning of this work. Existing single-source Guard/SDK contracts are unchanged.
2. **Fixed Microsoft Entra group reassignment:** Graph group directory sync no longer joins a new immutable group ID to an existing group merely because the email matches. Added a complete provider-directory-sync regression.
3. **Fixed external/internal identity collision:** permission grantee IDs no longer implicitly resolve to AccessProof database subject/group primary keys. Internal IDs are permitted only when explicitly resolving a pre-existing trusted grant. Unknown principal types fail closed.
4. **Enforced single Entra tenant per AccessProof organization (current schema limitation):** configured Microsoft sources require a valid, nonzero tenant UUID, reject conflicting Microsoft tenants, preserve the exact existing drive/root during credential rotation and reauthorization, and preserve legacy unconfigured draft source creation. This is not support for multiple independent Entra tenants inside one organization.
5. **Added Microsoft admin-consent onboarding:** an organization administrator begins consent for a named source through a trusted tenant-specific Microsoft URL; state is hashed, one-time and expires after ten minutes. Callback rejects replay, tenant changes, altered source drive/folder, and an initiating admin who lost admin privileges. Consent completion obtains a server-side, Microsoft Graph-audience app credential from the fixed tenant token endpoint and validates the approved root item before storing encrypted credentials. Supports a source draft without manually pasting a Graph access token.
6. **Added client-credentials token renewal:** scheduled source sync can reacquire expiring Microsoft Graph app tokens automatically from the configured Microsoft tenant. No arbitrary token endpoint is trusted. Existing refresh-token support is preserved for manual delegated credentials where already configured.
7. **Updated web-v2** to expose Microsoft administrator consent and permit draft source creation without manually supplying a token. Existing Shadow-only labels remain.
8. **Added a read-only SharePoint effective-permission probe** in `connectors/microsoft365/sharepoint_effective.py`. It queries SharePoint REST's per-list-item effective permission API using a separately provided SharePoint-audience token and verified SharePoint LoginName. It validates the site URL, list/item IDs, response mask and provider failures, and NEVER publishes an ALLOW to the Guard. It is a diagnostic foundation, not the complete source-of-truth ACL engine.
9. **Closed Guard missing-mapping bootstrap:** when a customer-side/machine or OIDC Guard has an application-bound source but has not received a verified identity mapping snapshot, access is now rejected. An older RAG integration fixture was updated with explicit synthetic mappings rather than weakening security controls.
10. Added synthetic security and integration tests for the above, including consent replay, confusable Entra group IDs, cross-tenant source insertion, source-boundary changes, identity collisions, mock app-token refresh, SharePoint REST masks and unsafe sites.

## Test evidence (local)
- **439 Python tests passed**, five third-party deprecation warnings, full suite after modifications: `/tmp/accessproof_sp_final_python_afterfixture.log`.
- web-v2 production build: passed.
- **25 Playwright tests passed, 1 skipped**, desktop/mobile: `/tmp/accessproof_sp_final_e2e_afterfixture.log`.
- Ruff: passed on changed components; mypy: passed on 7 source files; Python compileall: passed.
- Fresh Alembic upgrade -> downgrade to prior head -> re-upgrade: passed; new `config_fingerprint`, consent-state fields and revision verified.
- Earlier connected Microsoft Graph inventory, ACL revocation and synchronization tests retained their passing status in full regression.
- No actual Microsoft Entra, SharePoint, OneDrive or SharePoint REST API provider was contacted in these tests.

## Release blockers — not finished
**DO NOT REMOVE MICROSOFT PROTECT GATE.** The Graph DriveItem permissions API can omit site/library/native SharePoint group permissions or behave differently with sharing links and inheritance. The new SharePoint REST effective-permission probe is not integrated into an authoritative resource inventory and verified employee-to-SharePoint LoginName mapping. Thus there is not yet complete, production-approved effective access resolution. Microsoft SharePoint source remains Shadow-only.
- Live Microsoft Entra application registration, admin consent, configured Graph application API scopes, separate SharePoint-audience effective-permission probe credentials and user identity linking must be tested with a real authorized Microsoft tenant. Server env requirements: `ACCESSPROOF_MICROSOFT_CLIENT_ID`, `ACCESSPROOF_MICROSOFT_CLIENT_SECRET`, plus properly registered API callback URI. No real app registration has been performed.
- SharePoint native groups, site/library/item permission inheritance, unique/broken inheritance, external guests, link possession, multi-grant effective access, and actual revocation propagation still require complete source implementation and controlled tenant tests.
- Current organization-wide Microsoft directory identity graph supports one tenant per AccessProof organization. Multi-tenant Microsoft support needs a separately migrated tenant-scoped subject/group namespace and regression plan.
- The SharePoint effective-permission probe currently requires verified SharePoint LoginName and a correct SharePoint-audience access token. It is not an ACL sync replacement; do not treat its synthetic tests as confirmation of live Microsoft permission semantics.
- Performance under large sites, policy freshness/reconciliation, audit evidence, outage/recovery and customer-side real RAG SDK integration are not yet validated with an actual Microsoft customer environment.
- Production deployment and migration have not been performed. Existing Google Drive remains V1, Microsoft preview remains Shadow-only. Multi-source RAG is intentionally out of scope per explicit user request.

## Controlled pilot criteria
Establish a disposable, authorized Microsoft 365 test tenant with at least two users, security/M365/SharePoint groups, a SharePoint site/library and OneDrive, and site/folder/item inheritance and break/restore conditions. Verify actual effective access against independent user sessions (both allowed and denied), stable Entra-to-SharePoint account mapping, source token consent/refresh, all paths in the single-source Guard's Layer 1 and Layer 2, permission and mapping revocation, timing, failures, recovery and rollback. Keep Protect disabled until real-provider tests and a review demonstrate no unsafe ALLOW for any supported permission path.

Status: **PARTIAL IMPLEMENTATION — CONTROLLED SHADOW PREVIEW ONLY.**
