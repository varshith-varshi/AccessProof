# Microsoft 365 / SharePoint parity implementation report

Date: 2026-10-27  
Repository: `/home/white-devil/Downloads/accessproof/f15`

## Security release verdict

**IMPLEMENTED AND LOCALLY TESTED:** Microsoft source onboarding UI, tenant/profile-bound administrator-consent reuse, durable post-consent directory/ACL queueing, source management controls, Shadow application selection, and operator-managed production app-token renewal.

**SUPPORTED ONLY IN SHADOW MODE:** SharePoint and OneDrive. The existing Protect gate remains intact.

**VALIDATED AGAINST A REAL MICROSOFT TENANT:** None. No tenant credentials were available or used.

**NOT IMPLEMENTED / BLOCKED:** authoritative SharePoint native effective-permission resolution and certification, Microsoft employee OIDC RAG demo, and Graph webhook subscriptions. These require an authorized disposable Microsoft tenant and independent observed-access evidence.

## Reused implementation

The implementation reuses the existing FastAPI source model, encrypted credential store, Microsoft tenant/profile validation, Graph inventory/delta ACL sync, Entra directory adapter, worker, Gateway/Guard single-source binding, and source-effective certificate verifier. Google OAuth and Google Drive handling were not changed in this pass.

## Changes in this pass

- `web-v2/app/sources/page.tsx`: unified Google, SharePoint, and OneDrive connection flow. Microsoft uses only tenant/site-or-owner/drive/root identifiers and server-side admin consent; it accepts no browser token or secret. Sources display connection state, freshness, validation, directory/group sync, permission-sync queueing, authorization/reauthorization, and disconnect controls.
- `web-v2/app/applications/page.tsx`: SharePoint and OneDrive now appear in the single-source selector as **Shadow only**. They are not represented as Protect-ready.
- `apps/api/accessproof_api/app.py`: consent completion resets and queues durable directory and ACL cursors. Added a safe permission-sync queue endpoint that does not acquire tokens from the browser.
- `apps/worker/accessproof_worker/main.py`: production Microsoft client-credential renewal uses the operator runtime client ID/secret and strips legacy source-scoped secrets on a successful operator-managed renewal. A non-production legacy compatibility path prevents upgrades from stranding local test sources before operator secrets are configured.
- `connectors/microsoft365/trusted_ingestion.py`: adds the customer-side, root-bound SharePoint text ingestion bridge for the existing attestation contract. It supports only authenticated Graph `text/plain` items; it rechecks root membership and immutable metadata around download, uses the short-lived Graph download URL without forwarding the Graph bearer token, and binds the item ID, eTag and content digest to each chunk.
- `docs/MICROSOFT365_SHAREPOINT_FEATURE_GAP_MATRIX.md`: pre-change, file-backed feature-gap matrix.

## Capability parity matrix

| Capability | Google Drive | SharePoint | OneDrive for Business |
|---|---|---|---|
| Bounded source root and source health | Implemented | Implemented locally | Implemented locally |
| OAuth/admin onboarding | Server-side OAuth | Tenant-bound admin consent | Tenant-bound admin consent |
| Automated token renewal | Implemented | Implemented locally | Implemented locally |
| Stable directory identities and groups | Implemented | Entra IDs/transitive groups | Entra IDs/transitive groups |
| Inventory and delta/reconciliation | Implemented | Graph bounded inventory/delta | Graph bounded inventory/delta |
| Direct named grant ingestion | Implemented | Implemented with limitations | Implemented with limitations |
| Native effective access for Protect | Existing Google gate | Not certified | Not certified |
| Application binding | Gateway single source | Shadow selectable | Shadow selectable |
| Protect activation | Existing release gates | Blocked | Blocked |

## Permission and synchronization model

Microsoft ACL ingestion accepts only explicit, unexpired Graph read-capable user/group grants bound to stable Entra IDs. Link, unknown, and unsupported principal records fail closed. Directory sync requires complete pages and handles disabled identities and transitive group members. Graph delta is a trigger/input to a bounded, root-checked synchronization process; it is not proof of SharePoint effective rights.

SharePoint’s diagnostic `GetUserEffectivePermissions` probe remains non-authoritative. In particular, site/library/folder/item inheritance, SharePoint-native groups, limited access, guest/link possession, and custom roles must not create Guard ALLOW policy without provider-live evidence. OneDrive is maintained as a separate owner/business-drive profile and is not assumed to share SharePoint semantics.

## Gateway/Guard and revocation

The existing Gateway-first, single-source binding remains in force. Microsoft source IDs are scoped through the existing provider profile and Protect-readiness checks. Fresh ACL/directory cursors and unexpired, signed provider-live certification are required by the existing Microsoft Protect guard; this pass does not weaken it. Permission synchronization is durably requeued after consent so stale snapshots are not presented as current.

## Verification

- Focused Python suite: **21 passed** with the project’s async plugin explicitly loaded. Covered Microsoft admin-consent replay/tenant binding, Shadow release gate, profile binding, and token renewal.
- SharePoint trusted-ingestion unit coverage: **2 passed**, including no bearer-token forwarding and fail-closed boundary/download-host rejection.
- Ruff and Python compile checks: passed for modified backend modules.
- Frontend ESLint, TypeScript type check, and production Next.js build: passed.
- Playwright focused Google source onboarding was updated for the new provider selector and rerun after the UI change.

The default pytest invocation is currently blocked by an unrelated globally auto-loaded ROS pytest plugin (`pytest_launch_collect_makemodule`). The focused suite therefore used `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 -p pytest_asyncio.plugin`.

## Live validation and deployment requirements

Before Protect can be considered for Microsoft, use the existing real-tenant validation runbook with a dedicated tenant, Entra admin, Alice/Bob/Charlie, security/M365/SharePoint groups, a SharePoint library and a OneDrive business drive. Independently measure direct, group, native SharePoint-group, inherited/broken inheritance, guest and link behavior; then bind signed evidence to the exact organization, source, tenant, site/list or owner/drive/root profile. Exercise revocation through worker, policy distribution, Guard, Gateway Layer 1, Layer 2, cached content, and streaming output, recording measured denial latency. Deploy only after migration/recovery rehearsal and explicit review of the evidence.
