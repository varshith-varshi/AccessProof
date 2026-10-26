# AccessProof — Multi-source enterprise RAG expansion
Date: 2026-10-22 | Scope: local repository only | No production deployment

## Product goal
A customer's RAG may retrieve from multiple independent enterprise systems. Each retrieved chunk must carry a **trusted (source_connection_id, provider_resource_id)** pair; the customer-side Guard must resolve that source's *own* permissions for the verified employee. An OIDC token is evidence of authentication, not automatic authorization to any source.

**Do not turn on Protect for a mixed-source application while even one retrieval, cache, tool, or derived-data path can bypass pre-generation authorization and post-generation provenance checks.** A valid decision for Google Drive does not authorize content from SharePoint, S3, Confluence, or a database.

## Code inventory (verified locally)
- `connectors/google_drive/`: existing production-target V1 connector; real Workspace/permissions tests remain a gate.
- `connectors/microsoft365/`: existing Graph mutation/testing adapter. `acl_sync.py` and `directory_sync.py` contain partially implemented Microsoft Graph ingest paths. Not certified for real SharePoint/OneDrive effective access.
- `connectors/confluence/`, `connectors/slack/`, `connectors/salesforce/`: present, primarily test/source adapters; not evidence of production authorization enforcement.
- No standalone S3 source connector found.
- `web-v2/app/sources/page.tsx` deliberately offers only Google Drive in V1.
- `apps/guard/accessproof_guard/` supports per-source policy decisions and source-scoped verified OIDC identity mappings.

## Local hardening performed on 2026-10-22
1. Microsoft Graph ACL records require recognized read-capable roles and non-expired grants; malformed records fail closed.
2. Sharing-link permissions are not automatically converted to user permissions.
3. Site-local SharePoint user IDs and email-only claims cannot masquerade as stable Entra directory object IDs.
4. Microsoft directory-subject matching no longer infers identity solely from email.
5. Graph delta continuation URLs are restricted to the intended HTTPS graph.microsoft.com drive delta path.
6. Microsoft ACL delta ingest verifies an item's ancestry is inside the approved test-root folder before using its permissions; moved-out items are treated as removed.
7. Identity mapping creation and Guard sync enforce agreement between the source provider and mapped directory subject provider.
8. Added targeted synthetic security tests under `tests/security/test_microsoft_*boundary.py` and `test_microsoft_permission_ingestion.py`; expanded `tests/integration/test_guard_identity_mappings.py`.

These changes reduce risk but **do not certify SharePoint/OneDrive as supported production authorization sources**.

## P0 work before enabling Microsoft 365 in web-v2 Protect
1. Establish a complete, paginated, source-boundary initial inventory and incremental delta pass. Handle reset/invalid delta tokens, tombstones, moves, interruptions, continuation-loop protection, and transaction-safe cursor advancement.
2. Implement authoritative *effective* SharePoint/OneDrive access. Microsoft Graph DriveItem permission objects are not sufficient proof of inherited/site/role/guest/link effective access. Do not infer allow from missing `inheritedFrom`.
3. Support direct Entra user grants, supported security/M365/SharePoint groups, transitive group memberships, inheritance, multi-path grants, and revocation using provider-validated rules. Unsupported cases must be UNKNOWN/DENY.
4. Verify directory mapping for same-tenant Entra users and trusted links from any third-party IdP. Bind source account identifiers to specific Entra tenant and source connection, not only a provider label.
5. Implement safe OAuth authorization/refresh and least-privilege Microsoft Graph consent for the explicitly approved site/library/drive boundary.
6. Sync effective policy and mapping revisions to customer-side Guard with cache invalidation and rollback protection; test outages, stale-state handling, and evidence of revocation latency.
7. Test one RAG that retrieves **Google Drive and SharePoint in the same request**, plus deny/move/offboarding across both sources. All retrieved chunks and derived answers must pass the correct source-specific policy.
8. Provide transparent web-v2 onboarding, provider capability status, health/lag diagnostics, clear unsupported-feature disclosures, and Protect readiness gates.
9. Validate against a real authorized Microsoft 365 test tenant with two employee accounts, genuine Graph permissions, site/group inheritance, revocation, OIDC/JWKS, and rollback.
10. Reconcile existing/legacy grants before changing a previously deployed Guard's Protect source coverage.

## Expansion after SharePoint/OneDrive
- Confluence: use native space/page restrictions and inherited/effective viewing rights; do not equate app tokens with employee access.
- AWS S3: distinguish bucket IAM policies from actual per-employee application authorization; often authorization must come from the customer's upstream app or verified entitlement service, not from an S3 object ACL.
- Salesforce: enforce record sharing, role hierarchies, ownership, sharing rules, field/object-level security.
- Notion/Box/Dropbox/Slack: add *only* after verifying a reliable user-scoped permissions API and revocation semantics.
- PostgreSQL/MySQL: design an application-specific policy/row-level-security adapter. SQL connectivity is not a general employee authorization connector.

## Non-negotiable acceptance gates (for EACH new source)
- Source identity authenticated and mapped; unknown mappings fail closed.
- Complete boundary inventory; resource IDs are stable and globally source-scoped.
- Effective permission tested with allowed and denied employees, groups, inherited grants, multi-path grants, move/delete/revoke and reauthorization.
- No false ALLOW for links, guests, anonymous access, stale sync, incomplete pages, wrong tenant, or unrecognized principal.
- Layer 1 rejects unauthorized retrieval/cache/tool context before model generation.
- Layer 2 rejects mismatched, mixed-source, late-added, and unavailable provenance before output release.
- Revocation effective at Guard after policy synchronization with measured time.
- Backend/API migrations and web-v2 UI tested; full regression, build, and rollback rehearsal pass.
- Real-provider validation completed before external production support claims.

## Suggested implementation order
1. Secure Microsoft 365 permissions and root scope (hardening started locally).
2. Complete SharePoint/OneDrive effective ACL model and end-to-end controlled test tenant.
3. Certify mixed Google Drive + SharePoint RAG, then carefully expose Microsoft source onboarding in web-v2.
4. Choose the next connector using qualified customer demand: Confluence or S3 are different products with distinct authorization models; don't treat their APIs as interchangeable.
