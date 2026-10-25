# AccessProof: SharePoint/OneDrive implementation and security validation
Date: 22 October 2026. Local checkout: `/home/white-devil/Downloads/accessproof/f15`. Active frontend: `web-v2/`. No production deployment or live Microsoft credentials.

## Executive status
**PARTIALLY IMPLEMENTED — NOT CERTIFIED FOR PROTECT.**
Google Drive remains the existing V1 production target. A SharePoint/OneDrive **Shadow-only preview** is now offered in web-v2. Microsoft Graph ACL ingest, directory, and source-bound identity flows have received significant hardening. This report does **not** claim that all SharePoint native authorization semantics, consent flows, or real Microsoft integration validation are complete.

## Changes implemented locally

| Area | Changes | Representative files |
|---|---|---|
| Microsoft source connector | Bounded, paginated full subtree inventory under an approved drive/item; root-bound ancestry verification; safe Graph nextLink/deltaLink validation; paginated permission snapshots; pre-inventory delta checkpoint; new-folder subtree discovery | `connectors/microsoft365/adapter.py` |
| ACL ingestion | Explicit read-role and expiry checks; ignore link/unsupported identity grants; stable Entra user/group IDs (never email-only identity fallback); per-resource grants; initial inventory savepoint; `@removed` deletion handling; correct terminal page cap; folder descendant updates and moved-out revocation handling | `apps/api/accessproof_api/acl_sync.py` |
| Directory | Entra users and groups require complete Graph pages and immutable IDs; verify `accountEnabled`; read transitive users across nested Entra groups using Graph's `transitiveMembers` endpoint | `connectors/directory.py` |
| Token refresh | Tenant-specific official Microsoft v2 token endpoint enforced when Microsoft refresh credentials exist; untrusted credential-post endpoints rejected | `apps/worker/accessproof_worker/main.py` |
| Identity mapping | OIDC-to-source mapping creation verifies the mapped subject belongs to the same source-provider family; Guard policy snapshots exclude cross-provider mappings | `apps/api/accessproof_api/app.py` |
| Protect safety | Microsoft sources always fail the API Protect-readiness gate, and Guard receives `source_acl_healthy=false` for Microsoft sources until actual effective-permission certification | `apps/api/accessproof_api/app.py` |
| UI | SharePoint/OneDrive preview connector, tenant/drive/folder inputs, manual Graph credentials, optional Microsoft refresh credentials, explicit Shadow-only notices | `web-v2/app/sources/page.tsx` |
| Tests | Graph pagination/SSRF, nested inventory, ACL delta deletion, moved-in folder, partial-inventory rollback, email reassignment/group collision, Entra transitive members, OAuth exfiltration, source mapping and API Protect gating, mobile/desktop onboarding | `tests/security/test_microsoft_*.py`, `tests/integration/test_microsoft_shadow_release_gate.py`, `tests/unit/test_directory_connectors.py`, `tests/unit/test_oauth_refresh.py`, `web-v2/e2e/web-v2.spec.ts` |

## Confirmed defects reproduced and fixed
1. Microsoft permissions with absent/invalid roles incorrectly became readable.
2. Unknown/malformed/expired permissions, unsafe links, site-local identifiers, and email-only employee claims could be incorrectly interpreted as stable ACL grants.
3. Graph delta continuation URLs were not limited to the approved Graph drive path.
4. Microsoft folder boundaries were not enforced consistently during delta processing.
5. Initial SharePoint sync lacked complete descendant inventory and complete permission pagination.
6. Microsoft `@removed` deletion records were not recognized; a change feed ending exactly at the maximum page count was falsely reported as backlog.
7. Failed initial inventory could leave partial permission graph records after the caller committed a degraded sync status. Implemented transactional savepoint.
8. The Microsoft directory reader omitted nested group users. Now uses transitive membership and rejects incomplete directory snapshots.
9. Reassigned group email could alias an old Entra group and inherit its memberships. New group IDs must be verified as distinct.
10. Source identity mappings could target a source with a different provider; verified before creation and filtered before Guard sync.
11. Untrusted Microsoft OAuth refresh URLs could receive credentials; now restricted to tenant-specific official endpoint.
12. Recently moved-in nested folders could be missed by incremental Graph feeds; affected subtree is inventoried.

## Validation evidence
- Full Python regression suite: **420 passed, 5 warnings**, see `/tmp/accessproof_microsoft_final_after_moved_folder.log`.
- Previous complete run: 419 passed, five deprecation warnings, before latest moved-folder test and change.
- web-v2: ESLint, TypeScript compilation, production build passed.
- Playwright: **23 passed, 1 skipped** (desktop and mobile).
- Ruff and mypy of relevant modified source: passed, with no findings.
- Python compileall and Docker Compose config: passed (local configuration, not deployment).
- All provider API responses in new security tests are synthetic; no live Microsoft Entra/SharePoint/OneDrive tenant was contacted.

## Outstanding blockers (do not mark as implemented)
1. **Full effective SharePoint permissions:** site/library permissions, SharePoint-native groups, inherited/broken inheritance, guest access, sharing-link possession, and record-specific exceptions are not conclusively derivable from the current Graph DriveItem sharing objects. A real source-of-truth resolution strategy and provider tests are required. Protect gate intentionally blocks activation.
2. **Real Microsoft OAuth consent:** web-v2 has manual credential entry plus restricted refresh support, but not end-to-end self-service Entra admin consent/application setup/redirect/token acquisition.
3. **Actual enterprise environment validation:** signed Entra tokens, approved Graph scopes, site/group inheritance, SharePoint vs OneDrive, real account suspension, provider revocation timing and link access require a disposable authorized tenant.
4. **Single AI-application source binding:** the present Guard application-binding contract protects one `source_id` per application. A RAG that mixes Google Drive and SharePoint documents in one generation requires a reviewed multi-source binding/Layer 2 provenance contract and dedicated tests before Protect certification.
5. **Multiple Microsoft tenant directories in one organization:** existing `GuardSubject` provider-scoped identity graph is not yet fully namespaced by Microsoft tenant/source, which may cause ambiguous lifecycle updates. Must be resolved prior to multi-tenant Microsoft production usage.
6. **Directory polling/eventual consistency:** Graph's transitive membership and provider change feeds require measured freshness; no guarantee of instantaneous offboarding. Fail-closed stale-state gate exists, but exact customer SLO must be measured.
7. **Production deployment:** migrations, real consent and secrets, durable recovery, staged cutover and rollback have not been executed for Microsoft.
8. **Other requested sources:** Confluence, Salesforce, S3 and other enterprise systems are not certified authorization sources by these changes.

## Controlled test acceptance gate
Before certifying SharePoint/OneDrive Protect: set up a separate test Microsoft tenant with two Entra employees, a SharePoint site, OneDrive drive, group nesting and site/library/folder inheritance cases; exercise real OAuth/Graph API scopes, capture complete resource inventory, verify each effective permission via independently authorized user access, measure revocation and Guard denial lag, test customer RAG Layer 1/Layer 2 with real source IDs, and rehearse recovery/rollback. Only then consider removing the Microsoft-only Protect-readiness blocker.

No customer or production data was modified. Local changes are uncommitted and have not been deployed.
