# AccessProof — Master implementation prompt: enterprise multi-source authorization
**Project root:** `/home/white-devil/Downloads/accessproof/f15`  
**Active frontend:** `web-v2/` (**not** `apps/web/`)  
**Company:** NeuralMatrix | **Product:** AccessProof  
**Scope:** Build on Google Drive V1 to support multiple authoritative enterprise permission sources. Preserve existing OIDC identity mapping, Guard, SDKs, Layer 1 and Layer 2. No production changes without explicit permission.

## Working instructions
You are acting as a security-critical backend, connector, frontend, and test engineer on an existing product. Perform as much implementation and testing as is feasible in the present execution, not just documentation. Do **not** promise zero bugs or claim production readiness without evidence.

Start by reading:
- `ACCESSPROOF_CONTEXT.md`, `FINAL_ARCHITECTURE.md`, `IMPLEMENTATION_STATUS.md`
- `docs/MULTI_SOURCE_EXPANSION_2026-10-22.md`
- `docs/ACCESSPROOF_OIDC_IDENTITY_IMPLEMENTATION_REPORT.md`
- `docs/GOOGLE_DRIVE_V1_RELEASE_GATE_2026-10-18.md`
- `docs/guard-rag-sdk.md`, `docs/rag-adapter-contract.md`, `docs/sharepoint-setup.md`
- Source: `apps/api/accessproof_api/{acl_sync,directory_sync,guard_pipeline,app,db,schemas}.py`, `apps/guard/accessproof_guard/`, `connectors/`, `packages/rag_sdk/`, `packages/guard/`, `web-v2/`, `migrations/`, `tests/`.

First run `git status --short`, `git branch --show-current`, `git rev-parse HEAD`, and inspect diffs. Extensive local changes already exist. **Never git reset/clean or replace uncommitted user changes.** Do not read or print secrets unnecessarily, touch production resources, or deploy.

## Product invariants
1. **Authentication is not source authorization.** Validate enterprise OIDC issuer, signature, audience, tenant, stable subject; link verified employee principal to each source's trusted identity separately.
2. **Each retrieved object is identified by (organization, source_connection_id, provider_resource_id).** Neither plain filename nor LLM citation is an authorization key. User-controlled source IDs cannot select another tenant's policy.
3. Only source-owned effective permissions authorize a source object. Mixed-source RAG requests require **every** returned chunk, cache item, tool result, and derived answer to satisfy its own source policy.
4. Unknown, expired, partial sync, unsupported ACL, wrong-tenant user/group, ambiguous identity, unsupported sharing-link semantics, stale mapping, or unavailable trustworthy permissions must never silently become ALLOW in Protect mode.
5. Customer-side Guard must enforce Layer 1 before the LLM and Layer 2 before response release; never stream unverified output.
6. Revoke policies, group memberships, document permissions, and identity links without stale-state resurrection; measure provider-change-to-Guard-denial latency.
7. Support controlled pilot first. Do not mark a source supported solely because its connector API returns 200.

## Phase 1 — Source capability inventory and contract
Audit all current connector APIs, roles, principal representations, propagation paths, UI/provider allowlists, worker schedules, OAuth refresh, and web-v2. Produce a matrix for Google Drive, SharePoint, OneDrive, Confluence, Salesforce, Slack, S3, Notion, and SQL. Separate categories **enforcement ready**, **connector/test adapter only**, **unsupported**; never invent coverage. Define a minimal source contract: tenant/boundary verification; complete inventory; paginated change read; stable resource ID; normalized principals/groups; authoritative effective permissions; deletions/moves; cursor lifecycle; source-specific health/lag; reconciliation; OAuth renewal; explicit capability declarations and unsupported ACL behavior.

## Phase 2 — Complete Microsoft 365 / SharePoint / OneDrive FIRST
Existing Microsoft365Adapter, Microsoft Entra directory synchronization, ACL ingest, and source-bound Guard mappings are only partially implemented. Inspect latest hardening in `acl_sync.py` and `connectors/microsoft365/adapter.py` before changes. Implement:
- Graph v1.0 complete bounded inventory under administrator-approved drive/root folder, with deterministic paging and checkpointing.
- Validate every Graph continuation URL (same Graph host, drive, resource path) and response shape; prevent SSRF/bearer-token exfiltration, pagination loops, partial-success marking.
- Verify ancestry and preserve folder/parent metadata, cascade permission changes to affected descendants, handle moved-out/deleted resources.
- Correctly determine **effective** SharePoint/OneDrive viewing rights for direct user, Entra security group, Microsoft 365 group, SharePoint group, inheritance and item/site/library-level permission relationships. Microsoft Graph DriveItem sharing permissions alone do not prove every effective access path; design authoritative checks as required. Test this against real documented behavior before any Protect certification.
- Distinguish direct invitations from anonymous/organization/specific-people links and possession of share tokens. Do not treat broad links as automatic tenant grants. Unsupported case must fail closed.
- Handle guests/B2B, disabled users, tenant-scoped immutable Entra IDs vs SharePoint site-local user IDs, groups nested or transitive where applicable, duplicate emails, changed UPNs, permissions with expiration.
- Implement safe source reauthorization/refresh and approved Microsoft Graph least-privilege scopes. Never require tenant-wide write access to perform a read-only policy sync unless unavoidable and reviewed.
- Ensure complete, atomic grant snapshots, zero unsafe old ALLOW after revocation or permission-type changes, revision monotonicity, rollback prevention, reconcilers, failure and stale-age gates.
- Integration-test identity mapping from Entra/Okta/Auth0/Google to the correct *Microsoft source* user, not Google ID. Same employee may require separate mappings for Google Drive and SharePoint.
- Instrument Graph 401/403/404/429/5xx/timeout, retries/backoff and no false denial for transient errors. Provider inability to prove access means no new ALLOW.
- Test OneDrive and SharePoint separately despite sharing Graph APIs.

## Phase 3 — Two-source RAG security test
Build one disposable multi-source RAG harness using Google Drive + SharePoint, with two employees (Alice/Bob), documents belonging to each and both, stale RAG index, cache, tool output, one chunk referencing both sources, mixed answer provenance, and streaming LLM output. Verify per-source mapping and effective access, full pre-generation filtering, no cached bypass, post-generation provenance checks, access revocation, identity mapping revocation, rollback, source outage, audit evidence, and precise denial time. Never count a Guard API call alone as proof the customer's RAG filtered model context.

## Phase 4 — Secure backend and persistence
Extend existing SQLAlchemy models, migrations, FastAPI routes, workers, schedules, policy envelopes and Guard caches only as necessary. Use organization/source-scoped identities, stable principal IDs, versioned cache invalidation, verified mappings, least-privilege management endpoints, strong schema checks, audit events, bounded sync limits, safe storage of refresh credentials, and explicit capability/health fields. No source policy inference from email equality. Prevent cross-source collisions, group-ID collisions and permission ID collisions.

## Phase 5 — web-v2 onboarding and readiness
Implement new provider cards and guided workflows **only when backend validation is operational**. Do not edit legacy `apps/web/` instead. Provide Microsoft site/library/drive/folder selection, secure Graph OAuth consent, scope explanations, source health, inventory progress, directory health, issuer mapping, test Alice/Bob verification, Guard sync status, Shadow verification, Protect gating, and actionable unsupported-ACL statuses. Do not display "Connected/Protected" for incomplete sync or unmapped identities. Preserve Google Drive flow and existing responsive design.

## Phase 6 — Next connectors driven by verified demand
Confluence: space/page restrictions, inherited permissions, groups and revocation.  
Salesforce: object/field/record sharing, ownership, team/rules/roles, tenant-specific principal mappings; protect only explicitly supported query/retrieval modes.  
S3: IAM/resource policies often authorize roles/services, not end-user employees. Do not assume S3 object ACL directly represents employee authorization. Require an authoritative customer application entitlement model where necessary.  
SQL: row-level security or customer-defined entitlement adapter; a raw database URL does not prove user-level access.  
Slack/Teams/Notion/Box/Dropbox: verify provider permissions, private channels, membership changes, links, pagination, and effective source access before declaring support.
Prioritize based on actual customer data-source demand and real permissions API feasibility.

## Phase 7 — Adversarial tests
Cover wrong resource/source, resource-ID collisions, tenant collision, mixed-source query, identity provider collision, forged headers, forged source metadata, malicious Graph nextLinks, malicious file names, expired links, invalid roles, group role churn, guest renames, moved folder ACL changes, deleted/reattached object IDs, partial pages, lost next/delta token, 429 bursts, source downtime, stale cursor, fail-open configuration, Guard restart, control-plane restart, old policy replay, source disabled during generation, streamed token release before Layer 2, and cross-application decision reuse. For every confirmed bug: reproduce -> root-cause fix -> regression test.

## Phase 8 — Validation
Use synthetic signed identity tokens and realistic provider mocks for development, but explicitly distinguish them from real-provider validation. Run targeted unit/contract/integration/security tests, whole Python suite, Ruff, mypy, Python compilation, web-v2 ESLint/typecheck/build, Playwright, DB migration from empty AND populated staging copy, SDK tests, Docker Compose config, Guard policy sync and durable recovery. Record exact commands, counts and failures. If system pytest plugins interfere, isolate them; do not alter security controls to satisfy tooling.
**Before exposing Microsoft in production web-v2**, require a real test Microsoft tenant, real Entra identities, SharePoint+OneDrive permission variants, least-privilege consent, group and link scenarios, measured revocations, a live mixed-source customer RAG integration, documented security review, rollback and approval.

## Phase 9 — Deliverables
Produce `docs/ACCESSPROOF_MULTI_SOURCE_IMPLEMENTATION_REPORT.md` with exact files changed, source-by-source matrix, defects, migrations, measured tests, failed/skipped tests, results for Google Drive and Microsoft 365, blocked scenarios, external validation required, residual false-ALLOW risks, and a **GO / CONDITIONAL / NO-GO** controlled-pilot verdict for each source. Preserve existing production Google Drive functionality and Google-only V1 label unless Microsoft qualifies through acceptance gates. Do not claim Confluence, S3, Salesforce or others are supported until their independent source-specific authorization and complete RAG tests pass.

**Execute all feasible steps in the local authorized environment. Never use real customer credentials, change production, or deploy without explicit approval.**
