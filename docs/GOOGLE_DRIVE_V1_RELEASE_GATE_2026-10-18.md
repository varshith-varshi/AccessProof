# AccessProof Google Drive V1 — engineering release candidate
**Audit:** 2026-10-18  
**Repository:** /home/white-devil/Downloads/accessproof/f15  
**Deployment status:** LOCAL SOURCE ONLY — not deployed to production.  
**Commercial production status:** NOT YET VERIFIED. Do not describe the product as production-ready until the external gates below are satisfied.

## Work completed in this session

1. **Complete initial Drive folder inventory.** `GoogleDriveAdapter.list_boundary_resources` traverses descendants with Drive v3 paging, scoped to an explicitly approved root folder. The change cursor is acquired before the inventory so concurrent changes can be replayed afterward; incomplete scans fail instead of marking sync ready.
2. **Complete ACL pagination.** `permissions_snapshot` reads every permission page and rejects repeated page tokens or malformed snapshots.
3. **Per-file grant keys.** Grant identifiers now include the original Drive file ID as well as provider and permission ID, preventing the same account permission ID from colliding across multiple documents.
4. **Boundary-aware change processing.** Drive's user-scoped change feed is filtered against the approved root. Newly seen outside files are ignored; known files moved outside are queued for revocation.
5. **Folder/descendant dependencies.** Parent folder changes expand to known child documents for ACL re-evaluation. Newly moved-in folders trigger descendant discovery.
6. **Broad-sharing fail-closed.** Google Drive domain-wide and `anyone` grants are deliberately **unsupported** by the effective-access resolver for V1; they are not expanded to all AccessProof tenant members. No claim is made that valid link-sharing will be allowed.
7. **Nested group membership.** Google Directory synchronization recursively
   expands direct `GROUP` members, paginates every level, deduplicates users,
   and terminates membership cycles. A malformed or incomplete nested response
   degrades the directory sync rather than publishing a partial expansion.
8. **Protect-mode source freshness.** Control plane reports Google Drive ACL and Google Workspace directory sync health with each Guard application binding. Guard refuses Protect requests when its source-health flag is false and reports degraded health/heartbeat. Defaults: 900 seconds maximum ACL age and 2,400 seconds maximum directory age; these are safety thresholds, **not** real-time revocation SLAs.
9. **OAuth refresh restriction.** Google refresh-token requests are pinned to `https://oauth2.googleapis.com/token`; an arbitrary token endpoint supplied with source credentials is rejected.
10. **web-v2 V1 scope.** Customer source creation displays Google Drive only, explains the root-folder boundary, and supports optional administrator-approved OAuth refresh credentials. This is **not** a Google-hosted OAuth consent workflow.
11. **Layer 2 late-source authorization from prior session.** Python and TypeScript SDKs can re-check additional trusted RAG/cached/tool sources under the same verified employee/request. Guard checks contexts and latest installed policy before releasing buffered output.
12. **Customer Guard bundle.** Built Guard archive version `0.1.1` locally with SHA-256 checksum; EC2 Compose can select `ACCESSPROOF_GUARD_RELEASE_VERSION=0.1.1`.

## Verified local tests

- Backend Python regression suite: all tests passing using `TMPDIR=/dev/shm` and explicit pytest-asyncio plugin (latest result in `/dev/shm/accessproof-final-drive-tests.log`).
- Focused Google Drive tests: paginated ACLs, traversal, ancestry, different files sharing one Google permission ID, unsupported domain/anyone, partial-scan failure, parent-folder cascade.
- TypeScript SDK: four tests passed.
- `web-v2`: ESLint and production Next.js build passed.
- Playwright desktop/mobile: 19 passed, 1 skipped.
- Guard 0.1.1 checksum: verified.
- EC2 Compose structure: parsed with dummy (non-production) settings. Real production settings are unavailable and have NOT been tested.

## Production blockers (external evidence / remaining engineering)

**P0 — Real Google Workspace authorization.** No dedicated company Workspace connection, Admin Directory scopes, consent validation, signed Alice/Bob OIDC tokens, or live provider permission grant/revoke has been exercised in this audit. Tests with HTTP mocks are not proof of Drive effective permissions.

**P0 — Effective-permission semantics.** Verify inherited folder/Shared Drive permissions, parent-folder restrictions and moves, group nesting in the customer's edition, group-member revocations, and files with multiple independent grant paths. Domain and anyone/link grants currently fail closed; implement them correctly and provider-test before advertising them.

**P0 — Customer RAG data path.** Integrate one actual customer RAG, prove stable Drive file-ID mapping, use a verified employee principal, authorize every retrieval/cache/tool input before model use, and supply trusted complete source lineage to Layer 2. Model citations are not sufficient provenance.

**P0 — Revocation latency and safety.** Drive polling is currently scheduled every 300 seconds and Workspace directory every 900 seconds by default. Guard checks fresh installed policy but cannot stop a provider revocation that has not yet been detected. Establish measurable SLA, outage/staleness handling and source/identity polling coverage before saying “real-time.”

**P0 — Existing authorization state cutover.** Previous versions used non-resource-scoped grant keys; they can remain stored in deployed databases. Before upgrading a database with existing Guard policies, reconcile the existing graph in a staging copy and ensure legacy effective grants and stale ALLOW policies cannot remain authoritative. Do not simply deploy new code over existing active Protect rules without a verified data transition.

**P0 — Safe deployment.** Staging backup and restore, migration inspection, API+worker+web deployment, Guard enrollment/rotation, monitoring, negative tests, rollback rehearsal and production access are not completed here. An HTTP 200 from /health is not release certification.

**P1 — Google source onboarding.** Browser-hosted administrator OAuth consent and Google OAuth application verification are not yet implemented. The current advanced credential renewal fields support assisted pilots, not public self-service enterprise OAuth onboarding.

**P1 — Other requirements.** Versioned SDK publication, signed installer, support/incident runbooks, legal/customer agreements, security review, and production cloud operations. No claim is made that the Python Guard archive hides the shipped source.

## Recommended controlled V1 pilot definition

One dedicated Google Workspace organization, one explicitly approved test root folder, two genuine employee accounts with signed OIDC tokens, only direct/group Drive permissions, one protected Python RAG, Guard in Shadow then Protect after evidence-backed verification. Include allowed, denied, revoked, reused/stale, absent provenance and cache-source tests.

## Controlled staging cutover checklist

1. Back up and successfully restore the staging copy of the current DB; identify and reconcile legacy `google-drive:` grant keys and existing ALLOW policies.
2. Configure least-privilege Google Drive and Admin Directory access in a dedicated Workspace tenant; supply OAuth renewal as needed and validate Google consent/scopes.
3. Start worker; confirm complete inventory and ACL/directory cursors are healthy, then ensure Guard downloads bundle v0.1.1 and installs policy.
4. Run verified Alice/Bob RAG tests, revoke Drive direct and group grants and record source, policy and Guard enforcement timestamps; check failure modes.
5. Test full frontend/backend/worker staging stack, customer onboarding and production safeguards, then deploy in a reviewed window with rollback available.

**No live migration or production deployment was executed in this session.**

## Follow-up hardening audit — 2026-10-19

The release candidate was re-audited after the original gate. The following
additional fail-closed behaviour is now implemented and covered by focused
regression tests:

1. Empty group permissions persist as durable group grants. A user added to an
   existing group after its Drive ACL has been observed can now receive the
   group-derived authorization through the normal membership event path.
2. Expired, deleted, malformed-expiry, and non-reading Drive permissions are
   ignored as authorization inputs. A stale read allow cannot remain because an
   expired permission was treated as a normal permission record.
3. Drive shortcuts under the approved root are ignored. Their target can be
   outside the root and has independent ACL semantics, so V1 does not make an
   unsafe inference from the shortcut.
4. The configured Drive root must be a folder. Test resource moves between
   My Drive and Shared Drives are rejected, including a move where only one
   side exposes a Drive ID.
5. A bounded change-feed pass that stops at its page cap stores its continuation
   but reports `catching_up` / `ACL_SYNC_BACKLOG`, not a healthy source.
6. Test setup isolates itself from any locally enrolled Guard credential file;
   unit tests cannot contact a developer or customer control plane by accident.

Focused local validation on 2026-10-19: 31 Google Drive, directory, ACL,
Guard-cache, and RAG SDK tests passed; Ruff, Mypy, and Python compilation for
the changed code passed. A fresh SQLite database was migrated from base to
Alembic head `c2d4e6f8a0b1`. These results do not replace the P0 real-provider
validation gates above.
