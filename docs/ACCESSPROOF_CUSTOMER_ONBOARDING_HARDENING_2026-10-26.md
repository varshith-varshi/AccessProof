# AccessProof customer onboarding hardening — 2026-10-26

## Status and scope

Code changes were made in the existing `f15` repository without resetting other
uncommitted work. **Not deployed**. **Not certified in a live Google Workspace tenant**.
No OAuth credentials were created or uploaded; do not paste customer/provider
secrets into a chat, browser console, or source-control repository.

This addresses customer-facing friction without pretending that an arbitrary
enterprise RAG can be connected without an authorized integration step.

## Fixed in code

1. **Missing operator-owned Google OAuth credentials:** New authenticated
   `GET /api/v1/current/sources/google-oauth/status` reports configuration
   availability without returning secrets. The UI checks it *before* creating
   a tokenless OAuth draft; when unavailable it explains that AccessProof's
   operator must configure the backend. Customer never supplies the
   NeuralMatrix OAuth application's client secret.
2. **Same failure for Microsoft admin consent:** An equivalent status endpoint
   prevents tokenless Microsoft draft creation when operator setup is absent.
   Microsoft 365/SharePoint/OneDrive remain preview/Shadow only.
3. **Manual credential entry exposed as the default:** Hidden inside
   an explicitly labeled advanced section for approved pilots. Standard
   onboarding uses provider-hosted OAuth consent.
4. **Manual Google employee sync immediately after consent:** Google OAuth
   callback now returns a source-scoped nonsecret identifier. The authenticated
   frontend consumes the one-time callback URL and invokes directory sync;
   result counts and failures are displayed. Retries are still operator/user
   initiated; see production limitations below.
5. **Unclear connection vs authorization readiness:** Source list now reports
   separate, source-scoped directory and Drive ACL synchronization status,
   freshness, last successful sync, and error code. Connection state alone is
   not shown as a sufficient Protect criterion.
6. **Guard trust of stale healthy-looking Google cursors:** Machine policy
   source health now also checks validated source status and decrypted
   root-bound access-token presence. A degraded/disconnected/credentialless
   Google source returns `source_acl_healthy=false`, even if sync cursors
   look recent. Activation preflight also checks the root-bound credential.
7. **Invalid Guard authorization revision installed after an ALLOW policy:**
   Revision and identity-mapping snapshot preflight runs before installing
   new policy decisions. The Guard sends an `installed` ACK only after
   policy, revision, binding and mapping update calls complete.
   This is **not** a guarantee of fully transactional multi-table installation;
   see remaining limitations.

## Operator-only setup (legitimate backend secrets, not customer onboarding)

- Register a verified OAuth Web application controlled by the AccessProof
  service operator. Configure backend secrets securely:
  `ACCESSPROOF_GOOGLE_OAUTH_CLIENT_ID` and
  `ACCESSPROOF_GOOGLE_OAUTH_CLIENT_SECRET`.
- Confirm the exact deployed callback matches
  `https://api.accessproof.in/api/v1/current/sources/google-oauth/callback`.
- Enable Google Drive API and Admin SDK API, and obtain appropriate Google
  Workspace administrator approval for the requested read-only scopes:
  `drive.readonly`, `admin.directory.user.readonly`,
  `admin.directory.group.readonly`, and
  `admin.directory.group.member.readonly`.
- Deploy code and backend configuration through a controlled release; record
  its artifact hash, run migrations if needed, and perform a rollback rehearsal.
- On first authorization, confirm fresh directory and ACL sync and real
  employee identity mapping before a Shadow/Protect evaluation.

## Important remaining limitations (not fixed, do not claim complete)

**P0 / release gates**

- There is no live production-equivalent Google Workspace validation
  of admin consent, real employee/group users, inherited/shared-drive Drive
  permissions, revocations, and customer RAG identities. Synthetic/mock
  tests are not equivalent.
- Google OAuth still needs an actual Google Cloud client configured by
  NeuralMatrix's deployment operator; it cannot be conjured in application
  code. An unconfigured deployed API will correctly show "not configured."
- Directory auto-sync currently runs on the frontend after OAuth callback,
  not a durable queued server-side worker with resumable retries. Large
  enterprise directories and browser/navigation failures need robust job
  orchestration and idempotent retry.
- Source ACL ingestion/reconciliation remains a separate provider worker
  lifecycle. Successful directory sync is **not** full document permission
  certification. Protect needs fresh ACL, directory, Guard, and route evidence.
- Existing deployed Guard instances need updated runtime code and fresh
  authenticated policy synchronization to benefit from revised fail-closed
  behavior. Existing signed policy snapshots must not be assumed safe.
- Machine policy cache update steps are still separate SQLite transactions.
  Preflight catches malformed revision/mapping envelopes, but a crash or
  database failure between writes can leave partial state. Implement an
  atomic complete-snapshot transaction and test recovery before claiming
  full transactional Guard certification.

**P1 / customer-experience and commercial gaps**

- The customer RAG route still requires authorized SDK/Gateway/Guard
  installation and real integration evidence. There is no universal
  zero-change/one-click connection to arbitrary third-party RAG pipelines.
- Guard installation requires a customer-side execution environment and
  verified identity issuer/audience. It should not require a human user to
  upload service-operator secrets.
- Microsoft effective permissions and site/library inherited ACLs still need
  independent production-equivalent verification before Protect can be sold.
- Google OAuth consent/verification scope approval may be required before
  broad external use; a development or testing OAuth client is not sufficient.
- There is no proof yet of sustained sync/revocation time under customer
  load, production change-channel recovery, full provenance integrity, and
  safe failure during network outages.

## Validation

Focused backend tests include Google source OAuth, Microsoft consent,
directory adapters, guard policy/authorization revisions, preflight,
source policy health and readiness. Frontend TypeScript, Next.js build,
and browser tests validate the UI behavior. Test outcomes must be
rechecked on the release artifact and in an authorized staging environment.

## Go/no-go

- **Demo/Shadow on synthetic data:** after environment verification, appropriate.
- **External customer staging pilot:** only with written consent, scope, tested
  safeguards, and transparent unresolved limitations.
- **Production Protect certification:** **NO-GO** pending the remaining P0
  release gates and genuine provider/integration proof.
