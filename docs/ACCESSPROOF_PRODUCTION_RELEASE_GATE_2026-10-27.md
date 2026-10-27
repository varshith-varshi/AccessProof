# AccessProof production release gate — 27 October 2026

**Release classification: BACKEND DEPLOYED, SHAREPOINT PROTECTION NOT RELEASE-READY.**

## Deployed and independently checked

- Public app: `https://app.accessproof.in`
- Public API: `https://api.accessproof.in`
- API image: `accessproof/api:multitenant-20261027-r1`
- Worker image: `accessproof/worker:multitenant-20261027-r1`
- Frontend image: `accessproof/web-v2:multitenant-consent-ui-20261027`
- Production Alembic revision: `n7a2b4c6d801`
- Verified pre-upgrade production `pg_dump -Fc`:
  `/home/ubuntu/accessproof/backups/multitenant-20261027/pre-migration.dump` (mode 0600; pg_restore archive list verified).
- Pre-upgrade API/worker image IDs and Compose/environment backups are in
  `/home/ubuntu/accessproof/backups/multitenant-20261027/`.
- Migrated a separate restored copy of this production backup on AWS with the
  staged API image before the live upgrade. Two existing AI application rows
  were present before/after the rehearsal. This was not an empty-schema test.
- Live API+worker deployed after migration and passed health check; initial
  error scan found no API/worker exceptions.
- Web and API public smoke: login HTTP 200, API ready HTTP 200 with DB/Redis
  ready, anonymous Sources API and Microsoft readiness API HTTP 401. Desktop
  and mobile Playwright confirmed rendered email/password form, protected
  Sources redirect to login, and zero JavaScript page errors.
- Extended release-critical tests for authenticated customer lifecycle,
  Guard, Gateway, Microsoft admin-consent state, source scopes, RLS and
  fail-closed behavior passed. A separate suite of 25 Microsoft/SharePoint
  tests passed; earlier browser suite: 39 passed, 5 intentionally skipped.
  These are synthetic tests except where stated otherwise.
- One NeuralMatrix operator-owned multitenant Microsoft Entra app:
  `b8424d54-5428-4d35-ae2c-639de7e512a9`. Operator tenant Graph roles
  Sites.Selected, User.Read.All and Group.Read.All were granted and checked.
- A dedicated synthetic SharePoint site:
  `https://neuralmatrix093.sharepoint.com/sites/AccessProof-Validation-20261027`.
  The AccessProof app's *read-only selected-site* grant was checked via Graph.
  Temporary administrative service principal/app were deleted after granting.
- Three synthetic test documents have Alice-only, Bob-only, and shared
  SharePoint file-level read grants. Graph permission inventories were read
  back; employee-effective source-denial was **not** proven.

## Outstanding hard blockers

1. **Microsoft app credential not installed in AWS.** The client ID is
   configured. The 90-day client secret is retained in the Ubuntu machine's
   owner-only `~/.config/accessproof/entra-client-secret.json`. Credential
   transfer through the assistant tool was blocked by security checks.
   The production Sources UI correctly reports Microsoft consent unavailable
   rather than permitting an unauthenticated source to become Protect-ready.
   Do not print or paste this secret into chats or Git.
2. **Real end-to-end SharePoint customer onboarding not passed.**
   Actual tenant administrator consent callback, app-only Graph token in the
   production API/worker, selected-site source validation, fresh ACL/directory
   sync and eligible Guard RAG-route evidence remain unverified.
3. **Live employee-effective security test not passed.** Alice/Bob Entra OIDC
   browser sign-in, delegated SharePoint 200/403 checks, Guard per-principal
   allow/deny, cache invalidation after source revoke, negative controls and
   signed leak-window/SLO results must all be tested independently.
4. **AWS production hardening gaps.** AWS Core reported the instance root EBS
   volume as **unencrypted**, only ~1.3 GB free disk after cleanup, and its
   current AWS management connection uses root-account credentials. There is
   no EC2 instance profile. Change to least-privilege IAM and encrypted
   storage in a controlled maintenance plan before an enterprise GA claim.
5. **Broader certification incomplete.** Real Microsoft effective ACL for
   nested group/inheritance/link permissions, multi-tenant customer setup,
   real cache routes and arbitrary enterprise RAG integration remain
   unproven. SharePoint Protect must remain Shadow-only.

## Release/rollback instructions

The currently running API and worker images are pinned by
`ACCESSPROOF_API_IMAGE`/`ACCESSPROOF_WORKER_IMAGE` in the owner-only
`/home/ubuntu/accessproof/.env` and `docker-compose.ec2.yml`.
Do not use `docker compose up --build` against an outdated EC2 checkout.
If the new API is unhealthy, restore the old image pins using the saved
`api.before-image-id` and `worker.before-image-id` and recreate only those
services with `--no-build`. Schema downgrade is not automatic:
`n7a2b4c6d801` includes new tenant-RLS tables and downgrade restrictions.
For database recovery, first stop API/worker and use the verified pre-migration
archive during a controlled outage; never overwrite live data casually.

**No security certification is implied by HTTP 200 health or by Graph
consent/grant success.** Final GA/protection activation requires actual
authorization and revocation evidence.
