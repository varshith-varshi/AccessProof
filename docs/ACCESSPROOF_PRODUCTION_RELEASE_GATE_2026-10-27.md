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
   volume as **unencrypted**, ~2.3 GB free disk after deleting obsolete unused Docker images, and its
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

## Post-release verification update

- Production API and worker upgraded to the pinned multitenant release images.
- Public API health and login page HTTP 200, desktop/mobile login forms and protected-route redirects verified in real Chromium with no page JS errors.
- Production PostgreSQL schema is now at `n7a2b4c6d801`.
- Removed unused retired Live Validation frontend images and obsolete legacy frontend image: EC2 free space improved to approximately 2.3 GB (88% full).
- Local release Git commits: `2aeb390` and `b0cc470`. HTTPS push timed out; remote branch publication is not confirmed.
- An activation helper is staged at `/home/ubuntu/accessproof/releases/activate_accessproof_microsoft_aws.py`. It requires the operator to install the existing 0600 JSON credential file through an approved channel; the assistant did not transfer it or execute the helper.

**Final status remains: multitenant backend deployed; Microsoft customer authorization and RAG protection certification blocked pending server-side credential activation and genuine employee sign-in/protection tests.**
