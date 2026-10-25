# AccessProof V1 — Guard/Adapter hardening report (2026-10-18)

Scope: local source hardening of the existing AccessProof f15 repository and web-v2. This report is a release-readiness record, **not** a production-deployed certification. No production infrastructure, customer data, source access tokens, or enrollment credentials were changed.

## Corrected engineering issues
- Legacy Guard CLI regression test updated for the extracted `onboarding.py` implementation.
- Browser and CLI Guard enrollment require a trusted HTTPS OIDC issuer and non-empty JWT audience **before** consuming the one-time bootstrap token. The enrollment record cannot silently overwrite an existing Guard identity and tenant cache.
- Legacy `drive-rag-demo /v1/chat` ACL-cache simulator is disabled by default. It may only be explicitly enabled in isolated development. The guarded `/v1/protected-chat` endpoint uses Python SDK Layer 1 filtering and Layer 2 provenance verification.
- Customer-side Guard bundles can be downloaded from `GET /api/v1/guards/download` by authenticated organization admins; web-v2 Guard onboarding links to this route. `scripts/build-guard-package.sh` generates the checksum and stages the release in `packaging/guard/releases` before API Docker builds.
- Bundle contains only Guard runtime and customer-facing Python RAG SDK, not the unrelated control-plane backend. The Guard binary distribution is still Python source, and is not tamper-proof or IP-hidden.
- Guard policy sync installs policy decisions before updating application bindings; stale policy responses cannot change binding modes.
- Protect activation proceeds from Shadow to `protect_pending`, then to `protect` only after machine-authenticated Guard heartbeat reports the actual installed Protect mode. Guard data-plane evaluates per-application policy bindings and fails closed on stale policy synchronization.
- Readiness verification no longer accepts simple checkboxes. The admin must provide distinct, recent, Guard-machine-authenticated request evidence for authorized Layer 1+Layer 2 flow, denied Layer 1, and Layer 2 provenance rejection, and explicitly attest a real RAG output-buffering test. The attestation itself is **not** cryptographic proof of how every customer RAG request behaves.
- Shadow-mode provenance failures now remain `would_block` rather than denying release.

## Verification performed
- Full backend regression suite: **234 tests passed** with ROS's conflicting automatic pytest plugin disabled and pytest-asyncio explicitly enabled.
- Focused hardening API/Guard tests: passed, including authenticated installer delivery, evidence-backed readiness, Shadow behavior, existing-state overwrite rejection and Guard Protect heartbeat acknowledgement.
- TypeScript SDK: **2 tests passed** with the existing frontend-installed TypeScript compiler.
- web-v2: ESLint and production Next.js build passed.
- Playwright desktop/mobile: **19 passed, 1 skipped**; additional Guard download-link browser regression: passed.
- Guard release archive: checksum passes. Docker built and served Guard setup and health successfully using a temporary isolated container; it was removed.
- Alembic disposable SQLite migration: upgrade to current head `c2d4e6f8a0b1` succeeded.
- Local Docker Compose configuration: parsed successfully.

## Strictly outstanding before a commercial production pilot
1. Deploy the reviewed image and migrations to staging first with database backup and rollback rehearsal. Production AWS EC2 SSH/SSM access was previously unavailable; it was **not restored or tested here**. The live website/API remain on their prior deployment.
2. Real Google Drive source authorization and OIDC/JWKS validation with dedicated Alice/Bob test identities and actual signed employee JWTs. Perform a real permission revoke and prove no unauthorized document reaches the model before generation, and no unauthorized answer leaves the buffering boundary.
3. A complete real customer RAG integration test, including actual framework version mapping, application-managed output buffering, token audience/subject mapping, cached/group/inherited ACL handling, and Guard stale-policy behavior under network interruption.
4. Customer-side SDK versioned distribution, platform installer signing, dedicated Guard networking, credentials rotation, operational backup/monitoring and support runbooks remain release/operations tasks. The TypeScript package is private/unpublished. Framework-specific adapters remain beta pending real version certification.
5. Layer 2 checks **structured trusted resource provenance**; it is not a general semantic leak detector or arbitrary response-content classifier. Do not advertise broader coverage.
6. The original exposed one-time Guard token must be revoked; generate a new token only when ready to enroll the customer-side Guard.

## Predeployment commands (only after backup and proper AWS access)
```bash
bash scripts/build-guard-package.sh
docker compose -f docker-compose.ec2.yml build api worker web
# After staged DB backup and migration review, deploy:
alembic upgrade head
docker compose -f docker-compose.ec2.yml up -d api worker web
```

Never run these migration/deployment commands against a production database without a verified backup, reviewed diff, and authorized release window. Do not treat an HTTP 200 health endpoint as proof of policy readiness: the local prior Guard returned policy_version=0, ready=false.


## Continued review and fixes (late 2026-10-18)

- The API refuses to acknowledge `protect_pending` as fully active on a Guard
  heartbeat with policy version zero, degraded health, or reported degraded
  conditions. Tests prove both negative cases and the healthy acknowledgment.
- Added an in-process end-to-end test using actual customer-side Guard Layer 1
  and Layer 2 endpoints, a protected RAG demo endpoint, synthetic JWT-bearing
  Alice/Bob identities, and versioned effective-access decisions. Alice sees
  permitted content initially; Bob is denied; after revocation Alice is denied.
  This is **not** a live Google Drive or live OIDC test.
- Guard Layer 2 now rechecks the current source permission for each resource
  from its Layer 1 decision context when Protect is active, preventing an
  already-generated answer from being released if access is revoked during
  generation or a Shadow request crosses an activation boundary.
- Web-v2 Applications now has a guided test-evidence submission form with three
  distinct Guard request IDs and the mandatory explicit response-buffering
  attestation; it displays actionable API verification errors. Its desktop and
  mobile UI test succeeds.
- Customer-side Guard heartbeats report `degraded` when the machine has not yet
  installed or synchronized any effective-access policy, instead of reporting
  an unready Guard as healthy.
- Rebuild the Guard package **after all Guard source changes**. The
  versioned release archive is staged in `packaging/guard/releases` and has
  a SHA-256 sidecar. The archive is not cryptographically signed.
- The web-v2 frontend and API work together with the existing worker service;
  deploy **api + worker + web** in a controlled window, not only api + web.

Reminder: a successful end-to-end *synthetic* test cannot replace actual
Google Drive ACL propagation, account/group identity mapping, real IdP JWKS,
SSRF review, customer RAG model buffering and cloud infrastructure staging.
