# NeuralMatrix AccessProof — customer onboarding hardening

Date: 2026-11-05. Branch: `claude/universal-rag`. The changes are designed to preserve Protect fail-closed behavior and require a reviewed deployment.

## Implemented

- Source form uses a specific two-column grid (one-column on narrow screens) and full-row security notices and action buttons; no overlapping fields.
- Source table uses a pinned, wrap-capable action column so Validate, reauthorize, sync and disconnect remain reachable at desktop widths.
- Discovered chatbot picker uses a two-column grid that preserves the chatbot name rather than a third `max-content` badge column stealing available width.
- The source UI no longer labels all Microsoft connections `Shadow` regardless of their actual application-level Protect state; certification is always checked on the application separately.
- The site-grant-required state is explicit. Consent is not falsely marked `Connected` or lost when a site grant must follow tenant consent.
- AI Applications includes a typed, signed-in OWNER-only Protect approval step backed by the existing `/protection/approve` API. Backend checks and Guard acknowledgment are unchanged; non-owners see instructions, not an approval button.
- Source security grant documentation now distinguishes `Sites.Selected`, the explicit named-site grant, and the elevated `fullcontrol` role needed in existing lab certification evidence. It does not silently request tenant-wide privileges.
- Customer documentation identifies the `accessproof-rag` PyPI publication gap, the remote-host certification requirement, and the current limits of self-service.

## Verification

- Frontend TypeScript: `npm run typecheck`.
- Frontend lint: `npm run lint`.
- Browser E2E: `npx playwright test e2e/onboarding-hardening.spec.ts e2e/onboarding-source-parity.spec.ts` — 26 passed across desktop and mobile, including five added regression scenarios.
- **Full frontend suite:** `npx playwright test --workers=2` — **109 passed, 5 skipped, 0 failures** across desktop and mobile (2026-11-05). Existing Google provider tests were updated to select Google explicitly; current UI defaults to SharePoint. Existing site-grant tests now assert the distinct `Site grant required` state instead of the obsolete Shadow-only wording.
- Customer onboarding PDF: newly generated, **11 A4 pages**; text extracted and critical pages visually rendered/checked. Guide source: `scripts/build_customer_onboarding_guide.py`.
- Backend test suites: `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest tests/integration/test_microsoft_admin_consent.py tests/security/test_human_activation_approval_d28.py -q` — 11 passed.
- Client wheel built and import-smoke-tested, staged for an authenticated website download after deployment. Package `accessproof_rag-0.1.0-py3-none-any.whl` is **not on PyPI**. SHA-256: `ce72587503532202add008990e59fbf2a9c1c23e3740e1a4be3fac4b37235072`. Framework extras are installed separately. Customer download has to be tested with a real server-validated account after deployment.

## Not certified by this report

- A complete independent Microsoft customer tenant walkthrough, production client ID, support email deliverability, Gateway download on an authenticated production session, and remote RAG host certification without agreed technical assistance.
- New UI production deployment, source-site privilege reduction or customer authorization. Do not claim these as complete based solely on branch tests.

## Release restrictions

The production role `accessproof-certifier` is intentionally scoped to approved read-only and certificate/route SSM documents. It is **not** a general deployment role and cannot upload a Git archive to S3 or invoke `AWS-RunShellScript`. Do not fall back to the AWS root login or broaden this role to ship the UI. Deployment requires an explicitly authorized, separate least-privilege release mechanism, pre-deploy DB/image backup, rollback proof and post-release checks. Current production Protect settings must remain unchanged.

## Follow-up security finding: customer ZIP session bypass (fixed in branch)

An unauthenticated request to `https://app.accessproof.in/downloads/accessproof-gateway-connector.zip` correctly redirected to login, but an **arbitrary invalid `accessproof_session` cookie** returned HTTP 200 with `Content-Type: application/zip` and a roughly 98 MB ZIP (observed 2026-11-05). The existing `web-v2/proxy.ts` only checked whether the cookie was present. It did **not** verify the session before serving customer installer assets.

Patch: only for `/downloads` paths, the Next.js proxy now checks the existing server-side `/api/v1/auth/me` API using the cookie and active organization, refuses 401/403, refuses API outages with HTTP 503, and adds private/no-store caching. No password or AWS credentials are sent to the browser. Direct tests cover missing cookie, invalid cookie, valid API-verified session, and fail-closed outages in `e2e/download-auth.spec.ts`. The download path additionally sets private, no-store response headers through both Next configuration and the proxy. This does not change the security gates governing Protect.

**Release-critical:** The currently deployed production ZIP remains accessible using a fabricated session cookie until a reviewed new web release is deployed. The ZIP is documented as containing no embedded credentials, but its authorization boundary remains incorrect in production. Do not mark this issue resolved for customers merely because the branch fix passed local tests.

## Additional Guard and SDK corrections

- Customer-side Guard setup UI no longer says the internal release name `web-v2`; it refers to the **AccessProof dashboard**.
- The stable subject-claim form now automatically suggests `oid` for Microsoft Entra issuers (`login.microsoftonline.com` or `.us`), without overwriting a claim manually chosen by a customer administrator. Generic OIDC remains `sub` by default.
- The advanced Python RAG SDK is packaged as a 14,167-byte source-built wheel and verified by a local offline pip install/import smoke test. It is staged in `web-v2/public/downloads` for the next reviewed web release. It is **not** published on PyPI.
- The current live Gateway connector ZIP was retrieved read-only and successfully ZIP-CRC checked: 97,946,971 bytes, 27 members, published SHA-256 `91a7c7d421316e882fe15003c8023bc4cc50de88cef9c6913c98cb887ae3df9a`. No suspicious credential-shaped filenames were seen at the ZIP entry level. This does not prove the nested container runtime has no embedded secrets.
- Microsoft Entra production client ID and actual support inbox deliverability still require authorized operational review; DNS MX records alone do not verify that mail is being received.

## Release preflight: preserve the actual customer Gateway installer

The public production Gateway connector ZIP is 97,946,971 bytes. It is deliberately absent from Git's small release artifact. Previously `deploy/ec2-release/deploy_on_ec2.sh` built a new web image solely from `web-v2/public`, silently dropping that ZIP. The release preflight now copies the ZIP **read-only from the previous running web container**, verifies its reviewed SHA-256 `91a7c7d421316e882fe15003c8023bc4cc50de88cef9c6913c98cb887ae3df9a` and ZIP CRC/required entries **before building or migrating**, and refuses release if the asset is missing or changed. It verifies the installed ZIP in the new web container and rejects a fake session-cookie download after cutover. The tar/CI artifact still excludes the 98 MB binary. `PUBLIC_CHECKS=0` rehearsals skip the production asset-preservation requirement.

A no-op Alembic upgrade now leaves `MIGRATED=0` so a failed web-only/code-only rollout will not incorrectly enter a database downgrade and Ed25519 certificate guard. Seven offline release-preflight tests cover success, checksum mismatch, corrupt archive, missing archive, rehearsal skip, script syntax, and no-op migration semantics. The full EC2 release script itself has **not** been run against production under this branch.

## Final release-candidate checks

- Full frontend: **109 passed, 5 skipped** (2026-11-05); Next build, TypeScript and ESLint pass.
- Actual local Next HTTP download route with a simulated auth API: **4/4 PASS**: valid session yields wheel SHA-256 match and `private, no-store`, fake and absent session cookies are blocked with HTTP 307, and API outage fails closed with HTTP 503.
- Guard onboarding unit tests: **6 passed**. Release preflight and no-op migration tests: **7 passed**.
- Final combined backend/security run: **24 passed, 0 failed**, exit code 0 — Microsoft consent, Owner approval, Guard enrollment UI and release-asset preservation/rollback tests (2026-11-05).
- **Production release not performed**: the installed `accessproof-certifier` and `accessproof-staging-tunnel` Roles Anywhere identities cannot deploy and must not be broadened to do so. A separately authorized least-privilege release role / secure deploy workflow is needed. This report does not authorize root-account deployment or weakening of existing Protect.

## Final release-candidate checks (2026-11-05)

- Frontend TypeScript and ESLint: **PASS**.
- Complete Playwright desktop/mobile suite: **109 passed, 5 skipped, 0 failed** (114 collected).
- Targeted backend tests (Guard setup, Microsoft admin consent, Owner approval, release installer preservation): **24 passed**.
- `deploy/ec2-release/deploy_on_ec2.sh` shell syntax and `git diff --check` (excluding binary PDF) both passed.
- Actual **built Next standalone server** served the correct SDK wheel with valid organization session and `Cache-Control: private, no-store`; fabricated or missing cookies redirected; API failure returned HTTP 503. All smoke conditions passed against a local synthetic auth API. This is not a live production deployment test.
- The offline ZIP-preservation release helper refuses absent, modified or corrupt installer artifacts and correctly passes an intact pinned installer. Production deploys will fail closed if the running web image does not contain the reviewed ZIP or its checksum has changed.

### Release boundaries and pending operational verification

1. **Production web deployment still pending.** Existing production installer downloads are reachable with an arbitrary cookie value; the new Next session gate is not deployed. Do not tell customers that this production flaw is fixed.
2. **Guard setup UI is a separate customer-side runtime.** The source code now names the dashboard and suggests Entra `oid`, but currently installed customer Guard containers and the existing archived installer are not modified by a website-only release. A reviewed Guard/runtime installer refresh and acceptance test are still required before calling this live for customers.
3. The dedicated `accessproof-certifier` IAM Roles Anywhere identity is intentionally **not** allowed to deploy applications or run general shell commands. Do **not** expand its SSM rights or use root to bypass the deployment gate. A separately authorized scoped release identity and safe rehearsal/rollback are prerequisites for shipping this web release.
4. The currently deployed Gateway ZIP has a verified binary SHA-256 (`91a7c7d421316e882fe15003c8023bc4cc50de88cef9c6913c98cb887ae3df9a`), which the production deploy script now pins and preserves from the previous running web container. The ZIP must still be audited more deeply before customer shipping, and the release itself must verify archive availability on the authenticated live web route.
5. Real tenant SharePoint selected-site permission acceptance, Entra production client ID, support email deliverability and actual customer RAG challenge remain **not yet independently validated by this branch**.
