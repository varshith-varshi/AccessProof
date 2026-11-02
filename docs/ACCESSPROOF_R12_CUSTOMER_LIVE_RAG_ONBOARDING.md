# AccessProof r12 — customer-first live RAG onboarding

## Product experience

- Step 1: Connect SharePoint and synchronize permissions.
- Step 2: Install and pair customer-side Gateway.
- Step 3: Test the existing real RAG with actual employee identities:
  enter the employee-facing URL, ask allowed and denied document questions,
  review independently recorded Layer 1/Layer 2 Guard decisions,
  generate a machine-authenticated reference Gateway challenge,
  and review production protection status before approved cutover.
- The customer-facing setup page **no longer renders** the 23 internal
  certification checks, the 14/23 progress counter, a raw failed-check list,
  or the old preflight checklist blocking the security-challenge button.
- A customer may request a short-lived challenge before source certification;
  this is read-only verification of a test route and never enables Protect.
- The UI does not store customers' RAG URLs or credentials. It opens only
  HTTPS destinations or HTTP loopback addresses, in a separate browser tab.
- Real evidence and source cutover approval continue to be verified by the
  production API, not by client claims or checkboxes.

## Deliberately unchanged safeguards

- All backend security requirements, Microsoft consent, Guard fail-closed
  policy and 3-second presence timeout remain intact.
- Route challenges still demand machine-attested real Gateway outcomes matched
  with signed Guard audit events. Starting a test creates a nonce, not a permit.
- Production Protect activation remains subject to independent source/route
  certification and explicit customer-approved cutover.
- The new screen never counts a heartbeat, manual answer or simulated test as
  proof of actual security authorization.
- The current Guard may be DEGRADED while Microsoft identity/source evidence
  is incomplete. In that state, even authorized positive RAG tests may fail
  closed; the UI must display the actual result, not silently bypass it.

## Validation

- Web ESLint and TypeScript typecheck succeeded.
- Next.js production build succeeded.
- Playwright full suite: 47 passed, 5 skipped (desktop/mobile).
- Explicit browser test: challenge issuance while source readiness is still
  pending never calls POST /protection/enable.
- Explicit browser test: internal 23-check customer checklist absent.
- Browser safety test: reject javascript: and credentialed URLs.

## Release

Website-only image; no API schema, worker, Guard, Gateway or authorization
policy changes. Preserve the previous r11 frontend image and .env for rollback.

## Production verification — November 2, 2026

- **Deployed image:** `accessproof/web-v2:customer-rag-r12-20261102`.
- **Deployment host:** AWS EC2 `i-0c11427d4d9c1b438` in `eu-north-1`;
  AWS Systems Manager SendCommand used; no SSH/firewall changes.
- **Rollout:** website only, via Docker Compose `--no-deps --force-recreate web`.
  Existing r11 API and worker images were not changed or restarted.
- **Image checksum:** Docker image identifier
  `sha256:eae48d5e4e43c689b7c57d07063432b1b6a8b6b7881013d5acb126e196d4e94d`.
- **Source checksum:** onboard page
  `f61c62c511042b0144344616418553f6510f56bbb4e4db3a69746b8b3c3db527`;
  onboarding stylesheet
  `41ced5434ca57dd98b41f98c505c03f60f0beb56aecb6c149a670c9762689110`.
- **Release and rollback:** `/home/ubuntu/accessproof-releases/customer-rag-r12-20261102/`;
  previous r11 frontend image retained, previous .env stored at
  `rollback/.env.before-r12` (restricted permissions).
- **Verified:** live frontend container healthy, Next.js compiled bundle contains
  “Test protection in your RAG”; public login HTTP 200 and API readiness HTTP 200.
- **Protect remains blocked:** live source verdict `protect_pending`,
  `certificate_verified=false`, `safe_to_enable_protect=false`.
  Nine security prerequisites still independently require evidence.
- **Capacity:** reclaimed 649.6 MB by pruning only old, unused Docker build
  cache. Live and r11 rollback images retained. Host now approximately
  94% used with 1.2 GB free. Expand the EBS root disk before major new
  production builds.
- **Tests:** ESLint/typecheck/production build passed;
  complete Playwright suite 47 passed / 5 skipped.
- **Scope:** Removing the confusing 23-check UI is **not** removing security
  checks from the backend or treating manual RAG answers as certification.
