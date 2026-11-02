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
