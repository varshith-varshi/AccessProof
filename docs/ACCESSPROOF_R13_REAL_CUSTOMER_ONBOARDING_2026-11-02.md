# AccessProof r13: real customer onboarding decisions and implementation

## The actual customer journey

1. **Authorize SharePoint** through Microsoft-hosted administrator consent.
   AccessProof checks the configured source and directory/ACL sync. Microsoft
   consent or site permission grants are never silently bypassed.
2. **Connect a compatible Docker RAG.** The RAG application owner registers
   the application, binds its source and enrolled Guard, downloads the official
   Gateway installer and a short-lived pairing file, and runs the installer
   from their real Compose project. An already paired Gateway is recognized
   without reinstalling. Customer RAG source code may require a supported
   signed-retrieval/identity-forwarding/buffered-answer adapter; the current
   installer cannot automatically make arbitrary uninstrumented RAGs secure.
   The original RAG keeps its private Docker networking and no production
   employee cutover occurs as a side effect of setup.
3. **Test the existing RAG.** The customer opens their own RAG interface,
   using normal Microsoft SSO, and runs agreed allow/deny questions against
   synthetic documents. AccessProof does NOT ask for its URL, host its chat,
   or solicit identity tokens. The user can start a temporary browser-only
   observation of real backend Guard decision counters while using the RAG;
   the view polls the server every five seconds. Only the backend audit and
   authenticated route tests can establish security proof. The 24-hour
   aggregate diagnostic counters may include other employee traffic and are
   never themselves certified evidence.
4. **Review and approve production cutover.** Only after the backend verifies
   independently signed/expiring source and route evidence does an
   administrator explicitly authorize employee route changes. The onboarding
   UI cannot force Protect or bypass the API and Guard.

## What r13 fixes versus r12

- Removed the redundant RAG URL input and cloud 'Open my RAG' link.
- Removed 'Generate live Gateway challenge' that was a dead end for an adopted
  existing Gateway because the currently downloaded request_ids-only challenge
  cannot be executed by the legacy zipapp verifier. No fake success path.
- Preserves straightforward one-time Gateway pairing, no reinstallation for
  already installed Gateways; explains adapter/Guard/source setup honestly.
- Displays actual Guard connected/readiness/backend protection status.
- Provides real decision-observation controls using current production
  decision telemetry, with a baseline sample, five-second refresh and
  explicit diagnostics-only labels.
- Removed manual internal 23-check status and certification jargon from
  customer onboarding, not the backend security policy.
- Separate links to Guard audits, denied requests, and real protection
  certification/status. No customer source passwords, token fields or
  arbitrary public RAG URLs required.
- When no RAG is bound, guides to existing application and Guard registration
  rather than presenting a broken installer form.

## Scope and technical limitations

- r13 is a **website-only** customer UX and evidence-view release. It is
  NOT a zero-config adapter for every pipeline and does not implement a
  cross-network executable customer-side challenge runner.
- Current reference SDK/challenge route has existing-Gateway adoption gaps.
  Until a supported local agent can execute the certified challenge, the UI
  does not advertise it as one click.
- The customer does not manually 'certify' protection. Backend production
  Protect remains fail-closed while the real SharePoint source, OIDC,
  Layer-1/Layer-2, provenance, buffering, and route cutover evidence is
  missing. A Guardian heartbeat or a manually allowed chat answer is not
  sufficient proof.
- A production-ready **fully automated test agent** is separate engineering
  work requiring a secure customer-side executor, scoped machine-authenticated
  enrollment, signed provider test fixtures, independent Guard audits and
  customer approval for tests that change ACLs. Not represented as delivered.
- EBS root storage must be expanded before substantial further builds.

## Tests

- ESLint and TypeScript: passed.
- Next.js production build: passed.
- Complete desktop/mobile Playwright suite: 45 passed, 5 skipped.
- Tests assert: no RAG URL or dead challenge action; one-time setup with
  truthful compatibility requirements; observed backend telemetry deltas;
  no POST /protection/enable when observing; no false 3/3 result.

## Verified production rollout (2026-11-02)

- AWS SSM instance `i-0c11427d4d9c1b438` in `eu-north-1`.
- Website image: `accessproof/web-v2:real-customer-rag-r13-20261102`,
  image digest `sha256:6949224e705ddd25bcf65bfdb215023d6d0ca9d89a679e85b74930726aff9b80`.
- Running API: `accessproof/api:verification-r11-20261101` healthy.
- Running worker: `accessproof/worker:verification-r11-20261101` running.
- Compiled production Next.js page includes
  `Start observing test requests`; public API ready and website login
  both returned HTTP 200.
- Current SharePoint application is `protect_pending`,
  `certificate_verified=false`, and `safe_to_enable_protect=false`.
  The established nine remaining backend checks still block live Protect.
- Previous r12 image and `.env` backup are retained for rollback at
  `/home/ubuntu/accessproof-releases/real-customer-rag-r13-20261102/rollback/`.
- Source hashes (independently matched AWS staging):
  page `5debfc09c3380141dc0d9967d3dea0f0ad6435f8b95424ea6b3128f8eefe4a18`;
  CSS `340b6181769780b054c9bfb70e782f7b6962f6320df966052f8e2b92348b64fa`.
- Disk remains approximately 96% full, 935 MB free. Pruning unused
  build cache older than one hour freed 0 bytes; do not delete live or
  rollback images. Increase EBS storage before further image-intensive work.
- Full Playwright regression 45 passed/5 skipped, production web build and
  lint/typecheck passed. The frontend test suite uses synthetic fixtures,
  and is not independent live provider certification.
