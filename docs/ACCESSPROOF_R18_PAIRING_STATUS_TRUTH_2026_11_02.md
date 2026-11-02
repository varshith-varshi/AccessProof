# AccessProof r18: honest Gateway status

Confirmed: production SharePoint app mode protect_pending. Production Redis pairing
status not_started, which is a transient receipt, NOT proof of network liveness.
The SharePoint Gateway is running and health/live HTTP 200; health/ready HTTP
503 GUARD_NOT_READY. Customer Guard policy version 8 remains degraded because
its SharePoint source ACL health is FALSE and is correctly fail closed.
Production still has nine unmet independent SharePoint Protect checks.

UI-only correction:
- Do not equate missing 24-hour pairing receipt with stopped Gateway;
  show No installation report and offer a fresh safe installation report.
- Distinguish awaiting, expired, reported, and absent receipts.
- Correct route certificate API parser to use route_certificate, not
  route_certification; accurately show current reference route status.
- Surface actual source authorization blocker; never mark an unverified route
  active or bypass Guard, effective-permission, OIDC, Layer 1/2 and route checks.

Validation: ESLint, TypeScript and Next build succeeded; complete browser suite
59 passed, 5 skipped (desktop and mobile). No API, worker, Guard or Gateway
code or production protection settings changed.
