# r16 — manual RAG validation without certification preflight

## Purpose

The AI Applications "Enable Protection" action misleadingly ran production
certification (nine pending checks) when the customer expected to manually
test their existing SharePoint RAG first.

This frontend-only release **separates manual functional tests from production
Protect enablement**. No backend authorization, certification, Guard policy,
SharePoint source eligibility, or audited verification rules were modified.

## Customer journey

1. AI Applications → **Manual RAG Test** for a Gateway application.
2. Get Started opens the selected application and shows a test worksheet once
   the paired Gateway has been reported. It does not issue a Protect request.
3. Using the customer's original RAG and approved synthetic SharePoint files,
   run Alice allow, Bob deny, Bob allow, revoke, cache retry, and restore.
4. Record each outcome as "Observed expected", "Observed unexpected", or
   "Not tested"; notes remain in browser session storage only.
5. Independently view fresh Guard decision deltas, denied requests, and
   audit logs. Deltas are diagnostics and are not individual request evidence.

The raw nine-check preflight popup and its Retry Checks control have been
removed from the AI Applications *manual testing* entrypoint; production
monitoring continues to report actual independent readiness.

## Security boundaries

- Manual checkbox/notes never set Protect, bypass SharePoint effective rights,
  certify Layer 1/2, or submit operator attestations.
- Permission-revocation exercises require approved **synthetic** resources,
  and must be restored. Never instruct operators to publish confidential
  RAG contents or employee tokens.
- If the Guard is degraded, a warning is shown; observing expected answers
  alone is not proof of enforcement.
- Production Protect remains fail closed until real provider authorization,
  employee OIDC, provenance, buffered response, cache and Gateway route
  evidence is gathered and an approved cutover is performed.
- No API/worker/migration change is required for this UI correction.

## Validation

- ESLint and TypeScript passed; Next.js production build passed.
- Complete Playwright desktop/mobile: 51 passed, 5 skipped.
- New browser test verifies a manual test worksheet can record results, persist
  in the current tab across reload, reset, and make **zero** calls to the
  Protect enable endpoint.
- AI Applications regression checks no Enable Protection button, no raw
  checklist counts in the manual path, and a link to the manual test worksheet.

## Limitations

This release enables **manual testing**, not manual bypass of security
certification or full production Protect activation. It does not itself repair
the existing degraded customer Guard or enable the currently non-certified
SharePoint provider. Real customer Alice/Bob tests still require access
to the existing RAG and real test accounts.
