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
- **Full frontend suite:** `npx playwright test --workers=2` — **97 passed, 5 skipped, 0 failures** across desktop and mobile (2026-11-05). Existing Google provider tests were updated to select Google explicitly; current UI defaults to SharePoint. Existing site-grant tests now assert the distinct `Site grant required` state instead of the obsolete Shadow-only wording.
- Customer onboarding PDF: newly generated, **11 A4 pages**; text extracted and critical pages visually rendered/checked. Guide source: `scripts/build_customer_onboarding_guide.py`.
- Backend test suites: `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest tests/integration/test_microsoft_admin_consent.py tests/security/test_human_activation_approval_d28.py -q` — 11 passed.
- Client wheel built locally (not published on PyPI). A production release artifact and customer download checksum must be separately verified.

## Not certified by this report

- A complete independent Microsoft customer tenant walkthrough, production client ID, support email deliverability, Gateway download on an authenticated production session, and remote RAG host certification without agreed technical assistance.
- New UI production deployment, source-site privilege reduction or customer authorization. Do not claim these as complete based solely on branch tests.

## Release restrictions

The production role `accessproof-certifier` is intentionally scoped to approved read-only and certificate/route SSM documents. It is **not** a general deployment role and cannot upload a Git archive to S3 or invoke `AWS-RunShellScript`. Do not fall back to the AWS root login or broaden this role to ship the UI. Deployment requires an explicitly authorized, separate least-privilege release mechanism, pre-deploy DB/image backup, rollback proof and post-release checks. Current production Protect settings must remain unchanged.
