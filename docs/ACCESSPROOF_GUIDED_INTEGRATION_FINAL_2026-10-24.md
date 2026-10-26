# AccessProof Guided Integration — Implementation & Verification
**Date:** 24 October 2026
**Repository:** /home/white-devil/Downloads/accessproof/f15
**User goal:** Make existing supported RAG applications quick to integrate:
inspect → configure Gateway/cache → challenge → route cutover → Protect.
**Release verdict:** Supported customer-side Docker reference integration
**locally implemented and tested**. **NOT** universally automatic no-code
RAG protection, and **NOT** a customer production readiness certificate.

## Implemented

1. **Customer-side wizard:** New
   `apps/gateway/accessproof_gateway/integration_wizard.py` with:
   `plan`, `stage`, `install`, `verify`, `cutover`, and `complete`
   (approved install → enrolled challenge → verified cutover as a single
   command AFTER private staging and server-challenge preparation).
2. **Compatibility inspection:** Validates approved
   `accessproof.gateway/v1` service contract, route-env label,
   one selected Redis/Memcached/PostgreSQL cache backend, signed-answer
   return-path declaration, privileged/Docker-socket issues, direct RAG
   model-network overlap, internal RAG network isolation and in-stack
   Guard/model presence. Unknown routes are rejected rather than treated
   as already protected.
3. **Secure staging:** Reuses the existing tested Gateway installer. Writes
   mode-0700 directory, mode-0600 private manifest/credentials, a reviewed
   Compose override and exact deployment/route digests. Does not modify the
   customer's original Compose file.
4. **Explicit customer approval:** Starts only Gateway on
   `--approve-gateway-install`, never silently redirecting the customer
   RAG. It checks actual loopback HTTP liveness and refuses to reapply
   an existing container without review.
5. **Independent challenge and cutover:** Uses the enrolled Guard
   customer-agent / real-route challenge code, machine-authenticated
   server challenge, nonce-bound decision audits, approved employee-facing
   allow/deny tests and fail-closed stopping of a changed RAG service on
   verification failure. The wizard cannot mint its own certificate.
6. **Control-plane Protect request:** Optional
   `--approve-protect-request --admin-credentials private.json` only after
   verified cutover. The existing admin preflight/Guard acknowledgment is
   authoritative. The wizard reports `protect_active=true` only for
   a server `protected` state with Guard acknowledgment and every returned
   server check passing; no self-certification or mode override.
7. **Web UI:** Added `web-v2/app/integrations/setup/page.tsx` at
   `/integrations/setup`, linked from Integrations. The wizard covers
   Redis, Memcached, PostgreSQL and no-cache reference routes, all six
   stages, copyable customer-host commands, and clear owner approval.
   It does not accept customer secrets in the browser or attempt
   remote Docker execution. Applications page continues to issue the
   enrolled challenge and request protected-mode preflight.
8. **Operator runbook:** `docs/gateway-guided-one-command-integration.md`.

## Verification performed

| Test | Result |
|---|---|
| Python full test directory snapshot | **750 passed, one expected failure, zero unexpected failures**, exit 0 |
| Wizard + customer Gateway installer/agent/cutover focused run after last edit | **58 passed**, exit 0 |
| Real Docker Compose synthetic app `plan`/private `stage` | Passed: original Compose unchanged |
| Real disposable Docker Gateway `install --approve-gateway-install` | Passed: Gateway liveness 200; Guard-offline readiness 503; customer RAG untouched |
| Web-v2 ESLint | Passed |
| Web-v2 TypeScript compile | Passed |
| Web-v2 production build including `/integrations/setup` | Passed |
| Ruff and whitespace checks | Passed |
| Docker Compose merged config | Passed |
| End-to-end real provider revocation, customer route certification | **Not performed**; customer/tenant access needed |

Python full-suite log: `/tmp/ap_one_click_final_suite_20261024.log`.
Focused wizard/cutover log: `/tmp/ap_wizard_final_focused_20261024.log`.
Web build log: `/tmp/ap_wizard_web_build.log`.

**Existing expected failure:** documented legacy metadata-only provenance
integrity. We did not remove it or weaken the Protect gate.

## Mandatory external gates

- Owner-authorized live Google Workspace / SharePoint tenant,
  verified employee tokens, real source ACL/group/shared-drive revocations,
  actual event-to-denial timing and signed provider evidence.
- Proof that the *customer's actual* RAG always routes all retrieval,
  generated answers, cache hits (Redis/Memcached/PostgreSQL or alternatives),
  tool/memory responses and background routes through the Guard/Gateway.
- Verified customer network isolation and failure recovery, production
  load/HA/DR checks, credential rotation, and incident/audit readiness.
- The customer-side wizard works on an explicitly supported Docker
  reference architecture that already emits signed source manifests.
  Arbitrary legacy RAG code may require framework-specific adaptation.
- The web console does not install arbitrary software on a customer's host
  with one remote click. The required customer-side approval and private
  machine challenge are deliberate security boundaries.

## Current disposition

The new guided workflow can be demonstrated locally and piloted on an
approved reference deployment after real permission validation.

**No production traffic cutover, no external provider ACL mutation, no
live customer data exposure, no credential sharing, no auto-activation of
Protect.** Existing repository working changes were preserved.
