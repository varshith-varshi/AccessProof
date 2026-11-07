# AccessProof customer launch audit — 7 November 2026

## Preserved strengths

- `web-v2` is the official Next.js customer frontend and already has consistent authenticated navigation, reusable loading/error/empty states, responsive layouts, and truthful backend-derived protection views.
- The dashboard and Protection page distinguish observed telemetry from `NO DATA`, and they do not infer verified protection from a heartbeat or configuration flag.
- Onboarding, source, Guard, Gateway, application, identity, audit, report, diagnostics, authentication, organization and settings journeys already use established API contracts.
- The customer-hosted Guard and Gateway boundary, signed policy/provenance concepts, route certification, source freshness checks, and explicit Protect approval gates are present in the implementation and regression suite.

## Highest-impact launch gaps found

1. The public site advertised a free plan that was not defined or implemented.
2. It displayed invented Team and Enterprise entitlements, including unlimited applications, SCIM, support and retention commitments.
3. It described Google Drive as generally available while the launch brief and evidence support a guided SharePoint and Entra pilot focus.
4. It claimed broad model and RAG compatibility without limiting the claim to the reviewed Gateway contract.
5. It implied immediate revocation rather than enforcement after provider and synchronization processing.
6. It described fail-closed behavior without clearly limiting that guarantee to protected routes.
7. It did not show an accurate control-plane/customer-environment trust boundary.
8. The primary conversion path was split between “Start free,” demo, pilot and sales actions.
9. The public pricing cards represented commercial commitments that have not been approved.

## Changes selected

- Use a single guided SharePoint pilot as the primary conversion path and retain workspace registration as a secondary, real route.
- Scope every protection claim to supported, certified customer routes and synchronized authorization state.
- Add a clear architecture flow and integration maturity labels.
- Replace pricing tiers with an honest pilot scope and contact-pricing statement.
- Keep authenticated navigation and protection monitoring intact because they already reflect backend truth; avoid a cosmetic rewrite that could introduce security ambiguity.
- Add browser assertions that prevent the removed GA, unlimited and free-plan claims from returning.

## Remaining launch dependencies

- A customer-specific SharePoint site, Entra tenant and RAG route still require administrator consent and live certification.
- Provider-wide SharePoint permission compatibility, revocation latency and continuous availability are not universally certified.
- AccessProof has no claimed third-party certification such as SOC 2.
- Self-service production onboarding is not the launch model; the supported launch verdict can be no stronger than guided pilots.

## Implementation review and validation — continued 7 November

- Preserved the existing backend-authoritative dashboard, Protect activation, Gateway pairing, and Guard security readiness paths. No security backend or installer was changed for this launch UI work.
- Reconciled stale browser fixture expectations without relaxing source readiness, certification state or backend activation behavior.
- Fixed mobile navigation to retain the guided-pilot CTA.
- Corrected page metadata to avoid an unsupported promise of instantaneous authorization updates.
- Clarified that Protect may be active while manual validation is pending; only backend-verified status is presented as verified.
- Scoped prompt-injection link filtering, group/inheritance claims, and source syncing to the implemented security boundary.
- Baseline complete Playwright suite: 137 passed, 5 skipped, 0 failed across desktop and mobile, before final copy assertions.
