# web-v2 cutover and rollback

This document describes a future production switch. Building and validating `web-v2` does not change the active frontend.

## Preconditions

- The full backend and `web-v2` test suites pass from a clean checkout.
- A production image is pinned by immutable digest.
- Required browser endpoints are complete and tenant-isolation tests pass.
- Production origins, cookie settings, CSP, TLS, and API proxy destinations are verified.
- A database backup and the currently deployed frontend image digest are recorded.
- A staging smoke test covers sign-in, source inventory, Guard creation and enrollment, permission events, and audit history.

## Cutover

1. Deploy `web-v2` beside the current web service under a temporary internal hostname.
2. Run the authenticated hosted smoke suite and inspect API, proxy, and browser error telemetry.
3. Move a small internal cohort to `web-v2` through the load balancer or feature flag.
4. Confirm login, organization isolation, Guard enrollment, and read-only operational pages.
5. Increase traffic gradually while monitoring 4xx/5xx rates, latency, and client errors.
6. Promote the pinned image to all web traffic only after the observation window is clean.

## Rollback

1. Route traffic back to the recorded legacy frontend image.
2. Keep the API and database running; `web-v2` requires no schema migration and rollback must not alter data.
3. Preserve logs and the failed image digest for investigation.
4. Re-run the legacy frontend smoke test before closing the incident.

## Post-cutover checks

- Direct URL refresh works for every application route.
- Anonymous users return to login and authenticated users retain their intended destination.
- No credentials or enrollment secrets appear in browser logs, URLs, analytics, or error reports.
- Desktop and mobile navigation, empty states, errors, and loading states remain usable.
