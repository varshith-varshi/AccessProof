# AccessProof r11 — durable post-install verification rollout

## Implemented

- New PostgreSQL entities: verification_runs, verification_steps, verification_evidence,
  verification_events, verification_outbox, verification_approvals, guard_presence_leases.
- Tenant-scoped, forced RLS for every new table; server-owned tenant context for
  authenticated Gateway pairing/Guard messages.
- Idempotent run creation on one-use pairing installation claim, fingerprint
  supersession on deployment/source/Guard/policy changes, DB outbox recovery.
- Bounded server-side worker reconciliation and retry, persisted steps/events.
  The worker reevaluates the existing authoritative readiness checklist;
  this is not a replacement for provider-live identity or route proofs.
- Read-only per-app run/events endpoints, authenticated tenant-scoped SSE
  verification and 2s Guard presence events, 30s polling fallback.
- One-second best-effort independent Guard presence, monotonic local SQLite
  sequence, server-side sequence replay rejection, three-second server TTL.
  Old clients remain compatible only until a sequence-aware lease exists.
- Explicit scope-fingerprint-bound, expiring owner approvals. Approval does
  not authorize Microsoft consent, change traffic routes or enable Protect.
- The UI now separates Guard connectivity from Guard security readiness,
  persists onboarding after Redis pairing TTL, and presents step-level state.

## Safety limitations

- This release does NOT certify Microsoft tenant effective-permission coverage,
  Alice/Bob Entra sign-in, live revocation, provenance, Layer-1/Layer-2 route,
  or production cutover. The workflow displays WAITING_FOR_ADMIN / CHALLENGE /
  CUTOVER for missing independent evidence. Protect remains fail-closed.
- VerificationEvidence stores schema and digest slots only; the orchestration
  never invents evidence or creates source certificates.
- No automatic Microsoft admin consent, production route mutation, or source
  permission change occurs. These operations remain explicitly authorized.
- Full multi-provider automatic evidence execution requires separate approved
  synthetic fixtures, provider-live challenge agents and signed acknowledgements.

## Validation

- Full Python test run exited 0 with pytest-asyncio plugin.
- Focused tests cover pairing idempotency, outbox resume, replay rejection,
  tenant-bound Guard machine auth and Guard cache sequence persistence.
- SQLite and disposable PostgreSQL migrations upgraded to p8c1e2f3a4b5.
- PostgreSQL pg_class confirms all seven new tables have RLS and FORCE enabled.
- Web lint/typecheck/build passed; Playwright 45 passed, 5 skipped.
- API and worker images were built and module imports verified before release.

## Production rollback discipline

- Rollback must preserve newly added tables; old binaries can run against
  additive schema. Never downgrade the database to bypass certification.
- Do not switch r11 worker before database migration and API rollout.
- Preserve r10 API/web/worker image tags, r11 rollback-compatible image, and
  pre-release .env/Compose file and database snapshot.
- After rollout independently verify API + website health, worker stability,
  pairing-created durable runs, Guard presence, tenant isolation, and Protect
  still blocked while Microsoft evidence remains uncertified.
