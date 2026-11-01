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

## Actual production release verification (2026-11-02)

- Deployed with AWS Systems Manager to existing eu-north-1 EC2 instance.
- Production API accessproof/api:verification-r11-20261101: healthy.
- Worker accessproof/worker:verification-r11-20261101: running; automatically
  generated one durable workflow for an existing installation without re-pairing.
- Website accessproof/web-v2:verification-r11-20261101: healthy.
- Database Alembic p8c1e2f3a4b5 (head) applied successfully.
- Customer Ubuntu Guard accessproof-guard-r11:20261102 connected with
  sequence-aware presence. Sequence samples 52 through 56 increased
  monotonically; server-received heartbeat ages remained below one second.
  The control plane continues to enforce a three-second offline threshold.
- One durable WAITING_FOR_AUTHORIZATION run with 23 checks:
  14 SATISFIED, 3 WAITING_FOR_ADMIN, 5 WAITING_FOR_CHALLENGE,
  1 WAITING_FOR_CUTOVER.
- Public API ready and website login returned HTTP 200;
  public metrics and docs returned HTTP 404.
- Protect certification still NO_GO, certificate_verified=false,
  safe_to_enable_protect=false; nine genuine permission, identity,
  route/provenance/security requirements are outstanding.
- Verified pre-migration compressed DB backup, original .env and Compose
  stored under /home/ubuntu/accessproof-releases/verification-r11-20261101/rollback.
  r10 rollback-compatible API image was built and retained.
- Local Guard rollback Compose:
  ~/Downloads/accessproof-guard-0.1.4/compose.yml.before-r11.
- Capacity maintenance is urgent: production root filesystem approximately
  96% used with about 909 MB available. Expand capacity or perform audited
  safe cleanup before additional large image builds.
