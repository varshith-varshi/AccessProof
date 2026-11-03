# AccessProof verified feature matrix — 2026-11-03

Commit: `7e8cb39eace4`

Status meanings:
* **VERIFIED-LOCAL:** automated tests at this commit (SQLite and PostgreSQL 17 as the restricted role).
* **VERIFIED-REHEARSAL:** additionally exercised through the real release scripts on the production-shaped stand-in.
* **NOT_TESTED-LIVE:** never observed against the real tenant or production host.
* **BLOCKED:** cannot be tested from this environment.

A feature flag, a dashboard label or indexed documents never count as verification.

| Feature | Local | Rehearsal | Live production / real tenant |
|---|---|---|---|
| Tenant isolation via forced RLS, non-superuser runtime role (P0-01) | VERIFIED-LOCAL | VERIFIED-REHEARSAL (gate I PASS, cross-tenant 403) | BLOCKED (switch needs owner approval + access) |
| Metrics through SELECT-only role | VERIFIED-LOCAL | VERIFIED-REHEARSAL (non-zero cross-tenant counts) | BLOCKED |
| Deploy, owner-run migrations, rollback | VERIFIED-LOCAL (syntax/tests) | VERIFIED-REHEARSAL (r22, r23, rollback r23→r22) | BLOCKED |
| Least-privilege switch: idempotent, honest restore, `RECOVERY=1` | — | VERIFIED-REHEARSAL (forced failure ×2, recovery) | BLOCKED |
| Production gates A–J | VERIFIED-LOCAL | VERIFIED-REHEARSAL (A, I PASS; others honestly FAIL/BLOCKED) | NOT_TESTED-LIVE |
| SharePoint effective-permission certificate (Ed25519, independent) | VERIFIED-LOCAL (test key only) | — | BLOCKED (no certifier key; no evidence) |
| Entra employee identity (OIDC, tenant-bound mappings) | VERIFIED-LOCAL | — | BLOCKED (real Alice/Bob sign-in) |
| Guard readiness computed, static identity refused in production | VERIFIED-LOCAL | — | NOT_TESTED-LIVE |
| Gateway authenticated heartbeat / live connectivity | VERIFIED-LOCAL | heartbeat route fail-closed (422) | NOT_TESTED-LIVE (deployed Gateways predate it) |
| Layer 1 retrieval filter | VERIFIED-LOCAL | — | NOT_TESTED-LIVE |
| Layer 2 release verification, L1==L2 revision binding | VERIFIED-LOCAL | — | NOT_TESTED-LIVE |
| Revocation propagation and cache invalidation | VERIFIED-LOCAL (simulated provider) | — | BLOCKED (authorized revoke/restore trial) |
| Output sanitizer v2 (entities, CSS, event handlers, URL tricks) | VERIFIED-LOCAL (real Chromium) | — | NOT_TESTED-LIVE |
| Shared conversations: signed roster / `single_user` default | VERIFIED-LOCAL | — | NOT_TESTED-LIVE (no roster-signing adapter exists) |
| Spotlighting with per-request nonce boundaries | VERIFIED-LOCAL | — | NOT_TESTED-LIVE |
| Account, workspace rename, archive app, onboarding reset | VERIFIED-LOCAL | VERIFIED-REHEARSAL (rename, reset preview) | NOT_TESTED-LIVE |
| Web app (Next.js) flows | VERIFIED-LOCAL (Playwright 81 passed in an earlier run this session; `web-v2/` unchanged since e69ee00, not re-run at this commit) | web healthy after each deploy | NOT_TESTED-LIVE |

**SharePoint Production Protect: NOT VERIFIED.** See `ACCESSPROOF_PRODUCTION_PROTECT_REPORT.md`.
