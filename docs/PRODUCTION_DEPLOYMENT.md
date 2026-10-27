# Production deployment gate — unapproved as of 2026-10-27

The source tree has production Compose, Gateway, Guard, API, worker, Postgres and Redis components. This document does **not** authorize production changes.

Before deployment:
1. Back up the production database and verify restore into a disposable environment.
2. Migrate a disposable database using `alembic upgrade head`; confirm `ai_application_source_bindings` backfills legacy rows. The multi-source downgrade intentionally refuses to drop data if more than one source is bound.
3. Deploy to staging with customer-owned TLS, least-privilege provider consent, approved source keys, secure secret injection and hardened network egress. Keep Guard and control plane private.
4. Provision two separate test identities and synthetic source documents; verify Microsoft and Google provider-specific grants, group membership and revoke behavior.
5. Verify source ACL/directory health and revision synchronization, all legitimate response/cache routes, retries, concurrent revocation, failure injection and audit delivery.
6. Load-test authenticated concurrent requests, measure latency vs LLM/provider time separately, and prove graceful connector outage handling.
7. Obtain explicit authorized application/tenant cutover approval and a passing route-specific customer security certificate before enabling Protect.
8. Reverify after cutover; maintain rollback procedures that never bypass the Guard.

Multi-source Protect activation remains explicitly blocked by the control-plane checklist until externally grounded customer-route evidence exists. Never promote a local reference test to a production readiness certificate. No production changes are performed by following this documentation alone.
