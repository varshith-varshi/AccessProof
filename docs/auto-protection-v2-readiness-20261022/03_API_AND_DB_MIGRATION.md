# API and migration map

**New non-activating APIs** (organization-admin scoped, user auth + existing CSRF; `GET` is read privilege):
- `POST /api/v1/current/ai-applications/{id}/protection/enable` -> 202 preflight; tenant-bound idempotent durable run, always Action required when real customer test agent absent. Does not activate Protect.
- `POST /.../protection/retry` -> 202 same scoped retry/readiness.
- `GET /.../protection/status` -> application/readiness/errors and explicit `guard_acknowledged=false`; no false active assertion.

Existing `PATCH /.../mode` now also requires a real customer RAG challenge-agent readiness check, so historical manual verification timestamps cannot silently bypass the new gate. Old manual `/verification` API is retained for compatibility/forensics, but is insufficient to activate.

**New migrations** on original Alembic chain:
- `a2b4c6d8e0f2` nullable, indexed `guard_resources.last_reconciled_at` separate from provider delta sync.
- `b3c5d7e9f103` `protection_activation_runs` with tenant+application uniqueness, source/Guard fingerprint, check summary, last_checked_at and reason.
- `c4d6e8f0a215` `source_effective_certifications` signed evidence metadata bound to exact source scope, provider profile and expiry; no admin mutation endpoint or certification issuer yet.

The migration upgraded a fresh **isolated SQLite** database, downgraded and re-upgraded. PostgreSQL production-like migration on populated copy, downlevel Guard/SDK behavior and concurrent first-click load still need verification. Old application modes and historical audit records are preserved.
