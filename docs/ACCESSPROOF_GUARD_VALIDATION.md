# Guard validation (2026-11-02)

## Why the deployed Guard was DEGRADED (root cause from code)

`/health` computes `ready` from policy version, freshness, audit capacity,
bindings, revisions and per-application `source_acl_healthy`. The control
plane sets `source_acl_healthy=false` for every Microsoft source lacking a
valid effective-permission certificate (`guard_policies()` →
`effective_source_certified()`). With zero certificates in production, the
SharePoint-bound application can never be ready. **This is the intended
fail-closed result and was not overridden.**

## Change in this release (D-03)

`/health` now also reports `identity_ready`, and `ready` requires it.

| Configuration | identity_ready |
|---|---|
| OIDC with issuer + audience | true |
| OIDC missing issuer or audience | **false** (previously could report ready) |
| static HS256, non-production, key ≥ 32 bytes | true |
| static HS256, `ACCESSPROOF_ENV=production` | **false**, and every decision returns 503 `IDENTITY_STATIC_MODE_FORBIDDEN_IN_PRODUCTION` |

## Local results

All Guard unit and security suites pass, including adversarial suites (identity
spoofing, duplicate grants, equal-revision replay, clock and resource limits,
atomic snapshot install). Counts are in `ACCESSPROOF_TEST_RESULTS.json`.

## Not validated here

Live Guard on the customer test host, its real policy sync from production,
and real Entra employee tokens. These are BLOCKED: no network path or credentials.
