# AccessProof adversarial test matrix — 2026-11-03

Every row ran in the isolated environment unless marked BLOCKED. Live = real tenant/production.

| ID | Area | Attack | Result | Evidence | Live |
|---|---|---|---|---|---|
| H-01 | Tenant isolation | 1,088 cross-tenant requests: every parameterized route x every victim object id (type-confused) | HELD — no 2xx, victim data intact | `tests/security/test_cross_tenant_route_sweep.py` | BLOCKED |
| H-02 | Entra identity | expired, wrong tenant/audience/issuer, v1 issuer, Graph token, forged signature, unknown kid, nbf, missing exp/oid, alg=none, HS256 key confusion | HELD — all rejected with specific codes; only oid/sub accepted as subject | `tests/security/test_entra_identity_negative_matrix.py` | BLOCKED |
| H-03 | Accounts | reset-token reuse, invitation reuse / wrong email, VIEWER/AUDITOR/ENGINEER escalation, ADMIN ownership seizure, API key after downgrade, cookie CSRF | HELD — all refused | `tests/security/test_account_attack_matrix.py` | BLOCKED |
| H-04 | Rate limiting | X-Forwarded-For spoofing through nginx to uvicorn 0.35 | HELD — right-most untrusted hop used; spoofed entries ignored | `manual probe (ProxyHeadersMiddleware)` | BLOCKED |
| H-05 | SSRF | webhook/OIDC URLs to private, loopback, link-local, CGNAT, DNS rebinding, redirects | HELD — HTTPS + is_global + IP pinning at save and at delivery; no redirects | `code review + existing tests` | BLOCKED |
| H-06 | Gateway heartbeat | replay, cross-tenant installation id, binding change, archived app | HELD — monotonic sequence, tenant-scoped lookup, rebinding forces re-pair, archive revokes credential | `tests/integration/test_gateway_presence.py + review` | BLOCKED |
| H-07 | Shared conversations | forged participant token passing roster comparison | HELD — Guard verifies every token before any decision | `tests/security/test_participant_aware_authorization.py` | BLOCKED |
| H-08 | Knowledge poisoning | authorized document instructs override + forges fences; compromised retriever supplies restricted chunk | HELD — restricted content never reaches the model; forged fences defused | `test_poisoned_authorized_document_cannot_pull_unauthorized_content_into_the_model` | BLOCKED |
| H-09 | Answer cache | reuse across employee / after revocation / forged dependency digest | HELD — every hit re-runs Layer 1+2 for current employee with revision binding | `existing cache tests` | BLOCKED |
| H-10 | Client redirects | consent redirect destination | HELD — pinned to login.microsoftonline.com / accounts.google.com over https | `review` | BLOCKED |
| P0-01 | database/deploy | API connected as superuser+owner; 19/58 tenant tables had no policy; none forced | FOUND → FIXED_REHEARSAL | tests/security/test_postgres_tenant_isolation.py; full suite on PostgreSQL as accessproof_app | BLOCKED |
| D-12 | deploy | accessproof_app: 'must be owner of table organizations' | FOUND → FIXED_REHEARSAL | rehearsal r23 | BLOCKED |
| D-13 | deploy | forced post-switch failure -> password authentication failed for accessproof_app; log said RESTORE complete | FOUND → FIXED_REHEARSAL | rehearsal forced-failure x2 | BLOCKED |
| RT-01 | web-v2/lib/api.ts | Chromium: /login?next=%2F%09%2Fevil.example%2Fphish -> http://evil.example/phish after sign-in | FOUND → FIXED_LOCAL | web-v2/e2e/post-auth-redirect.spec.ts (fails on old build, passes on fix) | BLOCKED |
| RT-02 | apps/guard identity | 50 unknown-kid tokens -> 50 JWKS fetches | FOUND → FIXED_LOCAL | tests/security/test_entra_identity_negative_matrix.py; tests/unit/test_guard_oidc.py | BLOCKED |
| RT-03 | apps/api auth | same code accepted twice at /auth/login | FOUND → FIXED_LOCAL | tests/security/test_account_attack_matrix.py | BLOCKED |
| RT-04 | supply chain | pip-audit: 60 advisories in 6 packages | FOUND → FIXED_LOCAL | full suite SQLite + PostgreSQL | BLOCKED |
| RT-05 | web-v2 devDependencies | npm audit (production deps: 0) | FOUND → OPEN | — | BLOCKED |
