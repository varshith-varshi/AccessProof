# AccessProof penetration test report — 2026-11-03

**Tester:** Claude Code (authorized engineering assessment for NeuralMatrix)
**Commit range:** `e76a89a` → `6aadb6af917b`, branch `claude/modest-bell-tazupa`

**Levels performed:**
* Level 1 (source analysis): yes.
* Level 2 (isolated adversarial testing, synthetic identities and documents):
  yes.
* Level 3 (live production): **not performed**. No access: AWS STS rejects the
  session credentials, and the production hosts and Microsoft Graph are denied
  by network policy.

No production system, customer tenant or Microsoft infrastructure was
contacted. The only Microsoft endpoint reached was public OIDC discovery for
the reference tenant.

## Summary

| Severity | Found | Fixed (local) | Deployed |
|---|---|---|---|
| P0 | 0 new (P0-01 carried over, fixed earlier and rehearsed) | — | no |
| P1 | 1 (RT-04 vulnerable dependencies) | 1 | no |
| P2 | 2 (RT-01 open redirect, RT-02 JWKS amplification) | 2 | no |
| P3 | 2 (RT-03 TOTP replay, RT-05 dev-only npm advisories) | 1 | no |

The authorization core held against every attack in scope:
* Cross-tenant access, role escalation and identity forgery.
* Knowledge poisoning, cache reuse and heartbeat replay.
* SSRF and CSRF.

Details: `ACCESSPROOF_ADVERSARIAL_TEST_MATRIX.md`.

## Findings

### RT-01: Post-login open redirect (P2, FIXED_LOCAL)
* **Vector:** `https://app.accessproof.in/login?next=%2F%09%2Fevil.example%2Fphish`.
* **Root cause:** `safeNextPath()` checked only for leading `//` and `/\`.
  Browsers strip TAB/CR/LF anywhere in a URL and treat `\` as `/`, so the
  value became the protocol-relative `//evil.example`.
* **Impact:** a genuine AccessProof login link delivers a freshly signed-in
  user to an attacker's page (credential and consent phishing).
* **Reproduced in Chromium** against the pre-fix build: the browser landed on
  `http://evil.example/phish`.
* **Fix:** reject control characters, whitespace and backslash, then require
  same-origin resolution through the WHATWG parser.
* **Regression test:** `web-v2/e2e/post-auth-redirect.spec.ts`. It failed
  before the fix and passes after.

### RT-02: JWKS refetch amplification in Guard identity verification (P2, FIXED_LOCAL)
* **Vector:** any request carrying a JWT whose `kid` is unknown.
* **Root cause:** an unknown `kid` always triggered a JWKS refresh from the
  IdP.
* **Measured:** 50 tokens caused 50 IdP fetches.
* **Impact:** unauthenticated amplification, added latency on every request,
  and IdP throttling that would fail *legitimate* employee verification
  (an authentication availability loss).
* **Fix:** a 30-second floor between forced refreshes. Key rotation is still
  honoured after the floor.
* **Regression tests:** `tests/security/test_entra_identity_negative_matrix.py`
  and `tests/unit/test_guard_oidc.py`.

### RT-03: TOTP replay (P3, FIXED_LOCAL)
* **Vector:** reuse an observed password plus a TOTP code within about 90
  seconds.
* **Reproduced:** a second login with the same code returned 200.
* **Fix:** persist the last accepted time step and reject any step at or
  before it, under a row lock (migration `v6f7a8b9c0d1`, verified up, down and
  up on PostgreSQL 17). This covers login, MFA enable/disable and the
  onboarding-reset step-up.
* **Regression test:** `tests/security/test_account_attack_matrix.py`.

### RT-04: Known-vulnerable dependencies (P1, FIXED_LOCAL)
`pip-audit` reported 60 advisories across 6 packages:
* **starlette 0.52.1:** `request.url` rebuilt from an unvalidated Host header
  and path; urlencoded form limits ignored.
* **cryptography 46.0.7:** bundled OpenSSL advisory, plus x509 issues.
* **opentelemetry-api 1.45.0:** unauthenticated ReDoS on the `tracestate`
  header.
* **certifi:** ships a root whose intermediates' private keys were
  compromised.
* **pillow 12.3.0** and **dnspython 2.8.0.**

**Fix:** fastapi 0.162 / starlette 1.10.0, cryptography 50.0.2, OTel 1.45.2,
certifi 2026.10.23, pillow 13.0.0, dnspython 2.9.1. After the upgrade
`pip-audit` reports **no known vulnerabilities**.

Validated by the full suite: SQLite 1401 passed, 0 failed, 10 skipped (1411 tests); PostgreSQL as accessproof_app 1407 passed, 0 failed, 4 skipped (1411 tests).

Customer-hosted Guard and Gateway images must be **rebuilt** to inherit these
versions. The already-built Guard 0.1.5 tarball predates the upgrade.

### RT-05: npm advisories in dev tooling (P3, OPEN)
`npm audit --omit=dev` reports 0. The 16 moderate advisories are in
development tooling that is never shipped.

## Attacks attempted that held
See `ACCESSPROOF_ADVERSARIAL_TEST_MATRIX.md` (H-01 … H-10). Highlights:
* **H-01:** 1,088 cross-tenant requests: every parameterized route × every
  victim object ID, including type confusion. No 2xx, and victim data was
  unchanged. Routes that validate the body before authorization were reviewed
  by hand and pinned.
* **H-02:** 16 forged or misbound Entra token classes were rejected, including
  `alg=none` and HS256 key confusion.
* **H-08:** an authorized but poisoned document combined with a compromised
  retriever could not bring restricted content into the model request.

## Not tested (requires authorization or access)
* Live production, the real Microsoft tenant, and real Alice/Bob identities.
* The customer Gateway host: whether another published route reaches the
  model directly.
* Disruptive fault injection against production. Never attempted.
* Load and DoS testing. Out of scope by instruction.
