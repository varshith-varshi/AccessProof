# Confirmed defects and remediation

Four baseline adversarial tests were initially RED (4/4 failed), then GREEN (4/4 passed) in `tests/security/test_unified_v2_four_regressions.py`:

1. **Reconciliation starvation (P0):** `reconcile_known_acls` sorted `last_synced_at` without advancing independent cursor, starving later files. Add persisted indexed `last_reconciled_at`, lock rows in bounded fair order and advance during successful transactions. 4 files/limit 2 recheck now visits all. Remaining coverage: concurrent PostgreSQL workers, item-permanent failure, 10k/100k, cursor reset.
2. **Reassigned provider permission ID (P0):** old group grant could survive when same provider permission ID referred to new user. The grant key now incorporates provider, resource, grantee type/stable ID, role, expiry and inheritance fingerprint; stale keys can be revoked while new identity needs an independently matched subject. Regression asserts old-group revoke and new-user grant. Remaining high-risk: concurrency, revocation-first event scheduling and independent access paths at production Graph scale.
3. **Missing source provenance in Protect (P0):** when `source_trace=None`, Python SDK historically substituted initial authorized retrieval and returned ALLOW for simulated uncaptured cache. Protect now blocks before generation unless an explicit trusted trace exists. TypeScript parity strengthened and customer demo updated. Real installed RAG full-path coverage still unverified.
4. **Microsoft admin consent scope (P1):** v2 `adminconsent` URL had no `scope`; now explicitly requests `https://graph.microsoft.com/.default` using tenant-specific authority. Local tests verify URL; no actual Microsoft consent was performed.

**Additional confirmed TS regressions:** TypeScript Protect accepted `would_allow` in a Protect flow and did not enforce chunk-scoped allowlist; reproduced with two failing tests, patched strict mode checks and chunk identity, 7 TS tests passed.

No external provider, customer or production claim follows from synthetic passing tests.
