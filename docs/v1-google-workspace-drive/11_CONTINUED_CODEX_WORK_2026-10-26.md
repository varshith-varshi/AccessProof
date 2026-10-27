# AccessProof Google Workspace + Drive V1 — Codex continuation handoff

**Date:** 2026-10-26
**Repository:** `/home/white-devil/Downloads/accessproof/f15`
**Frontend:** `web-v2`
**Environment:** Local authorized Ubuntu development computer. No live
Workspace tenant, customer data, production keys, database migrations or
production deployment were accessed or modified.

## Baseline and preservation

Resumed the already dirty checkout after earlier Codex work. Did not run
`git reset`, `git clean`, `git checkout`, overwrite the working tree, or
discard the preceding V1 scope/credential changes.

The earlier Codex V1 changes are preserved:
- production API only creates canonical Google Drive sources;
- browser-submitted per-source Google credentials are rejected;
- frontend offers server-owned Google Workspace/Drive OAuth onboarding;
- prior Google source/Guard readiness tests and docs remain in place.

## Further implementation in this continuation

1. Removed the OAuth *application client secret* from Google consent exchange
   return values and from the persisted per-source credentials in the Google
   callback. Per-source records retain the encrypted provider access/refresh
   tokens, the public OAuth client ID, and an explicit server-managed marker.
2. Updated the worker OAuth refresh path to use the operator's configured
   Google OAuth client ID and secret. Production refuses missing credentials or
   client-ID mismatch, and opportunistically scrubs legacy client secrets from
   encrypted source records during successful credential refresh paths.
3. Passed the operator OAuth ID/secret into **both API and worker** containers
   in EC2 and production Docker Compose configurations. These are operator
   runtime secrets, never customer dashboard fields.
4. Replaced the staging diagnostic script's unsafe
   `--session-token` CLI flag with `--token-stdin` or
   `ACCESSPROOF_STAGING_SESSION_TOKEN`. Requires an HTTPS API origin,
   rejects redirects, caps JSON responses and reports only aggregate
   provider/Guard health, not customers' folder IDs or source records.
5. Production V1 provider validation now requires the canonical exact
   `google-drive` identifier; mixed-case aliases cannot create source records
   that worker queries would miss.
6. Updated browser tests to reflect the Google-only V1 form and operator-owned
   consent path. Preserved the two old Microsoft UI tests as explicit skips:
   the Microsoft UI is intentionally absent from V1 but backend compatibility
   source remains.
7. Added/extended regression tests for OAuth-client-secret persistence and
   removal, runtime ID mismatch, staging-checker safety, production
   source creation, rotate-credential and reauthorize endpoint bypass.

## Local verification

- Previously running broader Google-focused suite: **38 passed**.
- Google OAuth / refresh focused suite: **14 passed**.
- Final source/config/OAuth/staging test group, including direct
  rotate/reauthorize bypass attempts: **28 passed, 0 failed**.
- Latest full desktop Playwright suite: **14 passed, 3 skipped**.
- TypeScript `tsc --noEmit`, targeted Python compilation and Ruff: passed.
- See logs:
  `/tmp/accessproof-continue-google-v1.log`,
  `/tmp/accessproof-v1-oauth-secret-tests.log`,
  `/tmp/accessproof-v1-browser-final2.log`,
  `/tmp/accessproof-v1-playwright-desktop-full.log`,
  `/tmp/accessproof-v1-handoff-final.log`.
- The final test log reports exit code 0. These runs have overlapping test
  cases; counts must not be summed as unique tests.

## Not a production-certification claim

**Verdict: NO-GO for unrestricted enterprise Protect.** Outstanding gates:

- A NeuralMatrix-owned, properly configured/verified Google Cloud OAuth app
  and real Google Workspace administrator consent.
- Complete provider permission coverage including limited folders, inherited
  permissions, shared drives, direct/group access and repeatable revocation.
- Actual directory/Drive change detection and measurable provider-change
  → Guard-denial latency against a live provider, with safe stale-state handling.
- A certified, real employee-authenticated customer RAG route and attested
  document/chunk provenance with Layer 1/2 negative tests.
- Crash-atomic Guard snapshot installation and multiworker consistency tests.
- Staging PostgreSQL/Redis/container integrations, cross-tenant adversarial
  tests, backups/restores, migration/rollback and incident drills.
- Security review and Google OAuth restricted-scope verification requirements.

Local root filesystem was about **100% full** with only **3.4 GiB free**,
which limits safe Docker/build/load operations. No destructive cleanup was run.

## Next safe implementation sequence

1. Move Google OAuth post-consent source initialization and ACL/Directory sync
   into a durable, idempotent backend job with retries and status.
2. Implement/verify atomic full Guard policy snapshot commit plus restart/crash
   recovery tests. Do not publish Protect if policy/revision/bindings diverge.
3. Test the Google connector's effective permission model with a customer
   validation partner's **approved synthetic staging corpus**.
4. Prove the employee JWT → stable Google directory identity → ACL → Guard →
   attested RAG → Layer 2 chain, including all bypass/cached/streaming paths
   actually enabled.
5. Carry out production-like restore, rollback, resilience, and operational
   release drills before a limited Protect pilot.
