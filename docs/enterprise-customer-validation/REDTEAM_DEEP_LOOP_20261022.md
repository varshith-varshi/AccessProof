# AccessProof — Iterative Adversarial Security Review
**Local execution date:** 22 October 2026, evening IST
**Repository:** `/home/white-devil/Downloads/accessproof/f15`
**Boundaries:** Synthetic/local test environment only; production APIs, databases, credentials and cloud deployment not modified.

## Final evidence and decision
- **Full Python regression: 551 PASS; 1 strict XFAIL; 5 library deprecation warnings.**
- **TypeScript SDK regression: 34 PASS, 0 FAIL.**
- **Browser E2E: 25 PASS, 1 SKIPPED** (UI/browser exercise does not prove live customer integrations).
- **Seeded Guard policy replay: 16 seeded test runs × 120 policy events**, using an independent decision oracle. Passed.
- **Ruff for modified Python files, Python compile, git diff whitespace: PASS.**
- **Customer Protect certification:** **NO-GO**. The original metadata-only provenance failure is unresolved.

## Confirmed vulnerability / defect register

### AP-RT-001 — HIGH — Future-dated Guard policy timestamp treated as fresh
- **Reproduced:** `PolicyCache.sync_age_seconds()` clamped an expired/clock-skewed *future* timestamp to zero, potentially making stale ACL state appear freshly synchronized after a host clock rollback.
- **Root fix:** Future timestamps now return unknown freshness (`None`); bound Protect apps reject missing/untrusted freshness.
- **Regression:** `test_future_dated_policy_sync_does_not_hide_stale_acl` red → green.
- **Modified:** `apps/guard/accessproof_guard/cache.py`.

### AP-RT-002 — MEDIUM — Unbounded Guard retrieval/provenance batches
- **Reproduced:** 5,001 document entries or 5,001 provenance entries were accepted by request schema and reached authorization logic (401 for absent JWT instead of schema 422). Nested 129-chunk vectors also lacked an appropriate bound.
- **Root fix:** Pydantic bounds on source/resource identifiers, request identifiers, retrieval collections, provenance collections, used-resource IDs and nested chunk arrays.
- **Regressions:** Oversized filter, output and nested chunk tests red → green.
- **Modified:** `apps/guard/accessproof_guard/app.py`.
- **Residual risk:** Pydantic validates after HTTP JSON parsing. ASGI/proxy request-body size and rate limits must also be deployed and measured; this fix alone does not eliminate volumetric DoS.

### AP-RT-003 — HIGH — Unenrolled Guard global-mode fallback
- **Reproduced:** When no authoritative per-application bindings existed, the Guard could use an old global mode with a persisted local policy and accept arbitrary application IDs, including with `ACCESSPROOF_ENV=production` or missing env configuration.
- **Root fix:** Require both an explicit `development`/`test` environment and `ACCESSPROOF_GUARD_STANDALONE_TEST_MODE=1` to retain legacy standalone fallback; default and all deployment modes are fail closed. Isolated pytest harness explicitly opts in; app/source-bound Guards operate normally.
- **Regressions:** Production without enrollment and missing-environment cases red → green.
- **Modified:** `apps/guard/accessproof_guard/app.py`, `tests/conftest.py`.
- **Operational note:** Any standalone legacy development Guard must explicitly opt in. Do **not** set the opt-in in customer production.

### AP-RT-004 — HIGH — Malformed provider principals coerced into matching string IDs
- **Reproduced:** `PolicyCache.install` stringified invalid source/grant identifiers, allowing unexpected `None` or numeric values to become stored grant keys.
- **Root fix:** Reject invalid or blank typed principal, source, resource and scope identifiers before SQLite writes; preserve missing-required-key behavior and transaction rollback.
- **Regression:** 16 malformed-identifier combinations red → green; adjacent legacy cache rollback test also passed.
- **Modified:** `apps/guard/accessproof_guard/cache.py`.

### AP-RT-005 — HIGH — Mutable caller retrieval data after Guard check
- **Reproduced:** Direct Python `ProtectedRAG` accepted a shared result list. A synthetic Guard wait swapped the allowed document object for a private canary with the same resource ID; the model consumed/released the substituted bytes.
- **Reproduced also in TypeScript:** Direct `ProtectedRAG` accepted mutable result entries and allowed the same substitution during asynchronous Guard I/O.
- **Root fix:** Python copies retrieval collection membership before Guard I/O. TypeScript snapshots the primitive source/resource/content/attestation fields before authorization.
- **Secondary regression repaired:** TypeScript framework adapter had relied on object-reference identity when mapping allowed resources back to documents; now uses full source/resource/chunk/content/version/attestation binding and per-key duplicate offsets.
- **Regression:** Both direct SDK substitution tests red → green; complete TypeScript SDK tests passed.
- **Modified:** `packages/rag_sdk/protection.py`, `packages/rag-sdk-typescript/src/index.ts`, SDK adversarial regression tests.
- **Residual risk:** A malicious caller that controls the generator/model invocation can omit tool/cache inputs or lie about provenance. These snapshots do not resolve the trusted source-origin architectural gap.

## New repeatable attack coverage
- `tests/security/test_redteam_guard_clock_and_resource_limits.py`
- `tests/security/test_redteam_guard_seeded_policy_replay.py`
- `packages/rag-sdk-typescript/test/source-identity-confusion.test.mjs`

The seeded oracle verifies out-of-order, duplicated and stale event behavior over 16 seeds. Passing these finite tests does **not** mathematically prove the absence of ordering bugs.

## Open CRITICAL/EXTERNAL security gates
1. **CRITICAL: Metadata-only provenance remains vulnerable**, as shown by the *still-expected-failing* `tests/security/test_known_provenance_integrity_gap.py`. Signed-source enforcement is implemented only for isolated/opt-in routes; real Google/Microsoft ingestion must cryptographically attest source bytes and every model input.
2. **Customer RAG coverage not certified:** Real customer routes, cached responses, tools, SSE/WebSocket paths and independently observed response bytes need machine-authenticated, nonce-bound challenge execution, with replay protection and actual route coverage.
3. **Google Workspace real-provider testing NOT RUN:** provider OAuth, directory, Shared Drive ACLs, inherited rights and real revocation latency require an authorized test Workspace.
4. **SharePoint/OneDrive real-provider testing NOT RUN:** effective site/library/item rights, SharePoint groups, links, B2B guests and OneDrive owner/remote-item semantics need owner-authorized test tenants.
5. **Operational durability still not fully certified:** Reverse-proxy upload limits, rate limiting, hostile high-volume traffic, multiworker fault injection and provider outage recovery need bounded staging tests.
6. **Future unknown bugs cannot be ruled out** by any finite red-team loop.

## Evidence paths (local machine)
- `/tmp/ap_deep_loop_baseline_20261022.log`
- `/tmp/ap_redteam_clock_limits_red.log`
- `/tmp/ap_redteam_unenrolled_prod_red.log`
- `/tmp/ap_guard_unenrolled_default_red.log`
- `/tmp/ap_redteam_policy_identity_red.log`
- `/tmp/ap_redteam_retrieval_mutation_red.log`
- `/tmp/ap_ts_direct_sdk_mutation_red.log`
- `/tmp/ap_redteam_seeded_replay.log`
- `/tmp/ap_deep_redteam_final_verified2.log`
- `/tmp/ap_ts_final_adversarial_20261022.log`
- `/tmp/ap_redteam_browser_final.log`

**Release verdict:** Security improvements are implemented and locally regressed; **NOT READY for unrestricted customer Protect**. This audit did not deploy changes or edit production. Review and integrate remaining real-provider and provenance blockers before any sensitive external pilot.
