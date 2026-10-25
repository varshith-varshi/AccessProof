# AccessProof — adversarial reliability audit checkpoint
**Date:** 2026-10-20 (Asia/Kolkata)
**Device:** whitedevil-Acer-ALG-AL15G-53 (Ubuntu)
**Repository:** `/home/white-devil/Downloads/accessproof/f15`, branch `master`, starting HEAD `ab59ffd`
**Scope:** Owned local checkout, synthetic JWT/Guard/Drive fixtures, local SQLite, mocked HTTP, local test clients. No live provider/customer attacks, no production deployment or credential exposure.

## Executive verdict
**NOT READY for unrestricted customer production security claims.**
**Local security regression gate: PASS on the currently executed suite.**
A controlled **synthetic-data** pilot is technically plausible only with strict scope, explicit integration verification and no promise of instant revocation or complete semantic leak prevention. Real-provider authorization and independent customer RAG are still **BLOCKED / UNVERIFIED**.

## Confirmed findings and repair evidence
- **AP-ADV-01 — P0 revocation / release TOCTOU**: Reproduced `allow` after policy changed to `deny` between Layer 2 recheck and context consumption (`/tmp/accessproof_h01_red.log`). Fixed locally by atomic SQLite release recheck and context consumption with application binding/mode check. Retests PASS.
- **AP-ADV-02 — P1 Guard error / late source SDK exception**: Reproduced uncaught HTTP 403 in SDK `ProtectedRAG` after buffered generation (`/tmp/accessproof_redteam_first6.log`). Changed SDK to return explicit safe block and no generated content; dedicated 401/403/429/500/503, invalid JSON and generator-interruption tests PASS.
- **AP-ADV-03 — P0 Protect-to-Shadow mismatch**: Two regressions initially failed because SDK released buffered answer on Layer 2 `would_allow`/`would_block` despite Protect Layer 1 (`/tmp/accessproof_sdk_adversarial_red.log`). Mode-continuity validation and retry-mode validation now PASS, including downgrade attempts.
- **AP-ADV-04 — P2 outage diagnostic**: Earlier broad suite caught demo protected API returning HTTP 200 on Guard 503 instead of an unmistakable outage. Demo maps structured Guard failures to HTTP 503; independent recheck PASS.
- **AP-ADV-05 — P1 Guard setup Host-header spoof**: Synthetic remote transport with forged `Host: localhost` reached local setup. The endpoint now additionally validates the actual peer as loopback; tests/security/test_guard_setup_peer_auth.py reproduced failure and passed after the correction.
- **AP-ADV-06 — P0 out-of-order permission events resurrect stale access**: Four deterministic tests initially failed because an old grant overwrote a later deny inside a newer policy envelope. Cache installation now verifies per-row revisions and resolves equal-version conflicts conservatively; regression plus cache/ACL/integration suite 21 PASS.

**Finding counts identified in this continuation:** P0=3, P1=2, P2=1, P3=0. **Fixed locally:** P0=3, P1=2, P2=1. **Known unfixed among these six reproductions:** 0. This is NOT evidence that untested P0/P1 issues do not exist.

## Changed/added code and regression cases
- `apps/guard/accessproof_guard/cache.py`: atomic `consume_contexts_with_recheck`, latest binding checks, per-resource policy revision handling and conservative equal-version conflict resolution.
- `apps/guard/accessproof_guard/app.py`: apply atomic release gate to bound app and block on revoked/invalid contexts.
- `packages/rag_sdk/protection.py`: explicit fail-closed exceptions and Protect/Shadow decision continuity across L1, L2, late sources and regeneration.
- `drive-rag-demo/app.py`: structured Guard-failure HTTP 503 (observed in working checkout).
- `tests/security/test_adversarial_guard_boundaries.py`: 11 executable adversarial tests (T1–T5 plus revocation race, mode race, forged provenance/replay, source outage).
- `tests/security/test_adversarial_sdk_contract.py`: 12 cases (including parameterized transport and retry variants).
- `tests/security/test_policy_ordering.py`: 28 executable ordering cases (4 targeted and 24 exhaustive event permutations), each with a positive grant control where applicable.
- Additional pre-existing/concurrent local tests include `tests/security/test_release_version_race.py`, `tests/security/test_sdk_guard_failures.py`, `tests/unit/test_drive_rag_guard_path.py`. Existing user changes were not reset or committed.

## Tests actually run
| Check | Measured result | Scope |
|---|---|---|
| Initial targeted security baseline | **54 passed**, exit 0 | Before new adversarial cases; different selection from final |
| Focused post-fix Guard/SDK set | **38 passed**, exit 0 | Guard/cache/SDK and earlier T1–T5 |
| New adversarial tests alone | **21 passed**, exit 0 | Deterministic HTTP mock/local Guard; includes positive controls |
| Previously failing rollover+demo endpoint | **7 passed**, exit 0 | Relevant isolated recheck |
| Entire Python suite on final checkout | **343 passed**, 4 warnings, exit 0 in 10.35s | Ephemeral SQLite as enforced in `tests/conftest.py`; `/tmp/accessproof_adversarial_verified_latest.log` |
| Python Ruff targeted changed paths | **PASS**, exit 0 | Guard/cache/SDK/new tests |
| Python compilation targeted files | **PASS**, exit 0 | Guard/cache/SDK |
| `git diff --check` | **PASS**, exit 0 | Tracked working-tree diff |
| Web-v2 ESLint | **PASS**, exit 0 | `/tmp/accessproof_ui_lint_adversarial.log` |
| Web-v2 TypeScript `tsc --noEmit` | **PASS**, exit 0 | `/tmp/accessproof_ui_typecheck_adversarial.log` |
| Playwright web-v2 browser E2E | **21 passed, 1 skipped**, exit 0 | `/tmp/accessproof_adversarial_web_e2e.log`; skipped test is not a pass |
| Docker Compose syntax | **PASS**, exit 0 | `docker compose -f docker-compose.yml config --quiet` |

**Important baseline caveat:** A prior overlapping full run captured two failures, which were addressed/rechecked before the final 309-pass run. The baseline 54 and final 309 are not an apples-to-apples before/after count.

## Attacks and evidence breadth
- **At least 16 distinct locally exercised adversarial scenario families** in this continuation: denied mixed retrieval, spoofed identity fields, tenant/source mismatch, stale policy, forbidden streamed candidate with late source, release-time revoke, mode drift, source provenance/citation forgery and replay, source health loss, SDK Protect/Shadow mismatch, HTTP error classes, invalid response format, generator failure, deliberate Shadow positive control, and regeneration downgrade. Parameterized variations are not counted as independent threat classes.
- The 68-item A01–K05 catalog is **not completed**: `02_coverage_matrix.md` presently lists **9 narrower PASS_LOCAL**, **18 PARTIAL**, **41 NOT_RUN**. This is an execution checkpoint, not a comprehensive penetration-test certification.
- **Local mocks only** in our new harness; no real Workspace, source tenant, OIDC service, customer RAG, live LLM, cloud outage or internet host was probed.

## Release blockers and shortest next path
1. Finish unexecuted highest-priority catalog entries with independent negative+positive tests, especially source/group ACL collision, tenant IDOR under workers, stream/tool/memory output, policy reorder, cross-tenant evidence and cross-layer bypass.
2. Freeze working tree under a single maintainer, review other concurrent edits, rerun CI in a clean branch and inspect provenance of all changes.
3. Verify exactly one independent customer integration with fail-closed startup checks, alternate endpoint probes, SSE buffers and active Protect/Shadow state; exercise its actual network delivery boundary.
4. Validate real Google Workspace ACL inheritance, groups, moves, revocations and retries only in a newly authorized disposable tenant with synthetic data; measure source-change→Guard-deny p50/p95/p99 and worst seen bound.
5. Test real verified employee identity, encryption/secrets, deployment recovery, and multi-tenant load. Define acceptable availability/latency thresholds *before* claiming SLOs.

## Next commands
```bash
cd /home/white-devil/Downloads/accessproof/f15
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
TMPDIR=/dev/shm .venv/bin/python -m pytest -p pytest_asyncio.plugin -o addopts='' tests -q --disable-warnings --tb=short
.venv/bin/ruff check apps/guard/accessproof_guard/app.py apps/guard/accessproof_guard/cache.py packages/rag_sdk/protection.py tests/security/test_adversarial_guard_boundaries.py tests/security/test_adversarial_sdk_contract.py
git diff --check
git status --short
```

**Operational caution:** Active local test sessions and independent repository modifications were observed while this audit ran. No branch reset, commit, production migration, customer API call, or live deployment was performed.

## Additional independently reproduced case and later verification

**AP-ADV-05 — P1 Guard setup Host-header spoof:** The dedicated test `tests/security/test_guard_setup_peer_auth.py` reproduced a remote synthetic peer reaching GET `/setup` with `Host: localhost` (HTTP 200 instead of 403). Patched `apps/guard/accessproof_guard/app.py` to require actual loopback transport peer **and** local hostname. This regression was failing before the patch and passing afterward; local loopback setup remains functional. Reverse proxies require separate network-topology enforcement. This fifth distinct finding updates the aggregate recorded counts to **P0=2, P1=2, P2=1, P3=0**, all five locally fixed, with no claim about untested categories.

**Independent final rerun:** `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -p pytest_asyncio.plugin tests --disable-warnings --tb=short` finished **309 passed, 3 warnings, exit 0** in 200.44 seconds, captured at `/tmp/accessproof_final_full_20261020.log`. New focused race and outage tests also passed after adapting to the atomic release implementation. `git diff --check` and Ruff of the changed Guard/cache/SDK/demo/test paths passed.

**Frontend, TypeScript SDK and real browsers:** `npm --prefix web-v2 run typecheck` passed, `npm --prefix web-v2 run lint` passed, and the TypeScript SDK suite passed **4/4** using `PATH=/home/white-devil/Downloads/accessproof/f15/web-v2/node_modules/.bin:$PATH npm test` from its package directory (the first attempt without its own compiler had failed to find `tsc`). Playwright started an isolated localhost Next.js server and completed **21 passed, 1 skipped** across desktop Chrome and mobile emulation; output in `/tmp/accessproof_browser_e2e_20261020.log`. The browser suite uses mock backend routes and is **not** independent end-to-end Google authorization proof.

**Updated coverage accounting:** A01–K05 remains incomplete; this independent check adds direct proof for G01/J04 loopback ingress only. No real Google Workspace ACL tenant, cloud service, customer RAG, real LLM provider or customer credentials were accessed. **Verdict remains NOT READY** for unrestricted security production or real customer data; a restricted synthetic-data pilot is a separate narrower claim.

## Final policy-ordering attack and test checkpoint (supersedes earlier totals)

**AP-ADV-06 — P0 old grant resurrection via out-of-order ACL events:** A new isolated test `tests/security/test_policy_ordering.py` initially failed in **four cases**. The Guard cache accepted an older `ALLOW` row delivered in a newer envelope after a current `DENY`, permitted equal-version conflicting allows to overwrite denies, and did not reject a future child policy version. The repaired `PolicyCache.install` preserves per-row policy epochs, ignores stale revisions, favors conservative decisions for a conflicting equal epoch, and rejects a row version beyond its envelope. Changes arrived alongside another local editing process; final merged state, not exclusive authorship, is verified. Recheck: **30 targeted tests passed** including all four attack regressions and legitimate newer-grant positive control.

**LATEST full-suite result (supersedes 309): 313 passed, 3 warnings, exit 0**, in 10.73 seconds, with `TMPDIR=/dev/shm PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -p pytest_asyncio.plugin tests --disable-warnings --tb=short`. Evidence: `/tmp/accessproof_final_after_ordering_20261020.log`. TypeScript SDK **4 passed**; Next.js lint/typecheck PASS; Playwright browser **21 passed, 1 skipped**, exit 0; Ruff and git diff whitespace check PASS.

**Updated confirmed local findings:** **6 distinct** (P0 **3**, P1 **2**, P2 **1**, P3 **0**), **6 fixed locally**, **0 unresolved from these six after the last test run**. This does **not** count as completion of the 68-case A01–K05 attack catalog: the coverage matrix still contains numerous PARTIAL/NOT_RUN entries, and real Google Workspace, true employee OIDC integration, third-party customer RAG paths, provenance trust, streaming network boundaries, revocation latency, performance and multi-container reliability remain unverified. **Release verdict remains NOT READY for enterprise production or external customer data; scoped synthetic-data demonstration only until independent evidence closes the gates.**

## Latest attack round — chunk-scoped Layer 1 enforcement

**AP-ADV-10 — P1 explicit chunk allowlist widening:** I reproduced a local model-context leak in the SDK when a synthetic Guard approved one chunk of a resource but the retrieved result contained another chunk of that same resource. The old SDK matched only the source and resource IDs; `FINANCE_CANARY` therefore reached the model callback. `ProtectedRAG._authorized()` now respects an explicit `chunk_ids` allowlist, treats an empty list as a complete resource allow, and rejects malformed Guard records. The regression failed before the patch and passes after it. This is a local contract fix; Google Drive V1 itself currently authorizes files rather than independently proven chunks.

**Latest verification:** full Python suite **349 passed**; focused adversarial Guard/SDK suite **27 passed**; Ruff, scoped Mypy and compilation passed; `web-v2` lint, typecheck and production build passed; Playwright **21 passed, 1 skipped**; Compose configuration parsed successfully. No real provider, customer tenant, live model, or production endpoint was attacked.

**Current audit count:** 7 distinct locally reproduced findings: P0 **3**, P1 **3**, P2 **1**, P3 **0**. All seven are fixed locally with regression coverage. The release verdict remains **NOT READY for unrestricted production security claims** because the external-provider, customer-RAG, identity-provider, live streaming delivery, operational latency and resilience gates listed above remain unverified.

## Synthetic external-customer validation

`tests/integration/test_synthetic_customer_http_boundary.py` starts a separately listening local customer RAG and Guard over loopback TCP, with synthetic documents and short-lived locally signed employee tokens. It passed Alice positive access, Bob header-identity spoofing, tenant mismatch, and policy revocation attempts without releasing the synthetic finance canary. This closes a local HTTP-boundary gap; it is still not proof for a real customer network, external IdP, real Google Workspace or a third-party LLM stream.

**Latest full suite:** **350 passed**. This run did not contact any external system or use real credentials.

## Addendum — 2026-10-20 adversarial continuation

The existing baseline Python suite was rerun and passed. This follow-up added eight new security test functions and reproduced/fixed two additional issues: AP-ADV-07 [P1] silent deletion of undelivered security audit events under full local buffer, and AP-ADV-08 [P2] missing source-health evidence implicitly treated as healthy by an internal Guard cache API. AP-ADV-09 [P2] made audit-buffer exhaustion visible in health and machine heartbeat.

Red-before-green evidence: two audit-overflow regression failures; one missing-health regression failure; one readiness regression failure. The local root causes were corrected, focused tests passed, and the complete Python suite again returned exit code 0. The final measured Python discovery reported 349 tests collected. Repository-wide Ruff clean; full mypy successful for 95 source files on final recheck; TypeScript SDK 4 passed; web lint/typecheck/build passed; Playwright 21 passed/1 skipped; Docker Compose parse passed; git diff --check passed.

Scope: local synthetic Python/HTTP/SQLite fixtures and browser automation only. No live customer/provider credentials, Google Workspace integration, production release deployment or load/soak test. Observed concurrent source edits make the evidence snapshot-specific. Controlled synthetic-data pilot validation can proceed with written scope and preflight checks; unattended confidential-data production Protect is NOT READY.

New regressions and exact commands are documented in tests/security/test_audit_backpressure.py, tests/security/test_audit_backpressure_http.py, tests/security/test_binding_health_defaults.py, tests/security/test_audit_health.py and RUN_SECURITY_TESTS.md. Prior A01-K05 entries marked NOT_RUN/PARTIAL are not implicitly passed by the suite.

## 2026-10-20 additional user-checklist execution — latest checkpoint
Using Desktop Commander on whitedevil-Acer-ALG-AL15G-53, branch master, four additional P1 issues were reproduced with failing tests before code changes, fixed locally and covered by permanent regressions.
AP-ADV-11 same-document late chunk; AP-ADV-12 other-document late chunk allowlist mismatch; AP-ADV-13 mutable OIDC principal claim; AP-ADV-14 MFA disable recovery-code replay. Four findings identified, four repaired in working tree; no commits or production deployments.
New test files: tests/security/test_chunk_trace_reauthorization.py (4 cases); test_stable_subject_configuration.py (7 cases); test_mfa_recovery_code_replay.py (1 test). Before fixes: 3 chunk failures, 6 identity failures, 1 MFA replay failure; each was rerun successfully after patch.
Patched: packages/rag_sdk/protection.py; apps/guard/accessproof_guard/identity.py; apps/guard/accessproof_guard/onboarding.py; apps/guard/accessproof_guard/app.py; apps/api/accessproof_api/app.py.
Full Python suite on patched checkout: 362 passed, 5 warnings, exit 0 in 11.02s. Evidence log /tmp/accessproof_followup_postmfa_20261020.log. Relevant Ruff and git diff --check passed.
Outstanding: complete A01-K05 exhaustive catalog not finished; independent customer RAG hooks, streaming, real Google Workspace/IdP, multimodal/agent path coverage, performance/soak and production recovery remain unverified. Identity subject-claim migration required for custom claims. Verdict: NOT READY for unrestricted production or customer-sensitive data; local synthetic demonstration gate passing.
