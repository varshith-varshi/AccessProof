# Fix log — adversarial run 2026-10-20

## AP-ADV-01 — P0, Layer 2 release-time revocation race
- **Failing before:** `test_h01_revocation_between_layer2_recheck_and_release_must_deny` produced `allow` under policy version 2 after installing a deny.
- **Root problem:** separate policy recheck and context-consumption operations left a time-of-check/time-of-use gap.
- **Change:** `PolicyCache.consume_contexts_with_recheck()` validates app source/mode, checks current ACL decisions, and consumes contexts under one SQLite IMMEDIATE transaction and process lock. Guard Layer 2 calls this for bound applications. For a revoked resource it blocks. Positive allow remains working.
- **Evidence:** focused adversarial suite, paired authorized Alice/handbook controls. A policy synchronization occurring after the atomic decision but before the browser renders is a separate operational timing boundary; do not claim impossible-to-race network delivery.

## AP-ADV-02 — P1, SDK Guard outage surfaced as unhandled exception
- **Failing before:** `test_t5_buffered_stream_with_untrusted_late_source_releases_no_canary` raised `httpx.HTTPStatusError: 403` during late-source authorization.
- **Change:** `ProtectedRAG.run` returns a structured `block` with `response=None` on Guard transport and adapter exceptions; no raw model content returned. Demo protected endpoint maps Guard errors to HTTP 503 (additional change observed during ongoing local work).
- **Positive checks:** normal retrieval and explicit Shadow behavior still function.

## AP-ADV-03 — P0, Protect/Shadow decision mismatch at Layer 2
- **Failing before:** `test_protect_layer1_must_not_release_if_layer2_silently_reverts_to_shadow` and `test_protect_layer1_must_not_accept_would_allow_at_layer2` returned `would_block/would_allow` with forbidden buffered output rather than blocking.
- **Change:** SDK uses Guard's trusted initial mode; Protect accepts only Layer 1 and Layer 2 `allow`, rejects incongruent Shadow decisions and inconsistent retry/late-source modes.
- **Follow-on:** tests cover retry-mode drift, network fault classes, invalid JSON, generator interruption and explicit Shadow positive control.

## Worktree ownership
Multiple pre-existing uncommitted files and concurrent tool/test edits were observed in this same checkout. These finding IDs document observed before/after behavior; they do **not** attribute every change in the checkout to this single audit run. Review the combined diff before merging.

## AP-ADV-06 — P0, stale policy event resurrects revoked grant
- **Failing before:** four adversarial regressions in `tests/security/test_policy_ordering.py`: newer deny followed by older allow in one delta returned `allow`; older allow in a newer envelope overwrote existing deny; equal-revision conflicting update chose allow; future-revision data was incorrectly accepted. Red evidence `/tmp/accessproof_policy_order_red.log` (4 failed).
- **Root problem:** `PolicyCache.install` overwrote each per-resource row using the **envelope** policy version, discarding each event's authoritative revision and allowing arbitrary ordering to reverse a deny.
- **Fix:** validate per-row event version and decision; use per-row version in SQLite UPSERT; only newer revision may replace the row, and equal-revision conflicts prefer `deny` then `unknown` over `allow`. The entire cache install stays transactional; invalid data rolls back.
- **Green evidence:** `tests/security/test_policy_ordering.py`, `tests/unit/test_guard_cache.py`, `tests/unit/test_acl_sync.py`, `tests/integration/test_guard_pipeline.py` — 21 passed. Paired positive grant after genuinely newer revision still allowed.
- **Deployment note:** existing durable cache rows written by the previous envelope-stamping algorithm should be refreshed by a trusted full snapshot when upgrading before relying on chronology claims.

## AP-ADV-05 — P1, local setup Host-header spoof
- **Before:** A synthetic non-loopback transport address could retrieve `GET /setup` by setting the HTTP `Host` header to `localhost`; the endpoint returned HTTP 200 instead of 403. Regression: `tests/security/test_guard_setup_peer_auth.py::test_remote_peer_cannot_spoof_local_setup_host`.
- **Cause:** A caller controls `Host`; its value does not prove the TCP peer originates from loopback.
- **Fix:** `apps/guard/accessproof_guard/app.py` verifies both loopback peer identity and local hostname before exposing setup endpoints. Paired genuine local peer still succeeds.
- **Limit:** An internet-facing reverse proxy can rewrite remote peer addresses; deploying the onboarding service publicly without network access controls remains unsupported.

## AP-ADV-10 — P1, explicit chunk allowlist widened to the whole document
- **Failing before:** `tests/unit/test_rag_sdk.py::test_layer1_chunk_allowlist_cannot_expose_another_chunk_of_same_document` failed locally. A synthetic Guard allowed `approved-chunk` from `finance`, but the SDK matched only `(source_id, resource_id)` and passed `forbidden-chunk` containing `FINANCE_CANARY` to the model callback.
- **Root problem:** the SDK discarded the `chunk_ids` narrowing information returned by Layer 1.
- **Change:** `_authorized()` now treats an empty chunk list as a full-resource allow and a nonempty chunk list as an exact narrowing allowlist. Malformed Guard allow records fail closed through the existing `ProtectedRAG.run()` safe-block boundary.
- **Evidence:** red reproduction followed by focused Guard/SDK tests (27 passed), full local Python suite (349 passed), Ruff and scoped Mypy. Resource-level allow remains covered by existing positive controls.

## Synthetic customer HTTP boundary validation
- **Environment:** two separately listening local Uvicorn services: a customer-facing RAG service and the Guard, with synthetic documents, an isolated SQLite policy cache, and signed local employee JWTs.
- **Test:** `tests/integration/test_synthetic_customer_http_boundary.py::test_customer_rag_and_guard_over_real_local_http_fail_closed` uses actual loopback TCP for RAG → Guard rather than an ASGI mock transport.
- **Observed:** Alice received only `PUBLIC_FACT`; Bob could not impersonate Alice with `X-User-Id`, `X-Email`, or tenant headers; a token with tenant `beta` was rejected without returning the synthetic canary; and the next request after Alice's allow was revoked returned no citation or document content.

## Continuation: audit backpressure and source health (2026-10-20)

AP-ADV-07 [P1]: The local Guard silently discarded undelivered security evidence when the audit buffer filled. Red tests reproduced the loss. The cache now evicts only acknowledged events and rejects further events transactionally; the Guard responds HTTP 503 and the SDK fails closed. End-to-end tests prove no model call at Layer 1 failure and no answer release on a Layer 2 audit failure.

AP-ADV-08 [P2]: An internal Guard cache API treated absent source-ACL health information as healthy. A failing adversarial test reproduced this condition. The cache now treats absent health as unhealthy; positive tests must explicitly provide source_acl_healthy=True.

AP-ADV-09 [P2]: A full undelivered audit backlog was invisible to Guard readiness/heartbeat. A red test reproduced this. Health now degrades with audit_buffer_ready=false; machine heartbeat emits AUDIT_BACKLOG_FULL and recovery after upload is tested.

Evidence: eight new test functions in tests/security/test_audit_backpressure.py, test_audit_backpressure_http.py, test_audit_health.py and test_binding_health_defaults.py. Complete Python pytest and additional lint/build/browser validation passed after fixes. No production deployment.

## 2026-10-20 follow-up — new P1 findings AP-ADV-11 through AP-ADV-14
- AP-ADV-11 (late same-document chunk): Before fix, a trusted trace mentioning a forbidden later chunk from the same document could result in buffered canary release; original Guard allowed only another chunk. SDK now compares exact source/resource/chunk authorization and requests a new Layer 1 decision for uncovered chunks.
- AP-ADV-12 (late other-document chunk): Before fix, a new source whose *document* matched the Guard allow response but whose *chunk* did not still caused synthetic canary release. SDK now verifies all late chunk IDs against the secondary Guard response.
- AP-ADV-13 (mutable identity key): OIDC verification and Guard enrollment accepted email/username/name as subject claim. Red tests: 6 failed and 1 positive control passed. Subject claim is now restricted to immutable sub/oid, including static Guard validation. Customer-specific claim mapping migration may be necessary.
- AP-ADV-14 (MFA recovery-code replay): A complete synthetic signup-verify-MFA-enroll-disable-reenable-disable API sequence accepted the same recovery code twice (original assertion failed with 200 instead of 400). Recovery code hash is now consumed on successful MFA disable. A distinct unused code still works.
- Red/green: chunk 3 failed/1 passed initially, then 4 passed; identity 6 failed/1 passed initially, then 7 passed; MFA 1 failed on intended replay, then passed.
- Full local Python suite after patches: 362 passed, 5 warnings, exit 0. Ruff of affected files and git diff --check passed.
- Test boundaries: synthetic MockTransport Guard responses, local SQLite, local API synthetic users only; no production, customer accounts, external Drive, or live IdP.
