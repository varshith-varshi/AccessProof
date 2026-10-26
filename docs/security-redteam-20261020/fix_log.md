# Red-team fix log — isolated copy

## AP-RT-001 — Protect-mode response downgraded (P1)
**Red:** `tests/security/test_adversarial_sdk_contract.py::test_protect_layer1_must_not_release_if_layer2_silently_reverts_to_shadow` and `...test_protect_layer1_must_not_accept_would_allow_at_layer2` failed: buffered model bytes were returned on `would_*` Layer 2 replies following Protect Layer 1.
**Fix:** `packages/rag_sdk/protection.py` now requires coherent explicit Shadow vs Protect decisions at all Guard boundaries, including late sources and retries. Missing mode is treated as Protect for compatibility. Legacy Layer 1 `block` remains a normal safe denial.
**Green:** focused tests and entire 305-item Python suite pass in the patched snapshot.

## AP-RT-002 — In-flight source-binding change allowed wrong lineage (P1)
**Red:** new `tests/security/test_cross_source_context_binding.py` reproduced an ALLOW at Layer 2 when app binding switched from source A to B with the same resource ID (both nominally allowed).
**Fix:** `apps/guard/accessproof_guard/cache.py` adds a `source_id` to one-time decision contexts and validates it at fetch and atomic finalization; `apps/guard/accessproof_guard/app.py` records and checks the originally bound source.
**Migration behavior:** old in-flight contexts have an empty source; bound Protect applications safely reject them until new Layer 1 checks are performed.
**Green:** red test now passes, existing Guard tests remain green, full 305 Python tests pass.

## AP-RT-003 — Guard outage misreported as normal denial (P2)
**Red:** `tests/unit/test_drive_rag_guard_path.py::test_protected_drive_fails_closed_when_guard_unavailable` expected 503 but received HTTP 200. No protected canary was released, but monitoring/customer feedback was misleading.
**Fix:** `drive-rag-demo/app.py` distinguishes Guard/adapter failure and mode mismatch from ordinary authorization denial, returning sanitized HTTP 503.
**Green:** synthetic demo tests pass without changing the safe-denial behavior.

## AP-RT-004 — Obsolete race injection point (test correction, not a product vulnerability)
The preexisting `tests/security/test_release_version_race.py` monkeypatched `consume_contexts`, but the current bound-application release uses `consume_contexts_with_recheck`. The test now injects a revoke into the actual finalization seam. The new atomic recheck blocked release; stable positive control passed.

## Isolated vs deployed
These changes are in `/tmp/accessproof-redteam-20261020/repo` only. A separate process was editing the active checkout. Reconcile/merge from the isolated snapshot after concurrent work is complete; do not overwrite newer active files wholesale.