# A01–K05 adversarial coverage and invariant traceability

Evidence is for the **local checkout** and tests actually executed or inspected. `PASS_LOCAL` proves the named synthetic case, not complete security of the entire catalog item. `PARTIAL` proves only the narrower named case. `NOT_RUN` is not a pass. Real customer Google Workspace and model integrations remain unverified.

| Case | Status | Test evidence | Limit / observed result |
|---|---|---|---|
| A01 | PARTIAL | tests/integration/test_auth_security.py;tests/unit/test_guard_oidc.py | Local synthetic identity tests; live IdP/JWKS unverified |
| A02 | PASS_LOCAL | tests/security/test_adversarial_guard_boundaries.py::test_t2_bob_cannot_spoof_alice_with_headers_or_body;tests/integration/test_synthetic_customer_http_boundary.py::test_customer_rag_and_guard_over_real_local_http_fail_closed | Forgery denied both at Guard API and through a local customer HTTP boundary |
| A03 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| A04 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| A05 | PARTIAL | tests/integration/test_guard_enrollment_api.py | Local Guard enrollment tested; stolen machine credential scenarios not exhaustive |
| B01 | PASS_LOCAL | tests/security/test_adversarial_guard_boundaries.py::test_t1_bob_finance_denied_before_llm_while_handbook_works;tests/security/test_adversarial_guard_boundaries.py::test_b01_end_to_end_sdk_never_passes_bobs_denied_finance_to_model;tests/unit/test_rag_sdk.py::test_layer1_chunk_allowlist_cannot_expose_another_chunk_of_same_document | Mixed resources filtered; forbidden document and same-document forbidden chunk absent from actual model callback |
| B02 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| B03 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| B04 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| B05 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| B06 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| B07 | PARTIAL | tests/security/test_adversarial_guard_boundaries.py::test_t4_protect_stale_policy_fails_closed | Stale policy denies; not all provider 429/5xx |
| B08 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| B09 | PARTIAL | tests/security/test_adversarial_guard_boundaries.py::test_t2_bob_cannot_spoof_alice_with_headers_or_body | Headers did not override verified subject |
| C01 | PARTIAL | tests/security/test_adversarial_guard_boundaries.py::test_c06_forged_provenance_is_blocked_and_context_cannot_be_replayed | Forged source IDs rejected |
| C02 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| C03 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| C04 | PARTIAL | tests/security/test_adversarial_guard_boundaries.py::test_t5_buffered_stream_with_untrusted_late_source_releases_no_canary | Buffered Python SDK; live SSE/WebSocket not tested |
| C05 | PARTIAL | tests/security/test_adversarial_sdk_contract.py::test_invalid_guard_json_fails_closed | Invalid response fail-closed |
| C06 | PASS_LOCAL | tests/security/test_adversarial_guard_boundaries.py::test_c06_forged_provenance_is_blocked_and_context_cannot_be_replayed | No forged additional source, replay blocked |
| C07 | PARTIAL | tests/security/test_adversarial_sdk_contract.py::test_protect_regeneration_must_not_release_after_downgraded_retry | Synthetic retry drift |
| C08 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| D01 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| D02 | PASS_LOCAL | tests/security/test_adversarial_guard_boundaries.py::test_h01_revocation_between_layer2_recheck_and_release_must_deny | Post-layer1 deny blocks output |
| D03 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| D04 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| D05 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| D06 | PASS_LOCAL | tests/security/test_adversarial_guard_boundaries.py::test_d06_mode_switch_during_final_verification_cannot_release | Binding mode rollover safe deny |
| E01 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| E02 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| E03 | PASS_LOCAL | tests/security/test_policy_ordering.py | Four red-before/green-after ordering cases; real Drive delta sync not tested |
| E04 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| E05 | PASS_LOCAL | tests/security/test_adversarial_guard_boundaries.py::test_h01_revocation_between_layer2_recheck_and_release_must_deny; tests/security/test_policy_ordering.py | Cache revoke/replay guarded; provider propagation unverified |
| E06 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| F01 | PARTIAL | tests/security/test_tenant_isolation.py | Existing local tenant isolation suite; every route not manually reviewed |
| F02 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| F03 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| F04 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| F05 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| G01 | PARTIAL | tests/security/test_guard_setup_peer_auth.py::test_remote_peer_cannot_spoof_local_setup_host | Forged Host prevented on direct remote peer; broad API/SSRF not complete |
| G02 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| G03 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| G04 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| G05 | PASS_LOCAL | tests/security/test_adversarial_sdk_contract.py::test_guard_post_generation_http_error_is_an_explicit_safe_block | 401/403/429/500/503 safe block; positive control |
| G06 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| H01 | PASS_LOCAL | tests/security/test_adversarial_guard_boundaries.py::test_h01_revocation_between_layer2_recheck_and_release_must_deny | Forced deterministic policy rollover; atomic boundary |
| H02 | PARTIAL | tests/unit/test_guard_cache.py | Local concurrency tests; no large load |
| H03 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| H04 | PARTIAL | tests/security/test_adversarial_guard_boundaries.py::test_h04_source_acl_unhealthy_during_layer2_blocks_release | Source unhealthy safe reject |
| H05 | PARTIAL | tests/security/test_adversarial_sdk_contract.py::test_guard_post_generation_http_error_is_an_explicit_safe_block | Mock Guard HTTP errors |
| H06 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| H07 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| H08 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| I01 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| I02 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| I03 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| I04 | PARTIAL | tests/security/test_adversarial_guard_boundaries.py::test_t5_buffered_stream_with_untrusted_late_source_releases_no_canary | Simulated secret in buffered generated text; semantic memory not tested |
| I05 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| J01 | PARTIAL | tests/security/test_adversarial_sdk_contract.py::test_protect_layer1_must_not_release_if_layer2_silently_reverts_to_shadow | Mode contract drift; missing hooks unverified |
| J02 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| J03 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| J04 | PARTIAL | tests/security/test_guard_setup_peer_auth.py::test_remote_peer_cannot_spoof_local_setup_host | Loopback-peer protection verified; reverse-proxy forwarding may obscure true client |
| J05 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| K01 | PARTIAL | tests/unit/test_drive_rag_guard_path.py::test_protected_drive_fails_closed_when_guard_unavailable | Demo now returns HTTP503 |
| K02 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| K03 | NOT_RUN | — | Not independently executed during this adversarial continuation |
| K04 | PARTIAL | tests/security/test_adversarial_guard_boundaries.py::test_t1_bob_finance_denied_before_llm_while_handbook_works | Alice and handbook positive controls |
| K05 | NOT_RUN | — | Not independently executed during this adversarial continuation |

## INV-01..INV-16 trace

| Invariant | Local evidence / state |
|---|---|
| INV-01 | A02 PASS_LOCAL; synthetics only |
| INV-02 | A02, F01 PARTIAL; source IDs and tenant-bound Guard fixtures |
| INV-03 | B01 PARTIAL; real Drive effective ACL semantics unverified |
| INV-04 | B01 T1 mixed retrieval safe; upstream embeddings/rerank not covered |
| INV-05 | C04/C06 scoped buffered SDK safe; customer streams unverified |
| INV-06 | B07 T4 and H04 safe reject |
| INV-07 | D06 PASS_LOCAL; SDK Protect-to-Shadow mismatch blocked |
| INV-08 | D02/H01 release-time revoke checked; upstream propagation pending |
| INV-09 | E03/E05 four local policy event-order and old grant regressions PASSED; live Drive events blocked |
| INV-10 | J01 application-specific hooks unverified |
| INV-11 | C06 source ID/provenance case passed; arbitrary model text cannot be verified |
| INV-12 | F01 local API tenant authorization partial |
| INV-13 | H01 atomic SQLite recheck demonstrated; network delivery race remains |
| INV-14 | C06 evidence metadata local suite partial |
| INV-15 | H04/H05 local faults; real outages not load tested |
| INV-16 | T1 Alice and handbook allowed; SDK Shadow positive controls |

**Counts:** 9 catalog cases with narrow PASS_LOCAL evidence; 18 partial; 41 NOT_RUN. This count describes **catalog entries**, not distinct executed attacker attempts or pytest parameter combinations.

## 2026-10-20 continuation — new execution evidence (supplemental)

| Attack area | Status | Executed evidence | Limit |
|---|---|---|---|
| G05/H05/K02 — Guard outage and safe errors | PASS_LOCAL | tests/security/test_audit_backpressure_http.py | Synthetic HTTP + SQLite only |
| H07 — Audit queue exhaustion and evidence durability | PASS_LOCAL | tests/security/test_audit_backpressure.py | No sustained real customer outage tested |
| B07/H04 — Source-health uncertainty on Protect | PASS_LOCAL | tests/security/test_binding_health_defaults.py | Cache boundary; real Drive provider remains blocked |
| K01/K03 — Readiness and heartbeat accuracy | PASS_LOCAL | tests/security/test_audit_health.py | Local health and synthetic heartbeat only |

Eight new adversarial test functions and corresponding positive controls executed in this continuation. The earlier counts were a snapshot prior to these additions; other NOT_RUN and PARTIAL categories remain unverified. Do not infer full A01-K05 coverage from the passing Python suite.

## 2026-10-20 additional checklist coverage (scoped local evidence)
| Category / invariant | Result | Tests and limitations |
|---|---|---|
| A03 / INV-01 stable user principal | PASS_LOCAL narrowly | tests/security/test_stable_subject_configuration.py rejects mutable subject configuration; external issuer/account reassignment NOT VERIFIED |
| B05, C06 / INV-04 and INV-05 late cache/tool chunks | PASS_LOCAL narrowly | tests/security/test_chunk_trace_reauthorization.py: 2 denied and 2 legitimate late source cases with MockTransport; live RAG memory/tools NOT VERIFIED |
| D01 / INV-05 late provenance after model generation | PASS_LOCAL narrowly | Same SDK tests: canary not released when late chunk not authorized; semantic leakage remains NOT VERIFIED |
| A01 management authentication MFA recovery replay | PASS_LOCAL narrowly | tests/security/test_mfa_recovery_code_replay.py; sequential reuse blocked; concurrent replay NOT VERIFIED |
| Other A01-K05 catalog cases | UNCHANGED | Earlier PARTIAL or NOT_RUN cases are not promoted to PASS from unrelated test success |

Full backend after repair: 362 passed, 5 warnings, exit 0. Test scope is synthetic local only.
