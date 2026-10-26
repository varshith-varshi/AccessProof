# Adversarial attack catalog coverage matrix — 2026-10-20

**Interpretation:** All 305 local backend tests ran and passed after fixes, but test-suite success does **not** imply that all 68 catalog scenarios were independently simulated. A listed test is evidence of a **subset** of a scenario, not completeness. `BLOCKED / UNVERIFIED` means no direct, attributable end-to-end evidence from this audit.

| Catalog ID | Evidence in executed local tests | Verdict | Remaining boundary |
|---|---|---|---|
| A01 | `tests/unit/test_guard_oidc.py; tests/integration/test_auth_security.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| A02 | `tests/security/test_adversarial_guard_boundaries.py::test_t2_bob_cannot_spoof_alice_with_headers_or_body` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| A03 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| A04 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| A05 | `tests/integration/test_guard_enrollment_api.py; tests/unit/test_guard_machine_credential_permissions.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| B01 | `tests/security/test_adversarial_guard_boundaries.py::test_t1_bob_finance_denied_before_llm_while_handbook_works` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| B02 | `tests/unit/test_drive_rag_guard_path.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| B03 | `tests/security/test_adversarial_guard_boundaries.py::test_t3_cross_tenant_source_metadata_and_identity_rejected` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| B04 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| B05 | `tests/unit/test_guard_cache.py; tests/unit/test_guard_partial_and_shadow.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| B06 | `tests/security/test_cross_source_context_binding.py::test_layer2_rejects_context_from_previous_source_after_rebinding` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| B07 | `tests/security/test_adversarial_guard_boundaries.py::test_t4_protect_stale_policy_fails_closed` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| B08 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| B09 | `tests/security/test_adversarial_guard_boundaries.py::test_t2_bob_cannot_spoof_alice_with_headers_or_body` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| C01 | `tests/unit/test_layer2_late_sources.py; tests/unit/test_guard_enforcement.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| C02 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| C03 | `tests/security/test_customer_integration_hardening.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| C04 | `tests/security/test_adversarial_guard_boundaries.py::test_t5_buffered_stream_with_untrusted_late_source_releases_no_canary` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| C05 | `tests/security/test_adversarial_sdk_contract.py::test_invalid_guard_json_fails_closed` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| C06 | `tests/unit/test_layer2_late_sources.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| C07 | `tests/unit/test_guard_partial_and_shadow.py::test_regeneration_uses_freshly_authorized_resources` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| C08 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| D01 | `tests/unit/test_layer2_late_sources.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| D02 | `tests/security/test_release_version_race.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| D03 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| D04 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| D05 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| D06 | `tests/security/test_adversarial_sdk_contract.py::test_protect_layer1_must_not_release_if_layer2_silently_reverts_to_shadow` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| E01 | `tests/unit/test_google_drive_v1_security.py; tests/unit/test_acl_sync.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| E02 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| E03 | `tests/contract/test_connectors.py; tests/unit/test_provider_retry.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| E04 | `tests/unit/test_oauth_refresh.py; tests/unit/test_provider_retry.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| E05 | `tests/unit/test_guard_cache.py; tests/security/test_cross_source_context_binding.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| E06 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| F01 | `tests/security/test_tenant_isolation.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| F02 | `tests/unit/test_rbac.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| F03 | `tests/security/test_rls_context.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| F04 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| F05 | `tests/security/test_audit_immutability.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| G01 | `tests/security/test_ssrf.py; tests/security/test_http_target_auth.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| G02 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| G03 | `tests/security/test_browser_session.py; web-v2/e2e/web-v2.spec.ts` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| G04 | `tests/unit/test_secret_backends.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| G05 | `tests/security/test_sdk_guard_failures.py; tests/security/test_adversarial_sdk_contract.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| G06 | `tests/security/test_customer_integration_hardening.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| H01 | `tests/security/test_adversarial_guard_boundaries.py::test_h01_revocation_between_layer2_recheck_and_release_must_deny; tests/security/test_release_version_race.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| H02 | `tests/unit/test_guard_cache.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| H03 | `tests/security/test_customer_integration_hardening.py::test_restarted_guard_requires_fresh_source_health_sync` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| H04 | `tests/security/test_sdk_guard_failures.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| H05 | `tests/security/test_sdk_guard_failures.py; tests/unit/test_drive_rag_guard_path.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| H06 | `security_review/benchmark_guard_cache.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| H07 | `tests/integration/test_backup_restore.py; tests/integration/test_migrations.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| H08 | `tests/integration/test_observability.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| I01 | `tests/unit/test_demo_ai_security.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| I02 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| I03 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| I04 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| I05 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| J01 | `tests/unit/test_drive_rag_guard_path.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| J02 | `tests/unit/test_guard_health_readiness.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| J03 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |
| J04 | `tests/security/test_guard_setup_peer_auth.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| J05 | `tests/unit/test_guard_customer_launcher.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| K01 | `tests/unit/test_drive_rag_guard_path.py::test_protected_drive_fails_closed_when_guard_unavailable` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| K02 | `tests/security/test_customer_integration_hardening.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| K03 | `tests/security/test_audit_immutability.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| K04 | `tests/unit/test_guard_partial_and_shadow.py; tests/unit/test_drive_rag_guard_path.py` | LOCAL SUBSET VERIFIED | Full attacker variant set and real-provider/customer use not certified |
| K05 | None directly isolated here | BLOCKED / UNVERIFIED | Requires additional adversarial fixtures and/or authorized external environment |

## Invariant mapping

| Invariant | Evidence | Status |
|---|---|---|
| INV-01 | tests/unit/test_guard_oidc.py | LOCAL PARTIAL |
| INV-02 | tests/security/test_tenant_isolation.py | LOCAL PARTIAL |
| INV-03 | tests/security/test_cross_source_context_binding.py | LOCAL PARTIAL |
| INV-04 | tests/security/test_adversarial_guard_boundaries.py | LOCAL PARTIAL |
| INV-05 | tests/security/test_adversarial_sdk_contract.py | LOCAL PARTIAL |
| INV-06 | tests/security/test_sdk_guard_failures.py | LOCAL PARTIAL |
| INV-07 | tests/security/test_adversarial_sdk_contract.py | LOCAL PARTIAL |
| INV-08 | tests/security/test_release_version_race.py | LOCAL PARTIAL |
| INV-09 | tests/unit/test_guard_cache.py | LOCAL PARTIAL |
| INV-10 | tests/unit/test_drive_rag_guard_path.py | REAL CUSTOMER PATHS UNVERIFIED |
| INV-11 | tests/unit/test_layer2_late_sources.py | SEMANTIC PROVENANCE UNVERIFIED |
| INV-12 | tests/integration/test_guard_enrollment_api.py | LOCAL PARTIAL |
| INV-13 | tests/security/test_release_version_race.py | LOCAL PARTIAL |
| INV-14 | tests/security/test_audit_immutability.py | LOCAL PARTIAL |
| INV-15 | tests/security/test_sdk_guard_failures.py | LOCAL PARTIAL |
| INV-16 | tests/unit/test_guard_partial_and_shadow.py | LOCAL PASS WITH POSITIVE CONTROLS |

## Explicit absence of real-world evidence

No provider claims: no real Google Workspace mutations, no customer IdP, no customer RAG, no production network/streaming or 24/7 soak test, no independently authenticated third-party pentest. Treat all these as blocked until separately authorized and executed.
