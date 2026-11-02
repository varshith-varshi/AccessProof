# AccessProof feature matrix (2026-11-02)

Classification rules applied:

* **IMPLEMENTED_UNVERIFIED**: code exists and automated tests pass **locally
  only** (SQLite, in-process or loopback HTTP, synthetic identities).
* **VERIFIED**: this engineering session observed the behaviour against a
  real external system. *Nothing* reached that bar here, because production and
  the tenant were unreachable.
* **PRODUCTION_CERTIFIED**: requires live evidence plus an authorized
  reviewer. **No feature qualifies.**
* Prior-team live observations (e.g. the 6/6 SharePoint effective-permission
  matrix on 2026-11-02) are cited as *reported*, not re-verified.

| Group | Feature | Status | Evidence / notes |
|---|---|---|---|
| A Accounts | Signup, email verification, login, PBKDF2 hashing, password reset, sessions + revocation, TOTP MFA + recovery codes | IMPLEMENTED_UNVERIFIED | `tests/integration/test_auth_security.py`, `test_mfa_recovery_code_replay.py`, `test_browser_session.py` |
| A | Org / members / invitations / RBAC / API keys / OIDC SSO / SCIM | IMPLEMENTED_UNVERIFIED | `test_invitations.py`, `test_rbac.py`, `test_api_keys.py`, `test_oidc_sso.py`, `test_scim.py` |
| A | Tenant isolation (API + PostgreSQL RLS) | IMPLEMENTED_UNVERIFIED | `test_tenant_isolation.py`, `test_rls_context.py`. RLS policies are PostgreSQL-only and **not exercised by the SQLite suite** |
| A | Admin audit logging | IMPLEMENTED_UNVERIFIED | `_audit()` on admin mutations; `test_audit_immutability.py` |
| A | Safe owner-approved onboarding reset | **NOT_IMPLEMENTED** | No endpoint (O-04) |
| B Sources | Connect SharePoint via admin consent, boundary/root validation, ACL + directory sync, freshness cursors, reauthorize, disconnect | IMPLEMENTED_UNVERIFIED | `test_microsoft_admin_consent.py`, `test_source_lifecycle.py`, `test_source_reauthorize.py`, `test_microsoft_graph_*` |
| B | Distinct states CONNECTED vs PERMISSIONS_VERIFIED vs CERTIFIED_FOR_PROTECT | IMPLEMENTED_UNVERIFIED | Separate checks `PERMISSION_SOURCE_TRUSTED`, `MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED`, `V1_PROVIDER_SCOPE` |
| B | Google Drive V1 (regression scope) | IMPLEMENTED_UNVERIFIED | `test_google_*`, release-gate docs from 2026-10-18 |
| B | OneDrive, Confluence, Slack, Salesforce connectors | PARTIALLY_IMPLEMENTED; **UNSUPPORTED for Protect** | Not in V1 provider scope |
| C SharePoint authz | Direct/inherited/group/M365/Entra grants, moved-out, multi-member revocation | IMPLEMENTED_UNVERIFIED | `test_microsoft_permission_ingestion.py`, `test_microsoft_group_*`, `test_microsoft_reconcile_moved_out.py` |
| C | Effective-permission certification gate | IMPLEMENTED_UNVERIFIED (hardened by D-01) | No certificate issued; 2026-11-02 live 6/6 matrix *reported* by prior team |
| C | Sharing links, guests | UNSUPPORTED for Protect | Graph sharing metadata explicitly not trusted |
| D Identity | OIDC verification: issuer, audience, exp, signature, tenant, immutable `sub`/`oid`; mapping to source principal; missing mapping → deny | IMPLEMENTED_UNVERIFIED | `test_guard_oidc.py`, `test_guard_identity_mappings.py`, `test_sharepoint_graph_employee_identity.py` |
| D | Static HS256 identity forbidden in production | IMPLEMENTED_UNVERIFIED (D-03) | new test |
| D | Real Entra employee sign-in for Alice/Bob | **BLOCKED** | Needs interactive tenant sign-in (O-02) |
| E Guard | Enrollment, machine credential, policy sync, durable cache, revisions, fail-closed decisions, audit buffer, presence | IMPLEMENTED_UNVERIFIED | `test_guard_*`, `test_adversarial_guard_*`, `test_guard_atomic_snapshot_install.py` |
| E | CONNECTED vs READY separation | IMPLEMENTED_UNVERIFIED | Control-plane presence and Guard `/health` (`identity_ready` added) |
| F Gateway | Installer, pairing, single-chatbot discovery/selection, route binding, L1/L2 via Guard, attestation verification, buffered release, bypass detection, health | IMPLEMENTED_UNVERIFIED | `test_gateway_*` (≈40 files) |
| F | Durable installation identity + authenticated heartbeat | IMPLEMENTED_UNVERIFIED (**new, D-02**) | `test_gateway_presence.py` |
| G RAG integration | One selected chatbot, Compose discovery, unrelated apps untouched, route env override, rollback of own service | IMPLEMENTED_UNVERIFIED | `test_single_chatbot_choice.py`, `test_gateway_customer_zip_multiapp.py` |
| H Layer 1 | Pre-generation filter, unauthorized chunks never in context, revision binding, missing identity/app/source → deny | IMPLEMENTED_UNVERIFIED | `test_authorized_retrieval.py`, `test_gateway_real_tcp_path.py`, `test_gateway_adversarial_contract.py` |
| I Layer 2 | Signed provenance, trace completeness, late-source L1, L1==L2 revision, no regeneration, forged signature rejection | IMPLEMENTED_UNVERIFIED | `test_source_content_attestation.py`, `test_layer2_late_sources.py`, `test_authorization_revision_binding.py` |
| J Revocation | Event → revision → Guard → deny; in-flight revision change blocks release | IMPLEMENTED_UNVERIFIED | `test_revocation_timeline_api.py`, `test_twin_acl_revision_replay.py`, `test_customer_lifecycle_over_http.py` |
| J | Live SharePoint revoke/restore + measured latency | **BLOCKED** | O-01, O-08 |
| K Cache | Signed cached-answer manifests, per-employee reauthorization, revision binding, Cache-Control no-store | IMPLEMENTED_UNVERIFIED | `test_cached_answer_protection.py`, `test_multisource_cached_answer_v2.py`, `test_universal_cache_connectors.py` |
| L Streaming | SSE emitted only after L1+L2 on a fully buffered answer | IMPLEMENTED_UNVERIFIED | `GatewayService` / `completion_response`; `test_gateway_all_response_routes.py` |
| M Onboarding | Signup → source → Guard → Gateway → checks → enable, no website test worksheet | PARTIALLY_IMPLEMENTED | Works locally; live journey blocked at SharePoint certification |
| N Activation | Idempotent state machine, fails unless all checks pass, Guard acknowledgement required | IMPLEMENTED_UNVERIFIED | `test_protection_state.py`, `test_automatic_protection_preflight.py`; Gateway-live check added |
| O Monitoring | Source/Guard/Gateway/policy/revision/decision telemetry from evidence | IMPLEMENTED_UNVERIFIED | `_protection_snapshot`; Gateway connectivity added |
| P Audit/reporting | Tenant-scoped immutable audit, signed exportable reports, retention | IMPLEMENTED_UNVERIFIED | `test_control_plane_reports.py`, `test_retention_deletion.py` |
| Q Lifecycle | Re-pair, credential rotation, reconnect, disable protection (mode PATCH) | PARTIALLY_IMPLEMENTED | Reset and app removal missing (O-04, O-05) |
| R Reliability | Redis fail-closed pairing, idempotent verification runs, durable outbox, restart recovery | IMPLEMENTED_UNVERIFIED | `test_durable_verification_engine.py`, `validate_redis_durable_recovery.py` |
| S Platform | Hardened containers, TLS, backups, rollback | NOT VERIFIED HERE | Production unreachable (O-07) |
