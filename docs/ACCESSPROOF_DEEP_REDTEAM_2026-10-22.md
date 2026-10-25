# AccessProof — Deep Adversarial Security Review
**Date:** 22 October 2026 | **Target:** local source tree `/home/white-devil/Downloads/accessproof/f15` | **Status:** NOT READY for uncontrolled customer Protect

## Authority, boundaries and evidentiary standard
This was a **source-assisted, synthetic penetration assessment** against the owner's authorized local repository. No production deployment, customer data, live Google Drive, Microsoft Graph, real tenant, cloud instance, or other third-party system was accessed. Existing uncommitted changes were preserved. Python tests ran against test-only SQLite; TypeScript tests used in-process mock HTTP. An isolated synthetic exploit is **not** a demonstrated compromise of the live service.

Assessment paths: SaaS API auth/roles and forged ACL ingestion; normalized provider-event processing, grant/membership revisions, tenant/source binding; Guard employee OIDC discovery/JWKS; Guard policy cache and one-time Layer 1/Layer 2 contexts; Python and TypeScript RAG SDK/adapters; application readiness, source certification, and token redemption. Existing tests covered much more; this review did not independently fuzz every endpoint or validate enterprise tenants.

## Confirmed security findings fixed in the local working tree

### AP-RT-01 — CRITICAL: untrusted human sessions could fabricate authorization events
**Attack:** `POST /api/v1/guard/permission-events` originally accepted ordinary authenticated users, including `VIEWER`, as authorities for `grant_upsert`/`grant_effect=allow`, with caller-supplied subject/resource and arbitrary provider. A valid tenant source could be presented in the payload to create a synthetic event; downstream worker can resolve it to ALLOW. A foreign-provider claim for the same source was also accepted.
**Proof:** three adversarial integration cases originally returned HTTP 201 where 403/422 was required; an authenticated malicious-ingestion synthetic case then reached `GuardEffectiveAccess.decision=allow`. See `tests/security/test_adversarial_event_ingestion.py` and `/tmp/accessproof_redteam_event_red_20261022.log`.
**Fix:** `app.py` now requires org administrator role, a separate >=32-character `X-AccessProof-Ingest-Key` matching `ACCESSPROOF_PERMISSION_EVENT_INGEST_KEY` constant-time, tenant-owned real SourceConnection, and exact provider match. No key => endpoint disabled (HTTP 503); GET requires audit-read permission. Legitimate connectors write verified events internally rather than depending on this diagnostic HTTP endpoint. Modified legacy integration test. All 5 focused tests GREEN.
**Residual:** possession of *both* org-admin auth and the server-configured ingestion key remains sufficient to forge events; this is a privileged diagnostic ingress, **not independently provider-signed evidence**. Keep this endpoint disabled on public production until replaced by dedicated scoped ingestion/machine authentication and signed verified provider observations. Do not distribute this key to end customers.

### AP-RT-02 — HIGH: equal-revision grant replay resurrected revoked access
**Attack:** sequence `grant_upsert(r=42) → grant_revoke(r=42) → delayed grant_upsert(r=42)` resulted in ALLOW. Revocation-first `grant_revoke(r=42) → grant_upsert(r=42)` also needs a permanent deny tombstone.
**Proof:** synthetic `tests/security/test_adversarial_equal_revision_replay.py` originally failed (ended `allow`), `/tmp/accessproof_redteam_equal_revision_red_20261022.log`.
**Fix:** revoke wins a same-revision tie; persist inactive grant tombstone even when no prior grant row exists; stale identical-revision reallow returns `STALE`. 2 scenarios pass. `apps/api/accessproof_api/guard_pipeline.py`.

### AP-RT-03 — HIGH: equal-revision group membership event replay resurrected group access
**Attack:** `membership_upsert(r=42) → membership_revoke(r=42) → delayed membership_upsert(r=42)` reactivated group and group-based document access. Revoke-first replay also reproduced.
**Proof:** both synthetic variants failed before patch, `/tmp/accessproof_redteam_group_revision_red_20261022.log`.
**Fix:** prevent equal-revision upsert of inactive membership; retained existing remove-first inactive record. Focused tests pass in `/tmp/accessproof_redteam_equal_revision_final_20261022.log`.

### AP-RT-04 — HIGH: Guard OIDC discovery/JWKS network SSRF
**Attack:** Guard `OidcVerifier` accepted local/link-local issuer URLs and issuer-supplied `jwks_uri=https://127.0.0.1:...` with only `https://` prefix. On a networked Guard this could cause unwanted requests into internal networks.
**Proof:** five adversarial tests in `tests/unit/test_guard_oidc.py` failed before patch (`/tmp/accessproof_redteam_oidc_ssrf_red_20261022.log`).
**Fix:** reject local/non-global literal addresses and unsafe reserved hostnames for issuer/JWKS, and for the real HTTP client validate+pin public DNS results while preserving TLS SNI. Mock HTTP clients remain injectable only in synthetic tests. `13` OIDC tests passed after patch. External DNS-rebinding and redirects were **not** tested live.

### AP-RT-05 — HIGH (defense in depth): contradictory Guard responses accepted in Python
**Attack:** synthetic Guard returned `mode=protect, decision=block` plus an ALLOW list; Python SDK previously generated and, with a synthetic Layer 2 ALLOW, released text. A late-source or regeneration Layer 1 `block` could similarly be treated as authorized when its allowlist was contradictory.
**Proof:** 3 deliberate synthetic protocol-violation tests failed RED (`/tmp/accessproof_redteam_guard_contract_red_20261022.log`).
**Fix:** explicit initial L1 BLOCK wins regardless of allowlist; additional and regeneration L1 decisions must **explicitly** be ALLOW in Protect. Normal denial retains `NO_AUTHORIZED_RESOURCES` for backwards compatibility. `8` focused regression tests GREEN after patch. **Not proof that a correctly functioning real Guard emits contradictory responses**.

### AP-RT-06 — MEDIUM: framework metadata exceptions escaped the SDK fail-closed return contract
**Attack:** untrusted/malformed retrieved document with missing resource ID throws in `RAGAdapter.normalize_document` before reaching `ProtectedRAG.run` exception barrier; a permissive customer fallback handler could then generate unguarded output. Reproduced in **Python and TypeScript**.
**Fix:** both adapters catch malformed normalization and return `{decision:"block", response:null, reason:"RESOURCE_METADATA_REQUIRED"}`. Existing + added tests GREEN, Python 4 focused and TypeScript 8 total.
**Caveat:** customer integrations must not catch/access a separate unguarded model path elsewhere; the SDK cannot enforce arbitrary application HTTP plumbing.

## Confirmed model limitation — unresolved (intentional XFAIL)

### AP-RT-07 — CRITICAL risk to customer Protect: provenance metadata is not content attestation
**Attack model:** an untrusted document/vector-store/agent/tool result can carry secret bytes while falsely claiming the exact provider resource ID of a legitimately allowed file. If the application-supplied `source_trace()` repeats that allowed ID, both Guard layers approve **metadata**, not the actual bytes the generator consumed. An incomplete application trace omitting off-path caches/tools is another form of this gap.
**Synthetic proof:** `tests/security/test_known_provenance_integrity_gap.py`; known-leak test intentionally `@pytest.mark.xfail(strict=True)`, output `x`, not reported as a pass. This is an authorization-origin integrity failure **under hostile/mis-tagged retrieval metadata**, not a remotely demonstrated exploit in a real provider integration.
**Required fix:** trusted provider-origin resource identity and bytes/chunk digest binding, immutable source identity mapping, trustworthy complete source trace spanning generation/cache/tools/memory, non-bypassable route gate, and independent customer-side route challenge verifying zero unauthorized response bytes. **Do not activate customer Protect until independently verified.**

## Other significant unresolved gaps or hypotheses

1. **Customer-side proof/activation — BLOCKER:** automatic `Enable Protection` preflight still reports `CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED`. No real authenticated, replay-safe nonce challenge of the precise customer's full response route/stream buffer and provenance instrumentation. The safe blocked state is intentional; no verified automatic activation was claimed.
2. **Microsoft source effective permissions — BLOCKER:** native SharePoint/OneDrive inherited item/site/library grants, SharePoint groups, guest/link possession, owner and remoteItem semantics, and independent live provider evidence issuer still incomplete. Source-bound HMAC certificate reader exists, but lacks live certification issuance. Graph sharing fields alone cannot prove read access. Keep Microsoft Protect blocked.
3. **Provider events are not independently cryptographically attested — HIGH:** admin+ingestion key remains a powerful diagnostic API credential; full provider-integrity proof and source-specific machine signing absent. Prefer non-public access/disabled configuration until upgraded.
4. **Admin identity mapping is attested, not independently proved — HIGH:** the current admin mapping route can mark OIDC-sub-to-source-sub `VERIFIED` without a proof-of-possession challenge to the same employee. This is an admin trust/insider misconfiguration risk; proper source/issuer identity verification requires real IdP and provider interaction.
5. **Token enrollment race — MEDIUM hypothesis, defensive change:** `exchange_guard` and `exchange_runner` selected unused redemption codes without database row locks. `.with_for_update()` added for PostgreSQL serializability. **Not reproduced with two real PostgreSQL workers**, and SQLite does not enforce FOR UPDATE; high-concurrency DB testing remains mandatory.
6. **Distributed rate limiting — MEDIUM risk:** login auth throttling uses an in-memory dictionary local to each API process with IP/email discriminator; cannot impose a cluster-wide budget across multiple workers/instances, and is bypassable by spreading requests over IPs. Needs a bounded Redis or upstream WAF rate limiter with adversarial tests.
7. **Policy propagation versus real revocation — HIGH risk:** provider APIs, Graph/Drive permission snapshots, group and ACL propagation, old grant key migration, partial pagination, outages, replay/reconciliation fairness, and cross-worker Postgres+Redis races have not been validated against controlled real tenant changes in this round.
8. **Denial of service — MEDIUM risk:** request size/element/length budgets on local Guard `FilterRequest` and `OutputRequest` are not comprehensive. Reverse proxy and data-plane rate/size limits were not penetration-tested.
9. **Customer bypass outside SDK — HIGH risk:** AccessProof cannot force a customer RAG app to use the wrapper on every path, including direct LLM APIs, websocket streams, cache reads, asynchronous tools, chat memory or alternate HTTP routes. Requires integration route attestation and runtime instrumentation.
10. **Strong guarantees need production-stack testing:** no two-worker PostgreSQL advisory-lock load/soak, Redis durability restoration, actual DNS/TLS network testing, real Entra OIDC and SharePoint guest/group proofs, or captured pre-release HTTP response byte measurements performed.

## Test execution and evidence
- **Complete isolated Python suite after initial exploit fixes:** `/tmp/accessproof_redteam_full_python_20261022.log`: 463 pass, 1 intentional XFAIL, process exit 0, 5 library deprecation warnings. This run preceded the final group replay defense and row-lock edits.
- **After group/revision change:** `/tmp/accessproof_redteam_equal_revision_final_20261022.log`: 15 pass including Guard cache and diagnostic event API, exit 0; `/tmp/accessproof_redteam_acl_integration_after_revision_20261022.log`: 19 pass across ACL, directory, Guard pipeline, equal-revision adversarial tests, exit 0.
- **Ingestion API:** 5 pass `/tmp/accessproof_redteam_event_green_20261022.log`.
- **OIDC verifier:** 13 pass `/tmp/accessproof_redteam_oidc_ssrf_green_20261022.log`.
- **Python SDK negative tests:** 4 pass `/tmp/accessproof_redteam_python_sdk_green_20261022.log`; protocol negative tests: 8 pass `/tmp/accessproof_redteam_guard_contract_green_20261022.log`.
- **TypeScript:** local tsc compile succeeded; `node --test test/*.test.mjs` 8 pass `/tmp/accessproof_redteam_ts_green_20261022.log`.
- **Provenance known gap:** `/tmp/accessproof_redteam_provenance_known_xfail_20261022.log`: one expected failure, not remediated.
- **Static checks:** Ruff on modified Python modules/tests and `git diff --check` pass.
- **Final full suite after all patches:** see `/tmp/accessproof_redteam_full_final_20261022.log`; do not claim result until exited.
- Existing Git changes from past work were preserved. No production deploy or real tenant access was performed.

## Release/security decision
**DO NOT describe AccessProof as penetration-tested or ready for customer Protect.** Confirmed direct low-privilege event forgery and equal-revision permission resurrection were reproduced and remediated locally. The **content-authenticity/provenance challenge remains demonstrated and unresolved**, and Microsoft provider effective-permission certification and customer-route automatic challenge are incomplete. A controlled shadow/instrumented validation pilot with synthetic documents may be feasible once test isolation, observability, and off-by-default controls are confirmed; a customer-enforced security guarantee is premature.
