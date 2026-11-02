# AccessProof security threat model (2026-11-02)

Assets: enterprise document content; employee identity; authorization state
(policies, revisions, certificates); Guard/Gateway machine credentials;
certifier private key; audit evidence.

| # | Threat | Control in code | Residual risk / status |
|---|---|---|---|
| T1 | Employee impersonation by sending another `sub`/email | Guard verifies OIDC signature/iss/aud/exp/tid; maps only immutable `sub`/`oid` through control-plane mappings; body/header identity ignored (`test_t2_bob_cannot_spoof_alice…`) | Static HS256 holder could mint any identity. **Now forbidden in production (D-03).** |
| T2 | Cross-tenant token substitution | `expected_tenant` (`tid`) enforced; mappings keyed by (source, issuer, subject, tenant) | Needs live Entra multi-tenant test (BLOCKED) |
| T3 | Unauthorized chunk reaches the model | Layer 1 allow-list; context built from allow-list only after attestation verification; denied candidates never generator inputs | Depends on the RAG using the Gateway contract. Direct model egress is checked by network-boundary audit, not prevented on hosts AccessProof does not control |
| T4 | Forged or altered retrieval bytes | Ed25519 attestation over exact bytes, tenant/app/source binding, pinned keys | Ingestion signing key custody is customer-side |
| T5 | Answer released after mid-request revocation | Single buffered model call; L1 and L2 revision must be equal; Guard L2 rechecks current policy | Live propagation latency unmeasured (BLOCKED) |
| T6 | Partial-stream leakage | SSE generated only from the verified buffered answer | none known |
| T7 | Cached answer reused across employee/app/tenant/revision | Signed cache manifests re-authorized per employee at current revision; `no-store` headers | Uninstrumented customer caches outside coverage (documented) |
| T8 | Forged SharePoint certificate unlocks Protect | **Ed25519, public key only in API; signer key forbidden in API env (D-01)** | Certifier key custody and its operator process are external |
| T9 | Stale "installed" shown as protected | **Authenticated, replay-protected Gateway heartbeat; activation requires fresh ready heartbeat (D-02)** | Heartbeat readiness is Gateway-reported; Protect still needs route challenges |
| T10 | Heartbeat replay / forgery | Hash-stored credential, forced-RLS tenant scoping, strictly increasing sequence, server clock, binding and route digest checks | Credential theft from the customer host would allow false liveness, but not authorization |
| T11 | Guard recovers into allow-all | Durable policy cache; never empty-allow; standalone mode only in explicit test env | none known |
| T12 | Control-plane outage | Guard enforces last valid policy until `max_policy_age`, then fails closed (`POLICY_SYNC_STALE`) | Availability trade-off is intentional |
| T13 | Pairing token replay | One-use `GETDEL`, 15-min TTL, superseded-digest check | none known |
| T14 | SSRF / plaintext upstream | `_validate_upstream_url`: HTTPS outside RFC1918/loopback; special-use IPs rejected; Gateway presence refuses plaintext remote control plane | none known |
| T15 | Audit tampering | Append-only audit; Guard durable buffer; reports signed and verifiable | Retention policy must be configured per tenant |
