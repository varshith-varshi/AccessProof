# AccessProof defect register (2026-11-02)

Severity scale from the mission brief: P0 disclosure/bypass, P1 broken core
authorization, P2 Guard/Gateway integration, P3 onboarding/operations, P4 UI.

## Fixed in this change (local verification only, not deployed)

### D-01 — API could mint its own SharePoint effective-permission certificates (P1)
* **Component:** `apps/api/accessproof_api/source_certification.py`
* **Root cause:** certificates were HMAC-SHA256 tagged with
  `ACCESSPROOF_SOURCE_CERTIFICATION_HMAC_KEY`, which the API process itself
  held. Anyone with the API environment (or the API itself) could produce a
  "valid" certificate and satisfy the Microsoft Protect gate. The docstring
  promised an independent certifier; the cryptography did not enforce it.
* **Security impact:** the only control preventing SharePoint Protect on
  unverified permissions was forgeable by the component it was meant to
  constrain.
* **Fix:** Ed25519 certificates. The API verifies with pinned public keys
  only (`ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON`). HMAC
  certificates are no longer accepted. If signer material is configured in
  the API environment, verification fails closed. New offline certifier
  `scripts/issue_source_certificate.py` (keygen / issue / import) signs only
  when all 14 `REQUIRED_CHECKS` are `PASS`, fresh (≤72 h), scope-matched and
  artifact-digested. `BLOCKED` / `NOT_TESTED` never count. Import re-verifies
  with the API's own check and rolls back on mismatch.
* **Migration:** `q1a2b3c4d5e6` widens `signature` to 160 chars. Production
  had 0 certificate rows, so no valid certificate is invalidated.
* **Tests:** `tests/security/test_source_certificate_trust_boundary.py`
  (10 tests) plus the updated `test_source_effective_certification.py`.
* **Operator action:** generate the certifier key **off the API host**, set
  the public-key JSON on the API, and remove any `…_HMAC_KEY` value.

### D-02 — Gateway had no authenticated liveness; "installed" could be read as "online" (P2)
* **Components:** `gateway_presence.py` (new), `db.py`, `app.py` (claim,
  heartbeat route, pairing status, activation checklist, protection
  snapshot), Gateway `presence.py` (new), `app.py`, `installer.py`,
  `customer_connect.py`, web panel.
* **Root cause:** the pairing token is consumed at claim, and nothing durable
  identified the Gateway afterwards. r19 added historical install recovery,
  but no live signal existed.
* **Fix:** the claim issues a per-installation credential (hash stored,
  returned once, rotated on re-pair). The Gateway posts
  `/api/v1/gateway-installations/heartbeat` every ~10 s with its own
  `/health/ready` verdict. The server checks credential, tenant (forced RLS),
  application, Guard/source binding, route digest and a strictly increasing
  sequence (replay → 409), and stamps receipt with the server clock.
  Connectivity is `CONNECTED` / `DISCONNECTED` / `UNKNOWN`, with readiness
  reported separately. Activation now also requires
  `GATEWAY_LIVE_AND_ENFORCEMENT_READY`. The installer writes
  `gateway-presence.env` (0600) and recreates **only** the Gateway service.
* **Migration:** `r2b3c4d5e6f7` creates `gateway_installations` with forced RLS.
* **Tests:** `tests/integration/test_gateway_presence.py` (9 tests,
  including the real API HTTP route).
* **Compatibility:** Gateways installed before this release report `UNKNOWN`
  and cannot satisfy the new activation check until re-paired. This is
  intentional: no live evidence means not activatable.

### D-03 — Production Guard accepted shared-secret (HS256) employee identity and reported ready (P1)
* **Component:** `apps/guard/accessproof_guard/app.py`
* **Root cause:** `identity_mode=static` verifies HS256 tokens with a
  shared secret. Whoever holds it (typically the customer RAG) can mint any
  employee `sub`. Production only *reported* `OIDC_IDENTITY_NOT_CONFIGURED`
  in heartbeats, while `/health` stayed `ready: true` and decisions
  continued.
* **Fix:** with `ACCESSPROOF_ENV=production`, static identity is refused
  (`503 IDENTITY_STATIC_MODE_FORBIDDEN_IN_PRODUCTION`). `/health` gains
  `identity_ready`, and `ready` requires it, so a Guard with no usable
  identity provider is never ready.
* **Tests:** `test_d03_production_guard_refuses_shared_secret_identity`.
  Three existing readiness tests had asserted `ready: true` for a Guard with
  no issuer/audience (a false-ready); they now configure OIDC explicitly.

### D-04 — Undecryptable Microsoft credentials crashed activation checks (P3, fail-closed)
* **Component:** `_application_checks` in `apps/api/accessproof_api/app.py`
* **Root cause:** `certificate_credentials` was bound inside a `try`. A
  missing or undecryptable secret (disconnected source, rotated KMS key) hit
  `UnboundLocalError`.
* **Impact:** HTTP 500 on the protection dashboard, activation status and the
  Guard heartbeat's protect-confirmation path. It failed closed but was
  unavailable and confusing.
* **Fix:** bind `{}` first. Test `test_d04_…`.

## Open (not fixable from code, or out of time) — carried forward

| ID | Sev | Item | Status |
|---|---|---|---|
| O-01 | P1 | No SharePoint source certificate exists; SharePoint Protect is blocked by design | **BLOCKED — external**: real Entra employee sign-in (Alice, Bob), authorized revoke/restore on the synthetic site, protected-route tests, then certifier issuance |
| O-02 | P1 | Production Guard reports `0` verified OIDC identity mappings (per 2026-11-02 docs) | BLOCKED — requires employee OIDC on the tenant |
| O-03 | P2 | Deployed Gateways predate D-02 and cannot heartbeat | Needs deploy + customer re-pair |
| O-04 | P3 | No owner-approved **onboarding reset** endpoint exists | NOT_IMPLEMENTED; design in `ACCESSPROOF_ONBOARDING_VALIDATION.md` |
| O-05 | P3 | No API to remove an AI application or change the selected chatbot other than re-pair | NOT_IMPLEMENTED |
| O-06 | P3 | CI workflow is not in the published branch (credential could not upload it) | Owner action |
| O-07 | P2 | Production deployment of D-01..D-04 | BLOCKED — no production access from this environment |
| O-08 | P3 | Revocation propagation latency has never been measured against the live tenant | BLOCKED with O-01 |
| O-09 | P3 | `--adopt-existing` re-pairing rotates the Gateway heartbeat credential but (by design) never restarts containers, so an adopted Gateway shows DISCONNECTED until re-installed | Known limitation of D-02; fails safe (never shows a false CONNECTED) |
