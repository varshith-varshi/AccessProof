# AccessProof defect register (updated 2026-11-03)

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

## Fixed in the SharePoint Production Protect mission (2026-11-03)

Local verification only. Not deployed to production (see O-07).

### P0-01 — Runtime database role was the PostgreSQL superuser; RLS was decorative (P0)
* **Component:** `docker-compose.ec2.yml`, `migrations/`, `apps/api/accessproof_api/db_security.py`
* **Root cause:** the API and worker connected as `accessproof`, which is the
  superuser **and** owner of every table. Superusers bypass RLS, and owners
  bypass non-forced RLS. Only 39 of the 58 tenant tables had a policy, and
  none forced it. Tenant isolation therefore rested entirely on application
  `WHERE` clauses.
* **Fix:**
  * Three least-privilege roles, `NOSUPERUSER NOBYPASSRLS`, owning nothing:
    * `accessproof_app` (API, tenant-scoped).
    * `accessproof_rls_admin` (worker; cross-tenant only through the policy predicate).
    * `accessproof_metrics` (SELECT-only policy, for cross-tenant aggregates).
  * Migration `t4d5e6f7a8b9` applies `ENABLE`+`FORCE` RLS and one canonical
    predicate to all 58 tenant tables. The 13 bootstrap tables are
    documented individually with a reason.
  * `scripts/provision_database_roles.py` provisions the roles and then
    verifies them **by connecting as each role**.
  * `enable_least_privilege_db.sh` performs the production switch. It
    requires `--approve-database-role-change`.
* **Found by running as the restricted role:** about 184 tests failed until
  tenant context was set at signup, Guard enrollment, runner registration,
  OAuth/consent callbacks, pairing claim and Google webhook ingestion. Each
  of these paths had silently relied on superuser visibility.
* **Tests:** `tests/security/test_postgres_tenant_isolation.py`. The full
  suite also runs on PostgreSQL with the API as `accessproof_app`.

### D-05 — `provider_revision` columns were INTEGER; Microsoft revisions overflow (P1, fail-closed)
* Found only on PostgreSQL, since SQLite has no width limit. Migration
  `u5e6f7a8b9c0` widens six columns to BIGINT. Its downgrade refuses if any
  value is above 2^31-1.

### D-06 — Output sanitizer v1 bypassable (P1 exfiltration)
* HTML-entity-encoded URLs in inline CSS and event handlers, protocol-relative
  and backslash URLs, userinfo and IDN tricks all slipped past (8+ bypass
  classes).
* v2 (`packages/rag_core/output_safety.py`) does the following:
  * Normalizes the text: NFKC, up to 3 rounds of entity decoding, and
    stripping of invisible characters.
  * Escapes every HTML tag opener outside code.
  * Parses URLs WHATWG-style against a default-deny host allowlist.
* Verified in a **real Chromium renderer** (`test_output_exfiltration_real_renderer.py`).

### D-07 — Shared conversations trusted a caller-supplied participant list (P1)
* A caller could omit a recipient. The Gateway now defaults to
  `single_user`. In `roster_required` mode it accepts only a short-lived
  Ed25519 roster signed by a pinned adapter key
  (`packages/rag_core/roster.py`), and the verified participants must equal
  the roster exactly.

### D-08 — `/metrics` would report false-calm zeros under RLS (P3)
* The tenant-scoped app role sees no rows without tenant context.
  `/metrics` now reads through the SELECT-only `accessproof_metrics` role.
  The rehearsal verified that cross-tenant counts are non-zero.

### D-09 — Deploy/rollback revision check assumed hex IDs (P3, fail-safe)
* `^[0-9a-f]{12}$` rejected `u5e6f7a8b9c0`, so the deploy aborted at
  preflight. Now `^[0-9a-z]{12}$`. Found by the rehearsal.

### D-10 — Role switch mounted password files the API user could not read (P3, fail-safe)
* The files sat in a root-only 0700 directory, but the image runs as uid
  10001. A dedicated uid-10001 `secrets/` directory is now the only mount.
  Found by the rehearsal; the ERR trap restored correctly.

### D-11 — Gate runner copied files into a read-only container rootfs (P3)
* Inputs are now streamed over stdin (`--stdin-bundle`). In-memory evidence
  is judged identically to a file, and this is tested.

### D-12 — After the switch, every future migration would run as `accessproof_app` (P2 — next release outage)
* `compose run api alembic …` inherits the api service's runtime URL.
  The rehearsal proved that `accessproof_app` gets
  `must be owner of table organizations` and
  `permission denied for schema public`.
* Deploy and rollback now migrate via `owner_alembic`, which passes the
  owner URL through the environment and never in argv.

### D-13 — Re-running the switch rotated passwords; a later failure locked the API out (P1 — outage)
* The rehearsal forced a failure after the switch from a new release
  directory. The fresh passwords had already been `ALTER`ed into the
  database, and the restored `.env` held the old ones. The API crash-looped
  on `password authentication failed`, yet the script printed "RESTORE
  complete".
* **Fix:**
  * Existing passwords are reused from `.env`.
  * Restore reports success only when api and worker are healthy;
    otherwise it logs "RESTORE FAILED — ESCALATE" and exits 4.
  * `RECOVERY=1` re-syncs a diverged host.
* Re-verified: a forced failure now restores to a healthy API that is still
  `accessproof_app`.

### Production rehearsal (local stand-in, 2026-11-03)
The stand-in is a production-shaped host:
* Same compose file, same `/home/ubuntu/accessproof` layout, postgres:17,
  redis, read-only API rootfs.
* Seeded with two tenants on the r21 release.

Sequence run:
1. The real `deploy_on_ec2.sh` (r22).
2. The real `enable_least_privilege_db.sh`.
3. A 20-check HTTP probe as `accessproof_app`: login, reads, writes,
   cross-tenant refusal (403), metrics.
4. `run_security_gates.sh`.
5. The r23 deploy *on top of* least privilege.
6. A forced post-switch failure.
7. `rollback_on_ec2.sh` from r23 to r22.

Every probe passed 20/20 after each step. Gates A and I PASS when measured
live. All other gates are honestly FAIL or BLOCKED (no real Entra,
SharePoint, Guard or Gateway on the stand-in).

## Open (not fixable from code, or out of time) — carried forward

| ID | Sev | Item | Status |
|---|---|---|---|
| O-01 | P1 | No SharePoint source certificate exists; SharePoint Protect is blocked by design | **BLOCKED — external**: real Entra employee sign-in (Alice, Bob), authorized revoke/restore on the synthetic site, protected-route tests, then certifier issuance |
| O-02 | P1 | Production Guard reports `0` verified OIDC identity mappings (per 2026-11-02 docs) | BLOCKED — requires employee OIDC on the tenant |
| O-03 | P2 | Deployed Gateways predate D-02 and cannot heartbeat | Needs deploy + customer re-pair |
| O-04 | P3 | No owner-approved **onboarding reset** endpoint exists | **FIXED 2026-11-03** — owner-only preview/execute; archives (never deletes) applications; `test_application_archive_and_reset.py` |
| O-05 | P3 | No API to remove an AI application or change the selected chatbot other than re-pair | **FIXED 2026-11-03** — `POST /api/v1/current/ai-applications/{id}/archive` (soft archive, `archived_at`), restore on re-create, UI Remove button |
| O-06 | P3 | CI workflow is not in the published branch (credential could not upload it) | Owner action |
| O-07 | P2 | Production deployment of D-01..D-04, P0-01 and D-05..D-13 | BLOCKED — no AWS credentials / production network path from this environment. Release rehearsed end-to-end on a production-shaped stand-in (above) |
| O-08 | P3 | Revocation propagation latency has never been measured against the live tenant | BLOCKED with O-01 |
| O-09 | P3 | `--adopt-existing` re-pairing rotates the Gateway heartbeat credential but (by design) never restarts containers, so an adopted Gateway shows DISCONNECTED until re-installed | **FIXED 2026-11-03** — adopt enables presence on the local installation; `test_existing_gateway_presence_adoption.py` |
| O-10 | P1 | Independent certifier key does not exist yet; `ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON` unset in production | BLOCKED — owner generates the key off-host (`scripts/issue_source_certificate.py keygen`) |
| O-11 | P2 | No production platform adapter signs conversation rosters yet; Gateways must stay `single_user` | By design until a Teams/Slack adapter holds a pinned key |
| O-12 | P1 | Production approval requires a human reviewer after all technical gates pass | Not automatable by design |
