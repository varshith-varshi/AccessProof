# AccessProof: remaining items completed (2026-11-05)

Windows is out of scope. **Protect is OFF.** Activation needs the owner's approval (Gate J), and that is the only open item for both organizations.
Evidence: `docs/evidence/pilot-and-automation-2026-11-05/`.

## Production

| Item | Result |
|---|---|
| Storage and health before deploy | 15 GB free, all services healthy, DB at `x8c9d0e1f2a3`, restricted roles intact |
| **r38e deployed** | `r38e-enforce-e30e287-e30e2871c46f` (commit `e30e2871c46f`). api, worker and web healthy; verified backup; DB `x8c9d0e1f2a3`. Release checks: SQLite and PostgreSQL 1656 tests, 0 failures. |
| Reference org gates (r38e) | **A–I PASS**, Gate E `remote_routes_certified: 2 valid`. J needs approval. |
| **Pilot org gates (r38e)** | **A–I PASS**, Gate E `route_certified: CERTIFIED` and `remote_routes_certified: 1 valid`. Readiness **24/25** (only `HUMAN_ACTIVATION_APPROVAL_REQUIRED` is open). |

## Pilot organization (fresh customer `0fb98b25-…`), completed

1. **Independent SharePoint source certificate:**
   * Fresh live evidence came from the pilot's **own** Guard, route and RAG: effective permissions, Layer 1, identity bindings, RAG E2E (including Guard-down and signed-tamper), buffered release, and a live revocation with route trial.
   * It was signed by the offline certifier, imported and verified by production.
   * It expires **2026-12-04 21:59:43 UTC**.
2. **Gate E route challenge:** verified on the first attempt. Allow 200; deny 403 `NO_AUTHORIZED_RESOURCES`; tamper 503 `SOURCE_CONTENT_ATTESTATION_FAILED`; Layer 2 revocation 503 `AUTHORIZATION_REVISION_CHANGED` during a live SharePoint revocation. Production corroborated it against 6 Guard audit records.
3. **Employee-route cutover:** `customer_cutover_verified`, with 6 Guard audits matched. For a remote deployment, the reference Compose isolation proof is replaced by the production-enforced remote route certificate. Production must report it CERTIFIED before the cutover may run.
4. **Verification records:** the positive control, denial and Guard Layer 2 `PROVENANCE_ESCAPE` block were matched to Guard-authenticated audits. Buffering is backed by certified buffered-release evidence.

## Automation installed (certifier host; lingering on, so it runs while logged out)

| Timer | What it does |
|---|---|
| `accessproof-cert-renewal` | Reference source certificate. Daily; renews with fresh evidence when 10 days or fewer remain (30-day validity). |
| `accessproof-cert-renewal-pilot` | Same procedure for the pilot organization (profile-bound evidence). |
| `accessproof-route-attestation` | **Twice daily.** Signed live attestation of every production-certified remote route; production invalidates on any configuration change. Full 14-check re-certification only when 2 days or fewer of validity remain. An unobservable route is not attested and goes `ATTESTATION_STALE` after 24 hours (Gate E fails closed). First run: the pilot route was attested and stayed VALID. |
| `ap-refresher-lab`, `ap-refresher-pilot` | Continuous trusted-ingestion refresh (transient user services). |

## Remaining

1. **Protect activation:** owner approval (Gate J), for each organization separately.
2. **Cross-server tunnel:** it closed, and Claude may not reopen it. The two cross-server routes will go `ATTESTATION_STALE` (Gate E FAIL for the reference organization) about 24 hours after their last attestation unless it is restored. Install `deploy/certifier/accessproof-remote-rag-tunnel.service` (instructions are inside the file); the next attestation run then keeps them VALID.
3. **The `ap-refresher-*` services are transient:** they don't survive a reboot. Install them as permanent user units if the lab stays in use.

## Readiness for a first Linux customer pilot

**Technically ready, pending owner activation approval.**
* A fresh organization was onboarded through production end to end:
  * registration, SharePoint consent and sync, Entra identity;
  * Guard enrolment and Gateway pairing;
  * its own source certificate, Gate E challenge and cutover;
  * a certified remote RAG route and continuous evidence refresh.
* All production gates A–I pass for it, and renewals and route verification are automated.
