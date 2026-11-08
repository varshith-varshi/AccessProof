# AccessProof independent route observer — staging host

## Deployed scope

- Installed on the staging EC2 host i-0e6d2256a1e5a6f67 as a systemd **system timer** (no user login required): accessproof-route-observer.timer invokes accessproof-route-observer.service every ~5 minutes.
- Files: /opt/accessproof-observer/always_on_route_observer.py and gateway-ca.pem (public trust anchor only). Timer and service units in /etc/systemd/system/.
- Uses only Python standard library, HTTPS with ordinary platform certificate validation for the production login/API and a pinned Gateway public CA + hostname for the **loopback reverse-tunnel** endpoint at 127.0.0.1:18443.
- Queries API /health/ready and requires status=ready and both database/Redis dependencies=ok; checks website login HTTP 200; checks Gateway /health/ready via the pinned certificate. On any failure it exits nonzero and systemd logs DEGRADED with only bounded service names and statuses.
- No employee sessions, private signing keys, API credentials, AWS write access or customer data were installed. No Protect endpoint is called. This host **does not and cannot renew certificates**.

## Verification

- Unit tests: tests/unit/test_independent_route_observer.py (success, failure, TLS inputs, API readiness schema).
- First live run: API incorrectly classified DOWN because production uses status=ready; code corrected and tests added. Second live run: all three checks UP, service exit 0, timer active.
- The API/Guard/Gateway retain independent fail-closed checks: a healthy reverse tunnel does not certify a source, grant Protect or verify Alice/Bob authorization.
- The owner laptop's remote tunnel service had restarted 91 times; observer reports DOWN when that route disappears and continues running on the separate staging instance. **It cannot keep the laptop-hosted Gateway online while the laptop is off.**
- Review from staging: sudo systemctl list-timers accessproof-route-observer.timer; sudo journalctl -u accessproof-route-observer.service -n 20 --no-pager.
- Owner may disable monitoring using sudo systemctl disable --now accessproof-route-observer.timer. No restart or production API change is needed.

## Remaining independent signing migration

Move to a dedicated isolated certifier host (not the public API or staging application host), obtain an authorized Ed25519 KMS key and pinned trust enrollment, isolated production-import IAM permissions, delegated Entra sessions from approved employees and a customer-approved private Gateway path. Use observer-only rollout followed by an approved synthetic test cycle, then real certification, and disable old laptop timers only after that evidence succeeds.

The current one-time admin pairing for sharepoint-rag-staging expired on 2026-11-04. The manually installed ap-remote-gateway does not support the standard installer-approved runtime/Compose adoption contract. Only a newly issued, Owner/Admin authorized pairing and a reviewed migration of the correct Gateway will close its authentic heartbeat gap. The separate synthetic-tenant Gateway MUST NOT be substituted. No old credential may be reused from the unrelated 8191 installation.

## 2026-11-08 transient attestation recovery (does not constitute independent signing)

- The owner's laptop tunnel had restarted 95 times. On November 8 the regular attestation of `crossserver-langchain` failed with a connection reset and `crossserver-llamaindex` failed with a connection refusal; the pilot route attested correctly. The three existing certificates were still within validity (~3.5 days remained). No stale or missing evidence was accepted as a PASS.
- After verifying the tunnel and both RAG `/health` endpoints were reachable, the authorized route-attestation service was rerun. All three routes reported `ok=true`, `matches=true`, `production_state=VALID` and the unit completed with `Result=success`.
- The certifier script now has a narrowly bounded retry for **only** transient failures while observing the current route binding. At most two retries (3 and 6 seconds backoff) gather fresh live evidence. This does **not** retry a signed mismatch, an authorization denial, certificate issuance, production import or a non-transient validation failure. Exhaustion yields `TRANSIENT_ROUTE_UNAVAILABLE` and no attestation, leaving the control plane fail-closed.
- Five isolated regression cases and the full unit/security suite passed. A second live invocation of the updated service again produced three matching VALID attestations. Current watchdog warning `ROUTE_CERTIFICATE_WATCH` refers to time remaining under four days, not an authorization bypass.
- **Limit:** This improves tolerance to a short tunnel interruption only while the laptop is operating. It does not provide an independently hosted Gateway, employee authorization or signer and must not be described as solving laptop-off renewal.
