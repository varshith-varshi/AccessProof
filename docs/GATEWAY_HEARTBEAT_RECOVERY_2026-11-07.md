# AccessProof Gateway liveness and certificate reliability — 7 Nov 2026

## Incident diagnosis (read-only evidence)
- Application shown in customer UI: `sharepoint-rag-staging`. Control plane reports an expired authenticated Gateway heartbeat. This must not be confused with Docker container uptime.
- Local `ap-remote-gateway` is running and its configured Guard is reachable when checked from the correct Docker network, but its environment has **no** `ACCESSPROOF_GATEWAY_PRESENCE_*` settings. It is an older manually managed installation and cannot send authenticated heartbeats.
- Local `neuralmatrix-customer-rag-e2e-accessproof-gateway-1` also carries that application identifier, but its Guard hostname `guard` is unresolvable from its network. It reports `503 GUARD_UNAVAILABLE`; it is not the route to adopt blindly.
- A separate Gateway for `accessproof-human-validation-rag` has presence configured. Its health cannot attest for `sharepoint-rag-staging`.
- Docker `Up`, `/health/ready = 200`, authenticated presence, Guard readiness, source freshness, and independently certified protection are **distinct** checks.
- Local renewal watchdog reported current pilot/remote-route certificates valid for approximately four days (2026-11-07); the screenshot's **expired optional reference-route** certificate is not evidence that every remote route certificate expired.
- Two constraints remain: local certificate issuance depends on the owner's laptop and delegated employee sessions; a customer must provide their own authorized pairing and source consent. The cloud cannot safely invent credentials or sign employee attestations.

## Product fixes in this release
1. Customer connector returns nonzero `SETUP_INCOMPLETE` when a manual Gateway's newly issued heartbeat credential is saved but NOT installed into its runtime. The same nonzero state applies when automatic Gateway-only recreation cannot activate heartbeat reporting. No false "connected" declaration.
2. Read-only `python3 ...zip --doctor --gateway-container NAME` checks the **selected** Gateway's actual internal readiness and presence configuration rather than an unrelated Guard published on localhost. The doctor never reads, prints, uploads, or persists secret values.
3. Admin dashboard shows reason-specific recovery steps for a missing/expired heartbeat, an authenticated-but-not-ready Gateway, and an expired *reference* route certificate, without relaxing the Protect gate or falsely certifying remote routes.
4. The installer ZIP preserves the approved Gateway runtime archive and hash; only the reviewed connector and doctor code change. All four deployment-side installer pins must match the new immutable digest.

## Safe remediation for an existing customer
1. Identify ONE intended production Gateway by application ID, container and signed RAG route. Do not infer the correct container from a display name or Docker status alone. Keep test Gateways separate.
2. Resolve its app-bound `/health/ready` result using the real configured Guard and policy; `GUARD_UNAVAILABLE` generally means a Docker DNS/network/hostname problem, whereas `GUARD_NOT_READY` means Guard readiness or application binding did not pass. Never bypass Guard checks.
3. Have the authorized organization administrator generate a fresh, one-use pairing file in AccessProof. On the private customer Docker host, use the reviewed installer to **adopt** the existing certified-compatible Gateway.
4. For an installer-managed Gateway, the existing Compose override and private `gateway-presence.env` (0600) are updated and **only** the Gateway service is recreated. For a manual legacy Gateway, the connector now fails visibly until an owner applies the private heartbeat settings and restarts that ONE Gateway. Never claim completion from a pairing receipt.
5. Check a fresh authenticated receipt and `enforcement_ready_reported: true` on the backend; verify an actual customer's approved RAG route with positive, negative, tampered-source and revoke/restore cases. Re-certify only the routes with expired/invalidated evidence. Get explicit customer approval for Protect.
6. Deploy Guard/Gateway on a customer-approved **always-on** host, with persistent private configuration and `restart: unless-stopped`. No software can keep a customer-hosted Gateway online while the host itself is powered off.
7. Monitor certificate and attestation expiry before deadlines. The currently installed local renewer is not an off-host availability guarantee; moving it requires explicit delegated employee session, signer key custody and network authorization.

## Verification and deployment truth
- Unit and browser tests are required before publishing a new installer.
- Production web-only deployment must preserve API, worker, database, Redis, Nginx and Guard. Do not change source certifications, ownership approvals or route challenge results.
- The code/installer release does NOT auto-repair older, manually managed production gateways without a new customer-authorized pairing and the correct Gateway deployment identity.

## Production release verification — 2026-11-07

- **DEPLOYED:** reviewed source commit `932013c16a0188461317c69bc75d7598bd6ec887`, isolated web-only release `web-r53-gateway-recovery-932013c16a01`.
- Approved AWS SSM release command `75bc0c06-c896-4556-a916-6a19f44e5f1a` returned `Success`; server reported `WEB-ONLY RELEASE VERIFIED`, new web image healthy and API/worker/DB/Redis/Nginx container IDs unchanged.
- Independent post-release SSM preflight `ef609578-c50b-4161-acee-46a0e5330c0f` returned `Success`; live Gateway ZIP SHA-256 `ef85f28e48d4078d75cf128eb60adc87cd0962ef9fde86f1fd6a95f16ee7d159` equals reviewed package digest. Note web uses an installer bind mount, so this verification is essential.
- Public `https://app.accessproof.in/login` and `https://api.accessproof.in/health/ready` responded HTTP 200. Anonymous customer installer download redirected to login (not public ZIP access).
- Preflight after deployment reported 8 GB available, at the release minimum. Earlier web-r52 attempt failed safely with 7 GB. The operator-approved cleanup removed only seven unused release `src` staging trees after checking live Docker mounts and acquiring the release lock, raising free disk from 6.9 to 8.3 GB; no live service data or rollback files were changed.
- 137 frontend Playwright tests passed (5 skipped). Full Python unit/security suite passed. Onboarding smoke passed after updating its route-challenge regression to require a fresh authenticated Gateway heartbeat. Reviewed Gateway runtime archive bytes preserved.
- Local “doctor” applied to the two legacy `sharepoint-rag-staging` Gateways: `ap-remote-gateway` lacks authenticated presence; `neuralmatrix-customer-rag-e2e-accessproof-gateway-1` lacks presence and its configured `guard` DNS hostname is unavailable. Both correctly yield incomplete, noncertified diagnostics.
- The locally available `sharepoint-rag-staging` pairing token expired **2026-11-04 02:26:47 UTC**, so old customer Gateway status was **NOT** repaired or falsely marked CONNECTED by this web deployment. A fresh Owner/Admin-issued pairing and explicit selection of the intended verified Gateway are still required. No old Gateway was recreated or assigned new credentials.
- Read-only local renewal watchdog returned `OK` for three tracked independent remote routes, but the renewal host remains `OWNER_LAPTOP_NOT_ALWAYS_ON`; independent off-laptop certificate signer migration and customer credential custody remain separate unfinished infrastructure work.

## 2026-11-07 follow-up: manual HTTPS Gateway diagnosis
- The real `ap-remote-gateway` is an older, non-Compose, manually managed Gateway that has a *different* reviewed TLS route from the installer-managed HTTP :8090 Gateway. Docker has no healthcheck for it, yet its operator-CA-verified `https://ap-gateway.lab.internal:8443/health/ready` (local loopback mapping) returns 200. Treating it as `GUARD_UNAVAILABLE` solely because the HTTP :8090 probe fails was a misleading diagnostic.
- New read-only `--doctor --gateway-container NAME --gateway-ca-file /path/to/trusted-ca.pem --gateway-hostname NAME` verifies the operator-pinned certificate, hostname, local-only published HTTPS :8443 binding, and actual Gateway `/health/ready`; it never disables TLS verification, prints secrets or claims cloud connectivity from a local result.
- Read-only local test command for the existing reference route:
  `python3 ~/Downloads/accessproof-gateway-connector.zip --doctor --gateway-container ap-remote-gateway --gateway-ca-file ~/.ap-id/remote-gw/ca.pem --gateway-hostname ap-gateway.lab.internal`
- Result: verified HTTPS readiness PASS, authenticated heartbeat **NOT CONFIGURED**, overall doctor **incomplete** (exit 2). An invalid hostname fails TLS verification. The separate synthetic-tenant test container is NOT an eligible production Gateway; its `guard` DNS is broken.
- **Still required:** a fresh Owner/Admin-issued pairing for the actual production organization, a separately reviewed adoption method for this manually managed (non-Compose) Gateway and exact restart of that one container. Old pairings expired. No credentials or employee sessions were copied, routes modified or Protect enabled by the diagnostic fix.

## R54 manual HTTPS diagnostic release and verified remaining constraints
- **DEPLOYED:** commit `501a74cdb9a2c9cd5e8d46f2e9f4b49ae0615481`, web-only release `web-r54-tls-doctor-501a74cdb9a2`, AWS SSM `1f1c23ad-223a-436f-84a8-932e7f0ee82f` returned `Success` and `WEB-ONLY RELEASE VERIFIED`.
- Independent live server Docker check: `accessproof-web-1` image `web-r54-tls-doctor-501a74cdb9a2`, health `healthy`, actual served ZIP SHA-256 `9db1c5a90e52e22097183c84c670a6dc71046d530a4c7627787d1344ba98ffc6`. API, worker, database, Redis and Nginx unchanged. Public login and API readiness HTTP 200, anonymous ZIP request redirected to login.
- Full Python unit/security suite passed. Standalone Gateway/Guard onboarding smoke passed. The local pinned HTTPS doctor confirmed the real remote Gateway responds over TLS 1.3 with the trusted `ap-gateway.lab.internal` certificate and wrong hostname is refused.
- Found private on-host `gateway-presence.env` copies from Nov 4 for this org, but they are bound to a **staged 8191** Gateway route (`route_sha256=a9eae8d...`), not the actual 8443 manual HTTPS Gateway. These are **not** authorized to be installed into `ap-remote-gateway`; that would give misleading heartbeat evidence for a different route.
- `ap-remote-gateway` uses a manually deployed legacy image, no Docker Compose metadata, and no Docker healthcheck; the current supported `--adopt-existing` intentionally requires a hash-pinned official runtime and verified Compose RAG peer and cannot safely adopt this unsupported container without independent review and fresh organization pairing. The other `sharepoint-rag-staging`-labeled Gateway is a **synthetic organization**, and must not be used for production enrollment.
- Operator manually triggered the existing scoped route-attestation service; **all 3 of 3** remote routes reported `ok=true`, `matches=true`, `production_state=VALID` (approximately 4 days until expiry). Read-only source expiry monitor completed successfully: pilot ~27.23 days and reference ~26.97 days remaining.
- Independent renewal remains a **human/security authorization blocker**: owner-laptop Ed25519 signer, Alice/Bob delegated sessions and customer-approved route tunnel are not installed on an independent certified host; dedicated private signer/host, managed key custody, Microsoft session authorization and limited network identity are prerequisite. Read-only-only staging host is online but has no certifier service. No keys/sessions copied, source/route certificate altered, or unsupported Protect state activated.
- Production root disk after R54 release about **6.8 GB** free, less than the 8 GB *next-release preflight threshold*. Future releases require safe unused artifact cleanup; active image, current/rollback release and mounted installer must be preserved.

## Post-R54 production disk cleanup and independent verification
- Operator-approved inspection identified obsolete local release archives from R40–R44, R45-manifest, R47–R49, R51, and the failed R52 staging directory, not mounted by the live web container.
- With the production release lock held and the active R54 image verified, removed only twelve explicitly listed historical artifact.tar archive copies, leaving release directories, deploy scripts, metadata, current R54 installer, active R54 archive, and the immediate R53 rollback intact. No service was restarted.
- Root free space rose from 6.8 GB to 9.0 GB. Standard post-cleanup SSM preflight ef7ec993-44fd-4dde-9805-9a07762110ee returned Success, with DISK_FREE_GB=9, database revision x8c9d0e1f2a3, healthy services and installed ZIP SHA-256 9db1c5a90e52e22097183c84c670a6dc71046d530a4c7627787d1344ba98ffc6.
- Independent SSH verification confirms web-r54-tls-doctor-501a74cdb9a2 remains healthy and the download ZIP checksum is unchanged.
