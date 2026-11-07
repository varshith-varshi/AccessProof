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
