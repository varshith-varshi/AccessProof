# AccessProof — automatic post-Gateway installation verification
**Production release: 1 November 2026**

## Outcome

Gateway installation now starts the **read-only** verification flow without a
separate dashboard button or new pairing token:

1. Customer runs `python3 ~/Downloads/accessproof-gateway-connector.zip`.
2. Existing Gateway adoption or new installation uses the one-time, tenant-bound
   pairing claim (unchanged security protocol).
3. After the claim is accepted, the control plane immediately evaluates the
   current application's existing comprehensive Protect-readiness checklist.
4. The claim response includes a restricted result:
   `verification.state`, `checked_at`, `checks_passed`,
   `checks_total`, `failed_check_codes`, and explicit
   `production_certification=false` / `protect_activated=false`.
5. The installer prints the server's results and then performs the
   automatic, read-only local Gateway/Guard doctor check.
6. The onboarding page polls the existing authenticated Gateway pairing
   status every 15 seconds. When installation is reported, the server
   recomputes the security checklist and the page displays the passed/total
   counts. The existing full 9-item blocker panel remains visible.
7. When a customer downloads the installer, the new versioned link prevents
   stale ZIP caches. The bundled Gateway runtime is byte-identical to the
   previous version; only Python installation/response-display code changed.

No installation report or green preflight can mint a source certificate, forge
Guard audits, change customer traffic, or mark Protect active. A real
certification still requires appropriately consented SharePoint effective
permissions, OIDC, real machine-bound Guard HTTP/audit evidence, and separately
approved customer-facing route cutover.

## Production images

- API: `accessproof/api:auto-verification-r8-20261101`
- Web: `accessproof/web-v2:auto-verification-r9-20261101`
- Gateway installer: `accessproof-gateway-connector.zip`, SHA-256
  `27c70c3fe113db3bb8d5fd5d92fe3575cf595cb7bb100f7cf71869cf062b2588`
- Customer installer mount:
  `/home/ubuntu/accessproof-releases/auto-verification-r8-20261101/installer/accessproof-gateway-connector.zip`
- Previous images and environment/Compose backups are retained in the release
  directories; runtime backend and database migration history unchanged.
- The server rebuilt the Next.js app from source; all 24 routes remain present.
  No mutable JavaScript assets were overwritten under immutable URLs.

## Verified results

- Production web/API/Redis/PostgreSQL healthy.
- Security smoke suite **17/17 passed** after r8 deployment.
- Playwright desktop/mobile onboarding **6/6 passed**.
- Targeted Gateway automatic-verification, authentication, installation and
  certification tests passed.
- Installer payload ZIP was verified against the previous release. The
  embedded Gateway runtime SHA-256 was unchanged.
- Mounted production installer ZIP equals the local updated ZIP.
- Read-only live production verification of `sharepoint-rag-staging`:
  **14 / 23** checks passed; **9** failed.
- Failed checks include Microsoft independent effective permissions, source
  eligibility, production OIDC, Layer 1/Layer 2 evidence, provenance,
  buffering, challenge agent, and approved cutover.
- `protect_activated = false`; live application remains
  `protect_pending` until independently certified.
- Local `--doctor` correctly identifies Guard as NOT READY even though its
  Docker container is healthy.
- No tenant permission, source certificate, Guard status, RAG document ACL, or
  employee-facing route was modified by this release.

## Operational implications

Existing customers who already paired a Gateway see their readiness results
after refreshing the onboarding page; they do not need to reinstall or
re-pair. A new customer obtains the updated ZIP from the download button.

**Scope:** This automates readiness collection and reporting, not independent
provider certification, live attack/test evidence issuance, Microsoft admin
consent, or production traffic cutover. These stay fail-closed.

## Rollback

- For API restore `auto-verification-r8-20261101/.env.before-r8`.
- For web restore the prior web image with `onboarding-auto-verify-r9-20261101/.env.before-r9`
  and the Compose backup at `auto-verification-r8-20261101/docker-compose.ec2.yml.before-r8`.
- Run `docker compose -f docker-compose.ec2.yml config -q`, then recreate only
  the affected services. Do not print or distribute backups containing secrets.
