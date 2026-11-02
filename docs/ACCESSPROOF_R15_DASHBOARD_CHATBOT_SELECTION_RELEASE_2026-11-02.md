# r15 — choose exactly ONE chatbot in the customer dashboard

## Customer path (implemented and deployed)
1. Customer connects an approved source, creates one Gateway application and
   binds its enrolled Guard.
2. In Get Started, generate/download the short-lived pairing file (15 minutes).
3. Download and run the official Gateway ZIP once on the customer Docker host.
4. Installer discovers running Docker Compose services locally, publishes only
   sanitized service/project metadata to the paired application over HTTPS and
   waits for selection.
5. Get Started displays supported chatbot candidates as radio choices.
   Unsupported candidates are disabled. The authenticated organization admin
   clicks **Confirm this one chatbot**. A second selection is rejected.
6. The customer-side installer polls the control plane for the exact selected
   application ID, re-discovers the real Docker container and rechecks
   its Compose labels/identity and adapter compatibility before proceeding
   through the existing local Gateway installation.
7. Unselected chatbots are unchanged; no Docker socket is opened to SaaS.
   Selection, pairing, Guard liveness and RAG answer observation do **not**
   certify or activate production Protect.

## Security architecture
- Reuses already issued, 15-minute **application-scoped** pairing token;
  does not create an unrestricted host access credential.
- Machine endpoints accept only bearer pairing token; session routes require
  Result Read or Organization Admin (for final choice). Existing CSRF protection
  applies to admin mutation.
- Redis records contain only sanitized host inventory with bounded item/field
  sizes and an exact token digest. Inventory and choice inherit token lifetime.
- Redis WATCH/MULTI enforces one-time choice under concurrent admins. Token
  renewal, expiry and consumption invalidate the prior selection.
- A selected ID is NOT a Docker command, path, arbitrary URL or certificate.
  It is checked against a fresh local discovery before installer actions.
- One chatbot per current onboarding, one standard Gateway service/port.
- Existing SharePoint, production OIDC, provenance, Layer 1/2, cache, streaming
  and route authorization certification gates remain fail-closed.

## Validation
- Unit suite: 664 passed, 0 failed.
- New pairing/discovery/security-focused tests: 35 passed.
- Web build, ESLint and TypeScript: passed.
- Full Playwright desktop/mobile: 49 passed, 5 skipped.
- Docker read-only smoke of published ZIP: 14 inventory records, two supported
  RAG services, exactly one approved single-Gateway plan; not certified.
- Ruff and targeted Mypy checks passed.
- Authenticated API routes confirmed in the running production API; Redis
  connectivity verified. Anonymous machine discovery/choice requests return 401.

## Production release
- Date: 2026-11-02, AWS eu-north-1, instance i-0c11427d4d9c1b438.
- API: accessproof/api:dashboard-choice-r15-20261102
  image ID sha256:b7708dfdb3c5df203079661f65efee676048212885fa7ada0c577c840ce13197.
- Website: accessproof/web-v2:dashboard-choice-r15-20261102
  image ID sha256:9aa8df98d3909f38ee24e6a8ae285ef5ff80c81a2de62cc4f66f0e34e427717b.
- Worker unchanged: accessproof/worker:verification-r11-20261101.
- Customer installer mount: sha256:
  91a7c7d421316e882fe15003c8023bc4cc50de88cef9c6913c98cb887ae3df9a.
- API health 200, website login 200; both containers healthy.
- Rollback: /home/ubuntu/accessproof-releases/dashboard-choice-r15-20261102/rollback/
  contains previous .env and docker-compose.ec2.yml; previous images retained.
- EBS gp3 increased from 20 GB to 40 GB to avoid exhausted production disk.
  Online ext4 filesystem expanded and now has ~20 GB free.
- Temporary private release-transfer S3 bucket and permission removed.
- No production Protect cutover or live Microsoft permission changes performed.

## Important remaining limitations
- Declared Docker adapter compatibility is not proof of safe output gating.
  Arbitrary Python, non-Compose apps and multi-file Compose projects that
  cannot be safely resolved still need a supported adapter or review.
- Production Protect needs **independent live-provider SharePoint effective
  permission evidence, real Entra employee sign-in, signed Guard/Gateway
  Layer 1/2 route evidence, provenance, cache and streaming verification,
  and explicit administrator production cutover approval**. Those are not
  completed or bypassed by r15.
- Production customer-account, full Entra provider and manual RAG route
  tests were not executed here; synthetic local/API/browser regression tests
  and production authentication/health checks are not substitutes.
