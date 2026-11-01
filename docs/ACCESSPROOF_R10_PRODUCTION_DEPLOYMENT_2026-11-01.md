# AccessProof r10 production release — 2026-11-01

## Deployed and independently inspected

- AWS region: eu-north-1; EC2 instance i-0c11427d4d9c1b438.
- Deployment transport: AWS Systems Manager SendCommand (no SSH firewall change).
- API: accessproof/api:guard-readiness-r10-20261101 — healthy.
- Web: accessproof/web-v2:guard-readiness-r10-20261101 — healthy.
- Installer: r10 SHA-256 5fb0bf362ffdb3c4b19947a82c6a0efce07d909cb38d950a13a95508947f5537, mounted in web container, matching host artifact.
- Local enrolled customer Guard (Ubuntu lab): accessproof-guard-r10:20261101.
- Live Guard presence: six samples were under one second old, then five more under one second old, based on control-plane received timestamps.
- Server offline threshold: 3 seconds, activated only after the customer Guard upgrade and live receipt validation.
- Browser onboarding readiness button now uses GET /protect-readiness instead of POST /protection/enable.
- Customer Gateway cutover verifier uses the Gateway's loopback port; customer RAG stays private.

## Readiness and limits

- Public API ready and login healthy; no Protect cutover performed.
- SharePoint staging is still protect_pending. Source certificate is not verified; nine mandatory checks are failing.
- Customer Guard remains degraded and not ready while SharePoint source ACL health is unverified; this is expected fail-closed behavior.
- One-second Guard presence is a best-effort heartbeat target, not a hard real-time SLA. No replay-resistant sequencing / lease store was added by this release.
- Durable workflow persistence, comprehensive automated live identity/provider certification, and all-route Protect challenge/cutover remain future work. Do not claim they were delivered.
- Production frontend still uses 15/30-second polling; it is not a one-second event-driven connectivity dashboard.
- Production disk approximately 95% used and 1.1 GB free after build; plan capacity cleanup without removing current images/rollback assets.
- Old source files and unrelated preexisting uncommitted work were not deployed.

## Rollback

- Production r10 release directory: /home/ubuntu/accessproof-releases/guard-readiness-r10-20261101
- Backup of prior .env and Compose: r10/rollback/.env, r10/rollback/docker-compose.ec2.yml
- r10/rollback/docker-compose.ec2.yml.before-guard-3s captures configuration with transitional 30-second timeout.
- API/web deployment script: r10/deploy.sh; 3s rollout script: r10/enable-guard-3s.sh.
- Local Guard Compose backup: ~/Downloads/accessproof-guard-0.1.4/compose.yml.before-r10.
- Existing r8 API/r9 web images and original Gateway ZIP were retained for rollback.

## Production verification

- SSM SendCommand result for r10 switch: 2f207d78-dda2-44e1-b884-03cee0595f84, Success.
- 3-second Guard timeout rollout: 03169426-e445-473e-929d-b3ddf97340ef, Success.
- Post-release live verification: 9b6fe65d-971e-449e-a64b-ac47d29e255c, Success.
- The post-release SharePoint verifier printed NO_GO and safe_to_enable_protect=false.
