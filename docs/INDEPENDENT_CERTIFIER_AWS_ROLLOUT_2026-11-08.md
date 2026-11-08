# AccessProof independent certifier AWS rollout — 2026-11-08

INFRASTRUCTURE DEPLOYED; LIVE SOURCE/ROUTE RENEWAL NOT MIGRATED.

## Verified AWS infrastructure

- Stockholm account 102076848988; CloudFormation stack accessproof-independent-certifier-2026: CREATE_COMPLETE.
- Dedicated Amazon Linux t3.small EC2 i-0af8a03948e7ba058, private IP 172.31.48.67, private subnet subnet-0142f48636f6e35c7, no public IP, no ingress rules.
- NAT Gateway nat-0da88198727912b16 for outbound HTTPS. NAT, EIP, EC2, encrypted 30 GB EBS, KMS and network traffic incur ongoing charges.
- SSM agent online; IMDSv2 required; separate base and execution IAM roles with explicit fixed names.
- KMS Ed25519 key 0f040c1c-afc8-4227-9f9f-18aa014c5f10, enabled. Candidate public key stored at deploy/certifier/independent/candidate-public-key.json, key ID kms-certifier-2026-11, NOT registered in production trusted keys.
- Read-only host-preflight systemd timer enabled and active. Preflight Result=success; all 6 host/role/KMS metadata checks PASS.
- KMS GetPublicKey allowed for execution role; KMS Sign, SSM SendCommand and IAM CreateRole denied. Production signing and certificate import deliberately disabled.
- Operator can manage this certifier EC2 via the restricted accessproof-infra-scoped profile; production-instance SendCommand is denied.
- Temporary AdministratorAccess removed from IAM user accessproof-infra-admin. User retains role-assumption and login/self-password access only. MFA NOT ENROLLED at last check: owner must enroll promptly.

## Cleanup of failed provisioning attempts

Two failed stacks were deleted. Their retained, unused KMS keys had no aliases and were placed into AWS 7-day PendingDeletion, scheduled November 15 2026:
- 18fb9ffa-1fe1-4b31-a93d-f4248e8b3d7a
- a184cdb7-0fb4-465e-a26e-cdde7f2fd90b

The active final KMS key above remains ENABLED and was not scheduled for deletion.

## Remaining real blockers for laptop-independent renewal

1. Microsoft Entra live employee consent. Existing source certificate renewal requires Alice and Bob delegated token sockets on the laptop. Obtain fresh employee-authorized Entra sign-ins on a trusted always-on system with secure token custody, refresh/revocation controls and human reauthentication. Never copy laptop session sockets or employee passwords. App-only Graph permissions are NOT an equivalent substitute for per-employee evidence.
2. Independent Gateway/Guard path. Existing remote certification uses laptop Docker Guard, Gateway signed audit material and a laptop-originated SSH tunnel to the staging RAG host. Deploy genuine customer-approved Gateway and Guard on an always-on customer host. Issue a NEW pairing through an authorized Organization Admin session and prove TLS-pinned routing, revocation, version freshness, signed audit and Layer 1/2 challenges before changing certified routes.
3. Hardened remote evidence collector. Existing scripts/certifier/renew_source_certificate.py and scripts/live/remote_route_certification.py invoke LOCAL Docker and read local Gateway evidence. Implement an authenticated, scoped remote evidence protocol preserving source/route/tenant/revision binding. Do not fabricate PASS evidence.
4. KMS signing and production trust transition. First register the distinct NEW public key alongside the previous production pinned trust and verify rejection/rollback behavior. Only after that, allow kms:Sign with the exact ED25519_SHA_512 algorithm and explicitly restricted production read-only/import documents on the new execution role.
5. Witness an entire fresh employee-based source renewal and route recertification/import while the laptop is offline. Enable exactly one writer and disable laptop timers only AFTER this passes.

Until then: current laptop renewal timers remain enabled and production Protect/trusted signing keys remain unchanged.

## Operator verification

Non-root AWS profile: accessproof-infra-scoped, assumes role AccessProofIndependentInfraBootstrap from accessproof-infra-admin.
AWS CloudFormation stack, VPC and instance IDs can be verified with AWS CLI Describe APIs in eu-north-1.
Idempotent read-only host bootstrap: scripts/certifier/bootstrap_independent_host_ssm.py.
Cloud stack: deploy/certifier/independent/isolated-certifier-stack.json.
The bootstrap never copies signing secrets or Microsoft sessions, never enables certificate signing, and never claims source/route certification.

## Independent HTTPS and Microsoft OAuth configuration check

Read-only network probes sent through the restricted infra operator role to
the new private host returned:
- Microsoft Entra OpenID discovery: HTTP 200.
- Microsoft Graph /v1.0/me with no token: HTTP 401 (expected unauthenticated).
- Production AccessProof API /health/ready: HTTP 200.
- Microsoft Entra public-client device code endpoint for the existing
  reference sign-in app and tenant: SUCCESS, 900-second expiry, 5-second poll
  interval. The disposable device code was NOT printed or retained; no actor
  has signed in and no delegated or refresh token was obtained.

This establishes that a FRESH authorized device-code sign-in is technically
available from the private host. It does not constitute employee consent,
credential custody, service restart recovery, or valid renewal evidence.

## Independent production certificate status observation (added November 8)

After the initial host-identity preflight, the isolated EC2 now has a separate
hourly read-only watcher. CloudFormation granted the execution role exactly:
SSM SendCommand on the EXISTING AccessProof-Certifier-ProductionReadOnly
document AND the pinned production EC2 i-0c11427d4d9c1b438, plus
GetCommandInvocation to retrieve the result. It did not grant AWS-RunShellScript
on production, ProductionImport, KMS Sign, role creation, or interactive SSM.

On EC2, accessproof-independent-certificate-status.timer is enabled and
active, running independent_status_watcher.py under a hardened DynamicUser
with per-run private HOME and short-lived assumed-role credentials.
Before every run it reconfirms actual EC2 IMDSv2 identity, the expected
assumed execution role and the new KMS Ed25519 PUBLIC key metadata.
The watcher reads fresh source and route state, reports only compact
expiry/status counts, and never writes production data or creates evidence.

Successful first live run (UTC 2026-11-08 06:06:35):
- monitor_status: UP.
- SharePoint source: VALID, 26.397 days remaining.
- Two current certified routes: VALID, earliest expiry in 3.456 days.
- One historical INVALIDATED route record correctly excluded from valid counts.
- signing_enabled: false, renewal_independent: false.

The status watcher detects approaching expiry but does NOT renew certificates,
does NOT host a Gateway/Guard, and cannot independently certify any route.
Existing laptop renewal timers remain active and necessary.
Local script: scripts/certifier/bootstrap_independent_status_ssm.py.
Installed verifier timer: accessproof-independent-certificate-status.timer.
