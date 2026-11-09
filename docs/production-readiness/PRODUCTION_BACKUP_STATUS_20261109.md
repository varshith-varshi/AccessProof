# AccessProof — live production backup, restore and renewal evidence

**Evidence date:** 2026-11-09 (Asia/Kolkata). All statuses below are observed, not promises of future work. Do not label full customer readiness or full RTO/RPO as certified.

## Live encrypted PostgreSQL backups: operational

- Production EC2: `i-0c11427d4d9c1b438` (AWS role `AccessProofEC2SSMManaged20261101`, not AWS root).
- Bucket: `accessproof-prod-db-backups-102076848988-eu-north-1` (private, SSE-KMS, versioning, 30-day Object Lock GOVERNANCE retention). On November 9 a database-prefix-only S3 lifecycle rule was verified live: expire current backup objects after 32 days, noncurrent versions after 1 day (subject to Object Lock), abort incomplete multipart uploads after 2 days. Both proposed CloudFormation change sets unexpectedly touched IAM policy resources and were discarded. The lifecycle was installed directly on the bucket and saved as `deploy/backup/database-object-lifecycle.json`; it is not declared in the currently deployed CloudFormation stack. A subsequent AWS stack-drift check returned `IN_SYNC`, but that does **not** mean this extra out-of-band property is controlled by CloudFormation; future bucket updates must preserve it.
- Encryption key: `arn:aws:kms:eu-north-1:102076848988:key/f4fa2b73-3a5e-4ae7-8919-9a013a5ba61e`.
- Scheduled SSM association `9f6b4342-356e-4a4d-bf22-1bf316ff659f`: **rate(30 minutes), version 2 of `AccessProof-Backup-FixedManualArchive`**, scoped backup writer role.
- The fixed SSM document's **exact active version 2 JSON** is retained at `deploy/backup/AccessProof-Backup-FixedManualArchive.json`. An earlier local prototype was not deployed and is intentionally excluded from this production source-of-truth. Only the fixed v2 association is active.
- Uses PostgreSQL 17 `pg_dump --format=custom` inside the existing Docker database container, streams to S3 KMS without a plaintext disk dump, checks S3 encrypted object metadata and full SHA-256 readback, and only then publishes/reads back a manifest. Incomplete objects have no commit manifest.
- Overnight verification on November 9: 16 completed scheduled executions in the available API history; 17 backup archive/manifest pairs present at first check (new pairs continued thereafter). The latest status observed through SSM was `Success`.
- Backup failure alarm: `accessproof-encrypted-db-backup-failure` — **OK**.
- The production instance root EBS volume remains **unencrypted**; encrypted copies from completed snapshots exist, but EBS in-place encryption migration is a separate approved disruptive procedure.

## Real production PostgreSQL restore: verified at database scope

- **Pinned isolated restore SSM command**: `702f0c5b-e732-4df3-90c5-c7e61803a93c`.
- Temporary host `i-0e0dafb5ce358eb57`: PostgreSQL 17 container with `--network none`, private EC2 subnet, zero inbound ports; EC2 terminated after the drill.
- Encrypted S3 archive was retrieved by the isolated restore-reader role and verified against the published SHA-256 manifest **before** `pg_restore --exit-on-error`.
- Actual restored result: **79 tables**, **59 RLS/forced-RLS tables**, **118 security policies**, **4 organizations**, Alembic `x8c9d0e1f2a3`.
- Measured database-restore script duration: **6.7 seconds**; measured age of recovery point at that drill: **577 seconds**. These measurements do **not** include provisioning the restore host, secrets recovery, customer-application recovery, tenant-by-tenant behavioral tests, or incident response.
- No general 1-hour RPO / 4-hour RTO promise may be made without a full-service outage and recovery rehearsal.

## Independent 15-minute backup freshness monitor: operational

- AWS CloudFormation stack `accessproof-production-backup-freshness-2026`: **CREATE_COMPLETE**.
- Lambda function `accessproof-prod-db-freshness` with dedicated scoped role; only `s3:ListBucket` for backup metadata, namespace-scoped `cloudwatch:PutMetricData`, and own logs. No `s3:GetObject`, no KMS decrypt, no production data, no Microsoft auth.
- EventBridge rule `accessproof-prod-db-freshness-every-15min`: **ENABLED**, `rate(15 minutes)`; invocation tested successfully.
- Metric `AccessProof/ProductionBackup:LatestArchivePairAgeSeconds`, dimension `AssociationId=9f6b4342-356e-4a4d-bf22-1bf316ff659f`. First real reading: **625 seconds**.
- Alarm `accessproof-production-backup-stale-or-monitor-missing`: **OK** at latest check, threshold **3600 seconds**, two 15-minute periods, treats missing metrics as breaching. This is metadata presence/freshness only, not archive integrity or restore verification.
- Error-event pipeline `accessproof-prod-postgres-backup-failed` -> CloudWatch Logs -> failure metric -> failure alarm also exists.
- **Alert delivery unresolved:** SNS topic `arn:aws:sns:eu-north-1:102076848988:accessproof-prod-db-backup-critical` currently has **ZERO confirmed subscriptions**. Owner must choose an operations alert email/endpoint and confirm the subscription. Do not claim humans receive alerts until this is tested.

## Independent certificate renewal: NOT active

- Dedicated AWS certifier EC2 `i-0af8a03948e7ba058` and independent KMS Ed25519 public key are verified, but its role is still read-only; it is **not** a trusted authorized production signing writer.
- The latest read-only investigation found independent watcher v3 `DEGRADED`, rather than an unexplained software crash: on November 9 around 03:47 UTC, **pilot** source VALID, route CERTIFIED, application route CERTIFIED, Gateway READY, certification healthy; **reference** source VALID and routes CERTIFIED, but application-route NOT_CERTIFIED and Gateway NOT_READY with `HEARTBEAT_EXPIRED`. Read-only evidence: SSM `df6fcd0a-16cc-4a28-bdb9-1f10c1c75cb3`. This is the root operational blocker for healthy full-scope monitoring.
- The watcher correctly returns nonzero when a monitored scope has an unhealthy required gate. Do **not** make the service green by ignoring the reference scope, disabling fail-closed gates, or fabricating Gateway heartbeats.
- The current reference Gateway remains laptop-dependent and requires genuine fresh Owner-approved pairing and independent TLS/authenticated connectivity. Microsoft Alice/Bob delegated authentication/consent and authorized token lifecycle on the independent host remain prerequisites.
- Production trust cutover / restricted `kms:Sign` are **not activated**. Existing laptop renewals must remain active until real off-laptop renewal, import, revocation tests and a witnessed laptop-off run pass.

## Remaining approvals and work

1. Owner/admin: provide approved reference RAG Gateway pairing and a permanent customer-approved Gateway/Guard host/network path independent of the laptop; perform genuine Entra employee consent (no copying tokens or passwords).
2. Infra/security review: dual-key production certifier trust cutover; restricted KMS signing; signed live evidence import and rollback; off-laptop renewal test.
3. Operations: select and confirm a human SNS alert recipient and run a test alert end-to-end.
4. SRE: complete a *full application* restore drill, verify tenant isolation with actual authorized test queries, measure full-service RTO/RPO, and approve encryption migration for the source EC2 EBS volume.
5. Use scoped AWS IAM profiles for future changes; AWS account root was used previously only for time-bounded infrastructure bootstrap and inspection.

**Current customer-facing claim:** encrypted PostgreSQL backups are automatically created and a real database-level encrypted restore has succeeded. Full independent certificate renewal and full-service disaster recovery certification are outstanding.
