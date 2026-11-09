# AccessProof production disaster recovery — approval and deployment guide

**Status (2026-11-09): AWS encrypted storage DEPLOYED, production PostgreSQL archive job SCHEDULED EVERY 30 MIN, and a real encrypted PostgreSQL 17 database restore VERIFIED on a temporary isolated EC2. Full application recovery/RTO and human alert delivery remain UNVERIFIED; no general disaster-recovery SLA is certified.**

The approved AWS storage foundation was deployed and verified. The separate live Systems Manager command `AccessProof-Backup-FixedManualArchive` **version 2** now executes under a dedicated backup-writer session every 30 minutes (association `9f6b4342-356e-4a4d-bf22-1bf316ff659f`). It has produced real encrypted, SHA-256-readback-verified PostgreSQL archives. A pinned isolated PostgreSQL 17 restore succeeded (SSM command `702f0c5b-e732-4df3-90c5-c7e61803a93c`), confirming 79 tables, 59 forced-RLS tables, and 118 policies. This proves database-level recovery, not full application recovery, tenant isolation by active user queries, or an RPO/RTO SLA. See `docs/production-readiness/PRODUCTION_BACKUP_STATUS_20261109.md` for live details and monitoring.

## Owner and infrastructure approvals required

The owner must explicitly approve the backup region, encrypted bucket name, 30-day minimum Object Lock retention and its recurring costs, recovery scope, and proposed objectives (RPO 1 hour / RTO 4 hours). **These are proposed targets, not guarantees.** The owner must also authorize a scheduled production database export, a separate isolated restore host, role and key custody, alert destination and retention lifecycle. Production and restored customer data must not be placed on the owner's laptop.

Root-level read-only inspection confirmed that production's actual EC2 IAM role is `AccessProofEC2SSMManaged20261101`, matching the instance profile name. As a one-time owner-requested bootstrap, the AWS connection deployed the scoped stack and attached an exact-ARN `sts:AssumeRole` grant from this instance role to `AccessProofProductionBackupWriter`. **Do not use root for scheduled backup runtime, ongoing renewals, or production release.** The restricted `accessproof-infra-scoped` profile's interactive login remained expired during this continuation.

The admin should also verify the approved isolated restore host IAM identity and encryption of its EBS root/data volumes, then review this template, IAM trust, bucket permissions and any existing backup facilities for duplication/conflicts.

## Reviewed infrastructure template (never run unattended)

`deploy/backup/isolated-postgres-s3-stack.yaml` creates, only when explicitly deployed:

- A private versioned S3 bucket with KMS default encryption, Object Lock and a **30-day minimum** governance retention period.
- A distinct KMS symmetric encryption key (not the Ed25519 certifier signing key), with automatic rotation.
- A backup writer role trusted only by the explicitly identified production EC2 IAM role. It cannot delete or decrypt arbitrary objects.
- A separate read-only restore role trusted by the explicitly approved restore operator.
- A bucket policy that denies plaintext transport, incorrectly encrypted object uploads and unapproved write principals.
- Retained bucket/key on stack deletion. No unrestricted public access, backup job, scheduler or production DB credentials.

Validation (read-only; already passed):

```bash
AWS_PROFILE=accessproof-infra-scoped aws cloudformation validate-template \
  --region eu-north-1 \
  --template-body file://deploy/backup/isolated-postgres-s3-stack.yaml
```

Deployment requires separately approved CloudFormation/S3/KMS/IAM privileges, `CAPABILITY_NAMED_IAM`, a globally unique approved bucket name and exact IAM role ARN parameters. Do not launch a duplicate stack. The owner must approve cost and retention before provisioning.

The original production instance IAM role also needs narrowly scoped `sts:AssumeRole` permission to assume `AccessProofProductionBackupWriter`. Keep the restore reader separate. Do not add backup writer access to the application runtime role.

## Proposed host service — uninstalled and disabled

Files are **templates**, not active jobs:

- `accessproof-production-db-backup.service`
- `accessproof-production-db-backup.timer`
- `scripts/drills/production_s3_backup.py`

After approval and AWS provisioning, an authorized production operator must install the reviewed backup script into `/opt/accessproof-backup`, create a dedicated **non-root** `accessproof-backup` user, and securely provision:

- `/etc/accessproof-backup/config.env` (non-secret approved bucket/KMS and database endpoint parameters, mode 0640).
- `/etc/accessproof-backup/aws-config` with `[profile accessproof-backup-writer]`, `role_arn` equal to the template output, and `credential_source = Ec2InstanceMetadata`; **no static credentials**.
- `/etc/accessproof-backup/pgpass` owned by the backup user, mode **0600**, never committed. Use a separately authorized PostgreSQL backup user, not the `accessproof_app` runtime account. The DB backup role must have legitimate complete-table backup access; PostgreSQL RLS must not silently filter production rows. A `pg_dump` error must block publication.
- Required runtime binaries `python3`, `pg_dump`, and AWS CLI. Network egress must be restricted to private DB and required AWS service endpoints.

The service runs an immutable named AWS profile **on the pinned production EC2 instance**, validates the dedicated role via STS and the host ID via IMDSv2, streams the custom-format dump into S3 KMS encryption, verifies KMS/size/checksum metadata, **streams the encrypted S3 object back through authorized KMS decryption directly into a SHA-256 calculation in RAM**, then uploads a separate manifest and verifies its readback. The manifest is a commit marker only after the dump, encrypted upload, full-object SHA-256 readback, and verification succeed. This requires scoped `s3:GetObject` and `kms:Decrypt` (already present in the reviewed backup writer policy) and incurs additional S3 read/KMS costs. S3 multipart `ChecksumSHA256` may be composite; unlike a full-object SHA-256, it cannot by itself establish archive identity. A checksum/readback failure must block success even if an untrusted object remains in Object Lock retention. Restore operators must always independently validate manifest format and the archive SHA-256 before use.

The template timer fires every 30 minutes. It must remain **disabled** until explicit authorization, an alarm/paging integration, IAM security review, test backups, and isolated restore validation. A timer existing or succeeding does not prove RPO/RTO compliance; a pipeline failure must page an operator.

## Approved isolated restore drill — not yet executed

1. Allocate a **separate** IAM-scoped restore host and encrypted storage, not the production EC2, the laptop or a reused customer service. Deny access from restored applications to live production databases, Microsoft/SharePoint API write paths, customers and sending services.
2. Read a specific immutable `database/*.manifest.json` using the restore reader and confirm bucket, KMS key, instance ID, timestamp, schema, object size and SHA-256.
3. Read the matching encrypted archive into the host's **encrypted, private** restore volume, verify its SHA-256 **before** executing `pg_restore`, and verify `pg_restore --list`. Do not log customer data.
4. Restore to an empty, isolated, appropriately named drill database with `pg_restore --no-owner --no-privileges` and apply reviewed restricted roles and migrations. Never restore onto the production DB.
5. Independently check completeness, Alembic revision, forced RLS and policies, organization/tenant row counts, encrypted-secret recovery under authorized key custody, application startup and read-only historical evidence. Run customer isolation tests without connecting the environment to live traffic.
6. Measure actual restore time (RTO) and latest usable certified recovery point age (RPO). Perform safe failed/corrupt backup rehearsals.
7. Record sanitized signed evidence and obtain the required reviewer/governance approval. Clean up sensitive isolated restore material per approved policy.

**Until all seven items succeed, `restore_verified = false` and disaster recovery remains open.**

## Certificate renewal is separate

The existing independent certifier EC2 is **deployed read-only**, not authorized for signing. KMS trust registration, restricted `kms:Sign`, genuine employee Microsoft consent and an independent customer-approved Gateway/Guard route are still mandatory. Do not turn the backup KMS key into a signer or move laptop-held signing keys/employee tokens to AWS.
