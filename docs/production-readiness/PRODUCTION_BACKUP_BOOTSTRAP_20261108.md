# AccessProof production backup bootstrap — 2026-11-08

## Verified deployed infrastructure (not live PostgreSQL backup)

One-time AWS root infrastructure bootstrap was requested by the account owner. The infrastructure change set was reviewed before execution; no application release was performed.

CloudFormation stack: `accessproof-production-encrypted-db-backups-2026` — `CREATE_COMPLETE`.

- Encrypted private bucket: `accessproof-prod-db-backups-102076848988-eu-north-1`
- KMS key (encryption only): `arn:aws:kms:eu-north-1:102076848988:key/f4fa2b73-3a5e-4ae7-8919-9a013a5ba61e`
- Backup writer: `arn:aws:iam::102076848988:role/AccessProofProductionBackupWriter`
- Restore reader: `arn:aws:iam::102076848988:role/AccessProofIsolatedRestoreReader`
- S3: SSE-KMS verified, versioning enabled, Object Lock 30 days (GOVERNANCE), public access blocked, four bucket policy guards.
- Production host role `AccessProofEC2SSMManaged20261101`: only additional inline policy `AccessProofAssumePinnedBackupWriter` granting `sts:AssumeRole` on the **single exact writer ARN**. IAM simulation returned `allowed`. No root runtime credentials have been installed.

### Pinned read-only host preflight

SSM document `AccessProof-Backup-ProductionPreflight` v1 is parameter-free and pinned to production instance `i-0c11427d4d9c1b438`.

Run `5bb0f039-397b-4240-91f2-8da9079485e4` succeeded with:

- Python3, Docker, systemd: present.
- AWS CLI, host PostgreSQL `pg_dump`, host `pg_restore`: **missing**.
- PostgreSQL 17.11 `pg_dump` exists in the DB container.
- `/etc/accessproof-backup/config.env` and `pgpass`: absent.
- Production disk: 7 GB free (below normal release preflight's 8 GB minimum).
- Application release deployment: **not attempted**.

**Do not enable** `accessproof-production-db-backup.timer` yet; it requires a tested DB backup identity with full RLS-safe data access, runnable host utilities/approved isolation, and a successful encrypted S3 archive plus **isolated production-data restore**. Existing user data has not been exported.

### Optional emergency infrastructure recovery snapshot

Existing source volume `vol-049776e139f349d46` is 40 GiB, unencrypted.

An on-demand crash-consistent source snapshot `snap-0ba4c1748a1868f54` was initiated as a temporary unencrypted intermediate. The initial early copy attempt `snap-02389ea2f494259ad` failed with `Source snapshot is not complete` and the failed copy was deleted. The previously completed November 5 snapshot `snap-006a1e5576a6df5ac` was independently copied to encrypted historical fallback `snap-0243658cf9c7ce134`, **verified completed and KMS-encrypted**. The newer source snapshot completed, and its **fresh encrypted copy** `snap-040c53509d6090c66` independently reached `completed`, with KMS key `f4fa2b73-3a5e-4ae7-8919-9a013a5ba61e` and matching source-snapshot tag. Only after verifying that encrypted copy, the temporary unencrypted source `snap-0ba4c1748a1868f54` was deleted successfully. No application-consistent quiesce or database restore has been performed. Never delete the older pre-existing `snap-006a1e5576a6df5ac` without explicit separate authorization.

This emergency EBS copy cannot count as a proven PostgreSQL RPO/RTO or replace continuous database backups.

## Independent renewal remains gated

- Independent certifier stack: `accessproof-independent-certifier-2026` in `UPDATE_COMPLETE`, observer only.
- KMS Ed25519 key: `0f040c1c-afc8-4227-9f9f-18aa014c5f10`, enabled. Production trust and signing remain separate approvals.
- Real Alice/Bob Microsoft delegated authentication, independent private Gateway/Guard route, fresh certification evidence and owner-approved sign/import remain missing. No laptop-owned keys or employee tokens were copied.
- Reference route status for app `sharepoint-rag-staging`: at least one VALID route last attested 2026-11-08 and expiring 2026-11-15. Historical INVALIDATED route entries also exist. This is NOT laptop-independent renewal.

## Next engineering requirements

1. Refresh an approved restricted infrastructure AWS login; root must not become the operational identity.
2. Complete a safe backup runner design that does **not** grant the app arbitrary Docker, EC2, backup decryption, or customer data access.
3. Provision and verify an authorized RLS-complete PostgreSQL backup identity and a secure host/container secret delivery path.
4. Run a real encrypted backup with checksum-verified readback and an isolated authorized restore. Measure RPO and RTO; only then activate scheduling and paging.
5. Complete the certifier authentication/route/signature cutover with genuine evidence and a laptop-off test, without bypassing source/route security gates.
