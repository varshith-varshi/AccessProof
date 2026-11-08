# AccessProof production remediation continuation — 2026-11-08

**Verdict: GENERAL AVAILABILITY NO-GO.** This document records evidence, not authorization to enable Protect or modify production data.

## Changes implemented locally

- `8f92f8f`: explicit selected manual legacy Gateways fail closed as `LEGACY_GATEWAY_MIGRATION_REQUIRED`.
- `3294810`: certifier stack preflight recognizes the existing CloudFormation `UPDATE_COMPLETE` stack, confirms expected non-secret outputs, refuses duplicate provisioning and keeps signing/renewal flagged disabled.
- `scripts/drills/production_backup_readiness.py`: read-only scoped AWS inspection. It refuses AWS root/default/static credential overrides, distinguishes `UNOBSERVABLE` IAM-denied state from `NONE`, and never treats snapshots or plans as a completed isolated production restore.

## Verified at continuation

- Independent certifier CloudFormation stack `accessproof-independent-certifier-2026`: `UPDATE_COMPLETE`; required EC2, execution role and KMS outputs present.
- Dedicated certifier status watcher is **read-only**; KMS signing, employee authorization and laptop-independent route renewal remain **OFF**.
- The reference application's legacy HTTPS Gateway on port 8443 is separate from the installer-managed 8090 Gateway; it lacks authenticated application presence. It cannot be adopted using prior 8191 credentials. Reference Gates E and J remain blocked pending authorized migration, paired presence, live challenge and new evidence-backed gate evaluation.
- Production EC2 `i-0c11427d4d9c1b438`, EBS `vol-049776e139f349d46`: 40 GiB, **unencrypted**. Manual snapshot `snap-006a1e5576a6df5ac` (2026-11-05) is also unencrypted. Regional AWS inventory found no AWS Backup plans, vaults or EC2 recovery points; no recurring EBS DLM policy. The restricted infrastructure role cannot list AWS Backup plans or recovery points, so the new scoped preflight correctly reports those entries as `UNOBSERVABLE` rather than asserting `NONE` from IAM denial.
- Existing local PostgreSQL synthetic isolated restore passed; there is **no production-data restore evidence** and no owner-approved RPO/RTO.

## Human-authorized completion gates

### Reference Gateway

1. Reference organization Owner/Admin generates a *fresh* one-use `sharepoint-rag-staging` pairing.
2. Approve migration of **exactly** `ap-remote-gateway` to an official hash-pinned, certified-compatible deployment preserving verified HTTPS, correct RAG/Guard route and private topology.
3. Apply the new private credential ONLY to the reviewed deployed runtime; verify server-observed authenticated heartbeat and route binding before challenge.
4. Complete live nonce/Guard challenge, permission revoke-and-restore, signed evidence and restricted Gates A–J. Do not activate Protect from a pairing receipt.

### Independent renewal

1. Review/approve dual-key production trust registration for the already provisioned KMS Ed25519 signer; negative tests and rollback before any `kms:Sign` grant.
2. Authorize least-privilege signer/import permissions and a private independent Gateway/Guard route.
3. Obtain genuine consenting Alice/Bob Entra sessions on approved independent infrastructure; never export the laptop's signer or employee tokens.
4. Complete signed renewal/import, fail-closed negative challenges, alerting, recovery and witnessed laptop-off renewal before disabling legacy timers.

### Production disaster recovery

1. Owner approves encryption migration, retention, recovery region, backup schedule and target RPO/RTO. **One-hour RPO / four-hour RTO are proposals, not measured or approved guarantees.**
2. Approve a narrowly scoped non-root backup/restore operator. Restricted existing deployer has no `ec2:CopySnapshot`; infra-scoped profile lacks AWS Backup listing permissions.
3. Establish **encrypted** production-aware backups with retention and off-host alarm. Do not assume a KMS-encrypted backup vault makes recovery points from an unencrypted EBS source encrypted; verify each actual recovery point.
4. Perform approved production-data restoration into a separate, non-egressing isolated host. Verify archive integrity, DB revision, RLS, tenant isolation, secret decryption, application startup, measured backup age and recovery time.
5. Retain immutable sanitized evidence and obtain human reviewer approval. Never restore over production or place plaintext customer dumps on the laptop.

## Integrity boundaries

No credential reuse, forged certificates, disabled checks, root privilege escalation, production service restarts, backup copy, data export, or enrollment/renewal changes were made by these read-only audits. Neither an existing healthy EC2 stack nor a passing synthetic restore is evidence of a completed production certification.
