# Retention and deletion

AccessProof minimizes retained customer AI content by default. Normal evidence favors hashes, canary matches, resource IDs, classifications and timestamps rather than indefinite raw response bodies.

## Retention

Organization retention policy supports scheduled cleanup of expired detailed evidence/run payloads. The worker periodically executes retention sweeps using `ACCESSPROOF_RETENTION_SWEEP_SECONDS`.

## Deletion

Project and organization deletion paths check active runs, detach/clean associated control-plane records, remove encrypted credentials according to policy and record deletion receipts/audit events. Provider-side synthetic resources are reconciled through tracked cleanup inventory; cleanup never relies only on resource names.

Deletion does not imply that external source-provider audit trails or backups controlled by the customer/provider are erased; those remain subject to those systems' policies.
