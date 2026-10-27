# V4 deployment hardening

Production API replicas never run Alembic.  Build and publish immutable images,
then record the exact digest for every component in the release environment:

```sh
export ACCESSPROOF_API_IMAGE='registry.example/accessproof-api@sha256:<digest>'
export ACCESSPROOF_WORKER_IMAGE='registry.example/accessproof-worker@sha256:<digest>'
export ACCESSPROOF_WEB_IMAGE='registry.example/accessproof-web-v2@sha256:<digest>'
docker compose -f docker-compose.production.yml run --rm migrate
docker compose -f docker-compose.production.yml up -d api worker web
```

The migration job is serialized by deployment orchestration.  It owns the DDL
database credential; API and worker images should use a runtime credential that
cannot alter schema.  Every API process runs `scripts/check_schema.py` before
serving requests and exits when its database revision does not match the image.

Roll forward with a corrected image/migration whenever possible.  The V4 RLS
migration has a technically reversible Alembic downgrade, but its downgrade
removes database isolation and is therefore not an acceptable normal production
rollback.  Revert the application image only when it remains compatible with
the upgraded schema.

The V4 RLS policies protect control-plane reports and authorization revisions
using transaction-local organization context.  Cross-tenant maintenance must
use the DB-admin-provisioned `accessproof_rls_admin` role; an application-set
`accessproof.rls_bypass` setting must not be relied on for those tables.

Offline evidence verification requires an auditor-supplied signing-key bundle:

```sh
python scripts/verify_control_plane_report.py report.json \
  --trusted-key-bundle accessproof-trusted-report-keys.json \
  --expected-organization '<organization-id>'
```

The bundle contains the current and authorized rotated Ed25519 public keys plus
any revoked key IDs.  `--allow-untrusted-self-signed` is solely a diagnostic
mode and is never production evidence verification.
