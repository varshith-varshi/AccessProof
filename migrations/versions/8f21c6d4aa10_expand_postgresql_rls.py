"""Expand PostgreSQL RLS to newer tenant-owned tables.

Revision ID: 8f21c6d4aa10
Revises: 73c9d4e812ab
"""

from alembic import op

revision = "8f21c6d4aa10"
down_revision = "73c9d4e812ab"
branch_labels = None
depends_on = None

# These tables can always be accessed after AccessProof knows the tenant.
# Bootstrap/authentication lookup tables whose tenant is intentionally derived
# from an opaque one-time credential (invitations, OIDC login state, SCIM config,
# runner/registration identity) are deliberately excluded; application-layer
# authorization remains authoritative for those tables.
TABLES = (
    "api_keys",
    "oidc_configurations",
    "oidc_identities",
    "scim_identities",
    "retention_policies",
    "audit_events",
)


def _predicate() -> str:
    return (
        "(current_setting('accessproof.rls_bypass', true) = 'on' "
        "OR organization_id = current_setting('accessproof.organization_id', true))"
    )


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    predicate = _predicate()
    for table in TABLES:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(f'DROP POLICY IF EXISTS accessproof_tenant_isolation ON "{table}"')
        op.execute(
            f'CREATE POLICY accessproof_tenant_isolation ON "{table}" '
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for table in reversed(TABLES):
        op.execute(f'DROP POLICY IF EXISTS accessproof_tenant_isolation ON "{table}"')
        op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
