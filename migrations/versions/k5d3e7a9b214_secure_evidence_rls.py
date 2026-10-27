"""Protect signed evidence tables with PostgreSQL tenant RLS.

Revision ID: k5d3e7a9b214
Revises: j4e2f6a8c013

The former migrations created these tables after the original RLS pass.  This
forward migration deliberately does not rely on a client-controlled GUC for
an administrative bypass.  Operations which genuinely need global access must
use the separately provisioned ``accessproof_rls_admin`` database role (or a
PostgreSQL superuser under the customer's own operational controls).
"""
from alembic import op

revision = "k5d3e7a9b214"
down_revision = "j4e2f6a8c013"
branch_labels = None
depends_on = None

TABLES = (
    "control_plane_reports",
    "authorization_revisions",
    "authorization_revision_sequences",
)


def _predicate() -> str:
    # ``accessproof.organization_id`` is set transaction-locally by the API.
    # A caller can set arbitrary GUCs, so authorization cannot be granted by a
    # GUC such as the former rls_bypass flag.  The exception is a fixed DB role
    # controlled by the database administrator, not by application input.
    return (
        "(organization_id = current_setting('accessproof.organization_id', true) "
        "OR current_user = 'accessproof_rls_admin')"
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
            f'USING ({predicate}) WITH CHECK ({predicate})'
        )


def downgrade() -> None:
    """Remove only policies introduced by this forward migration.

    A rollback removes the defense, so production recovery should roll forward
    after correcting the deployment rather than applying this downgrade.
    """
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for table in reversed(TABLES):
        op.execute(f'DROP POLICY IF EXISTS accessproof_tenant_isolation ON "{table}"')
        op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
