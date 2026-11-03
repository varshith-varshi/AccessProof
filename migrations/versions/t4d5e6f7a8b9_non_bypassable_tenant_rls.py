"""Non-bypassable tenant RLS on every post-authentication tenant table (P0-01).

* Replaces policies that honoured the session-settable GUC
  ``accessproof.rls_bypass`` (any connection could switch it on).
* Extends RLS to the authorization core that previously had none
  (Guard policies, grants, identity mappings, applications, certificates...).
* Grants data privileges to the restricted runtime roles if they exist; the
  roles themselves are provisioned by scripts/provision_database_roles.py.

Runs as the table owner. Has no effect on SQLite.

Revision ID: t4d5e6f7a8b9
Revises: s3c4d5e6f7a8
"""
from alembic import op

from apps.api.accessproof_api.db_security import (
    NEWLY_PROTECTED_TABLES, POLICY, apply_tenant_policies, grant_runtime_privileges,
)

revision = "t4d5e6f7a8b9"
down_revision = "s3c4d5e6f7a8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    apply_tenant_policies(bind)
    grant_runtime_privileges(bind)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    # Remove RLS only from tables this revision newly protected. The older
    # tables keep the (stronger) canonical predicate: re-introducing the
    # settable bypass would be a security regression.
    for table in NEWLY_PROTECTED_TABLES:
        op.execute(f'DROP POLICY IF EXISTS {POLICY} ON "{table}"')
        op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
