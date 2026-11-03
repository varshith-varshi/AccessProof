"""Widen provider/source revision columns to BIGINT (PostgreSQL overflow fix).

Google Drive revisions are millisecond timestamps (~1.8e12) and overflow a
32-bit INTEGER, so permission-change events (including revocations) could not
be stored on PostgreSQL. Widening is lossless.

Revision ID: u5e6f7a8b9c0
Revises: t4d5e6f7a8b9
"""
from alembic import op
import sqlalchemy as sa

revision = "u5e6f7a8b9c0"
down_revision = "t4d5e6f7a8b9"
branch_labels = None
depends_on = None

COLUMNS = (
    ("guard_permission_events", "provider_revision"),
    ("guard_permission_grants", "provider_revision"),
    ("guard_group_memberships", "provider_revision"),
    ("guard_policies", "source_revision"),
    ("guard_effective_access", "source_revision"),
    ("guard_permission_snapshots", "source_revision"),
)


def upgrade() -> None:
    for table, column in COLUMNS:
        with op.batch_alter_table(table) as batch:
            batch.alter_column(column, existing_type=sa.Integer(), type_=sa.BigInteger(),
                               existing_nullable=False)


def downgrade() -> None:
    # Narrow only when every stored value fits; never truncate a revision.
    bind = op.get_bind()
    for table, column in COLUMNS:
        largest = bind.execute(sa.text(f'SELECT max("{column}") FROM "{table}"')).scalar()
        if largest is not None and largest > 2**31 - 1:
            raise RuntimeError(f"BIGINT_REVISION_DOWNGRADE_UNSAFE:{table}.{column}")
    for table, column in COLUMNS:
        with op.batch_alter_table(table) as batch:
            batch.alter_column(column, existing_type=sa.BigInteger(), type_=sa.Integer(),
                               existing_nullable=False)
