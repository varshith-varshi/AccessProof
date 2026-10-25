"""Maintain a separate, durable last reconciliation timestamp per resource."""
from alembic import op
import sqlalchemy as sa

revision = "a2b4c6d8e0f2"
down_revision = "f13a2c4e5d68"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("guard_resources", sa.Column("last_reconciled_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_guard_resources_last_reconciled_at", "guard_resources", ["last_reconciled_at"])


def downgrade() -> None:
    op.drop_index("ix_guard_resources_last_reconciled_at", table_name="guard_resources")
    op.drop_column("guard_resources", "last_reconciled_at")
