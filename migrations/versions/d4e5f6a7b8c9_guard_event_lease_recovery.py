"""Track Guard event leases so abandoned worker work is recoverable."""

from alembic import op
import sqlalchemy as sa


revision = "d4e5f6a7b8c9"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "guard_permission_events",
        sa.Column("processing_started_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_guard_permission_events_processing_started_at",
        "guard_permission_events",
        ["processing_started_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_guard_permission_events_processing_started_at", table_name="guard_permission_events")
    op.drop_column("guard_permission_events", "processing_started_at")
