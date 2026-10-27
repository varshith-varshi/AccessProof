"""Durable tenant-scoped activation preflight attempts without fake certification."""
from alembic import op
import sqlalchemy as sa

revision = "b3c5d7e9f103"
down_revision = "a2b4c6d8e0f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "protection_activation_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("application_row_id", sa.String(36), sa.ForeignKey("ai_applications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("requested_by_user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("guard_id", sa.String(36)),
        sa.Column("source_id", sa.String(36)),
        sa.Column("configuration_fingerprint", sa.String(64), nullable=False),
        sa.Column("checks_json", sa.Text(), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "application_row_id"),
    )
    op.create_index("ix_protection_activation_runs_organization_id", "protection_activation_runs", ["organization_id"])
    op.create_index("ix_protection_activation_runs_application_row_id", "protection_activation_runs", ["application_row_id"])


def downgrade() -> None:
    op.drop_index("ix_protection_activation_runs_application_row_id", table_name="protection_activation_runs")
    op.drop_index("ix_protection_activation_runs_organization_id", table_name="protection_activation_runs")
    op.drop_table("protection_activation_runs")
