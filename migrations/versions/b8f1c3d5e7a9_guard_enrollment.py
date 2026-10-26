"""Add independent customer-side Guard enrollment metadata."""
from alembic import op
import sqlalchemy as sa

revision = "b8f1c3d5e7a9"
down_revision = "a7e9d2c4b6f8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("guard_registrations", sa.Column("last_policy_sync_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("guard_registrations", sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("guard_registrations", sa.Column("health", sa.String(30), nullable=False, server_default="not_enrolled"))
    op.add_column("guard_policy_distributions", sa.Column("guard_received_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("guard_policy_distributions", sa.Column("guard_installed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        "guard_enrollments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("guard_id", sa.String(36), sa.ForeignKey("guard_registrations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_guard_enrollments_organization_id", "guard_enrollments", ["organization_id"])
    op.create_index("ix_guard_enrollments_guard_id", "guard_enrollments", ["guard_id"])


def downgrade() -> None:
    op.drop_table("guard_enrollments")
    op.drop_column("guard_policy_distributions", "guard_installed_at")
    op.drop_column("guard_policy_distributions", "guard_received_at")
    op.drop_column("guard_registrations", "health")
    op.drop_column("guard_registrations", "enrolled_at")
    op.drop_column("guard_registrations", "last_policy_sync_at")
