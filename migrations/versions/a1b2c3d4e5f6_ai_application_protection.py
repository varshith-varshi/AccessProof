"""backend-owned AI application protection state

Revision ID: a1b2c3d4e5f6
Revises: f0a1b2c3d4e5
"""
from alembic import op
import sqlalchemy as sa

revision = "a1b2c3d4e5f6"
down_revision = "f0a1b2c3d4e5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_applications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("application_id", sa.String(255), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("mode", sa.String(20), nullable=False, server_default="shadow"),
        sa.Column("guard_id", sa.String(36), sa.ForeignKey("guard_registrations.id", ondelete="SET NULL"), nullable=True),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("source_connections.id", ondelete="SET NULL"), nullable=True),
        sa.Column("layer1_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("layer2_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provenance_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("buffering_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "application_id"),
    )
    for name, columns in (("organization_id", ["organization_id"]), ("application_id", ["application_id"]), ("guard_id", ["guard_id"]), ("source_id", ["source_id"])):
        op.create_index(f"ix_ai_applications_{name}", "ai_applications", columns)


def downgrade() -> None:
    op.drop_table("ai_applications")
