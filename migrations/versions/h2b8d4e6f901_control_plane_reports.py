"""signed control-plane evidence reports

Revision ID: h2b8d4e6f901
Revises: g1a7c3d8e9f0
"""
from alembic import op
import sqlalchemy as sa

revision = "h2b8d4e6f901"
down_revision = "g1a7c3d8e9f0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "control_plane_reports",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("report_type", sa.String(length=50), nullable=False),
        sa.Column("generated_by_user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("report_hash", sa.String(length=64), nullable=False),
        sa.Column("signing_key_id", sa.String(length=200), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("signing_public_key", sa.Text(), nullable=False),
        sa.Column("signed_manifest_json", sa.Text(), nullable=False),
    )
    op.create_index("ix_control_plane_reports_organization_id", "control_plane_reports", ["organization_id"])
    op.create_index("ix_control_plane_reports_report_type", "control_plane_reports", ["report_type"])


def downgrade() -> None:
    op.drop_table("control_plane_reports")
