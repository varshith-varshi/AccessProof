"""durable provider synchronization cursors

Revision ID: f0a1b2c3d4e5
Revises: e6f7a8b9c0d1
"""
from alembic import op
import sqlalchemy as sa

revision = "f0a1b2c3d4e5"
down_revision = "e6f7a8b9c0d1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "provider_sync_cursors",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.String(length=36), sa.ForeignKey("source_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("sync_kind", sa.String(length=50), nullable=False),
        sa.Column("cursor", sa.Text(), nullable=True),
        sa.Column("last_provider_revision", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="never_synced"),
        sa.Column("last_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=100), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "source_id", "sync_kind"),
    )
    op.create_index("ix_provider_sync_cursors_organization_id", "provider_sync_cursors", ["organization_id"])
    op.create_index("ix_provider_sync_cursors_source_id", "provider_sync_cursors", ["source_id"])
    op.create_index("ix_provider_sync_cursors_provider", "provider_sync_cursors", ["provider"])
    op.create_index("ix_provider_sync_cursors_status", "provider_sync_cursors", ["status"])


def downgrade() -> None:
    op.drop_table("provider_sync_cursors")
