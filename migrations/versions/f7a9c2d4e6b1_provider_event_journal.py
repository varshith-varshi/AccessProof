"""Add durable provider event subscriptions and notification journal."""
from alembic import op
import sqlalchemy as sa

revision = "f7a9c2d4e6b1"
down_revision = "e6f8a2c4d9b0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("provider_event_subscriptions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("source_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False), sa.Column("channel_type", sa.String(50), nullable=False),
        sa.Column("channel_id", sa.String(255), nullable=False), sa.Column("provider_resource_id", sa.String(1024), nullable=False),
        sa.Column("encrypted_channel_token", sa.Text(), nullable=False), sa.Column("state", sa.String(30), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("last_notification_at", sa.DateTime(timezone=True)),
        sa.Column("last_successful_processing_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("provider", "channel_id"))
    op.create_index("ix_provider_event_subscriptions_organization_id", "provider_event_subscriptions", ["organization_id"])
    op.create_index("ix_provider_event_subscriptions_source_id", "provider_event_subscriptions", ["source_id"])
    op.create_index("ix_provider_event_subscriptions_provider", "provider_event_subscriptions", ["provider"])
    op.create_index("ix_provider_event_subscriptions_state", "provider_event_subscriptions", ["state"])
    op.create_index("ix_provider_event_subscriptions_expires_at", "provider_event_subscriptions", ["expires_at"])
    op.create_table("provider_event_journal",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("source_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subscription_id", sa.String(36), sa.ForeignKey("provider_event_subscriptions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False), sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("provider_message_number", sa.String(128), nullable=False), sa.Column("dedupe_key", sa.String(64), nullable=False),
        sa.Column("status", sa.String(30), nullable=False), sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False), sa.Column("processing_started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)), sa.Column("error_code", sa.String(100)), sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "dedupe_key"))
    for col in ("organization_id", "source_id", "subscription_id", "provider", "status", "next_attempt_at"):
        op.create_index(f"ix_provider_event_journal_{col}", "provider_event_journal", [col])


def downgrade() -> None:
    op.drop_table("provider_event_journal")
    op.drop_table("provider_event_subscriptions")
