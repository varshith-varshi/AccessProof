"""signed authorization revisions and Guard audit binding

Revision ID: i3c9e5b7d102
Revises: h2b8d4e6f901
"""
from alembic import op
import sqlalchemy as sa

revision = "i3c9e5b7d102"
down_revision = "h2b8d4e6f901"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "authorization_revision_sequences",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("application_row_id", sa.String(length=36), sa.ForeignKey("ai_applications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("next_revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "application_row_id"),
    )
    op.create_index("ix_authorization_revision_sequences_organization_id", "authorization_revision_sequences", ["organization_id"])
    op.create_index("ix_authorization_revision_sequences_application_row_id", "authorization_revision_sequences", ["application_row_id"])

    op.create_table(
        "authorization_revisions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("application_row_id", sa.String(length=36), sa.ForeignKey("ai_applications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("application_id", sa.String(length=255), nullable=False),
        sa.Column("source_id", sa.String(length=36), nullable=True),
        sa.Column("guard_id", sa.String(length=36), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("revision_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("previous_revision_hash", sa.String(length=64), nullable=True),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("signing_key_id", sa.String(length=200), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("signing_public_key", sa.Text(), nullable=False),
        sa.Column("signed_manifest_json", sa.Text(), nullable=False),
        sa.Column("source_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "application_row_id", "revision"),
    )
    op.create_index("ix_authorization_revisions_organization_id", "authorization_revisions", ["organization_id"])
    op.create_index("ix_authorization_revisions_application_row_id", "authorization_revisions", ["application_row_id"])
    op.create_index("ix_authorization_revisions_application_id", "authorization_revisions", ["application_id"])
    op.create_index("ix_authorization_revisions_source_id", "authorization_revisions", ["source_id"])
    op.create_index("ix_authorization_revisions_state_hash", "authorization_revisions", ["state_hash"])

    op.add_column("guard_audit_events", sa.Column("authorization_revision", sa.Integer(), nullable=True))
    op.add_column("guard_audit_events", sa.Column("authorization_revision_hash", sa.String(length=64), nullable=True))
    op.add_column("guard_audit_events", sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_guard_audit_events_authorization_revision_hash", "guard_audit_events", ["authorization_revision_hash"])
    op.execute("UPDATE guard_audit_events SET occurred_at = created_at WHERE occurred_at IS NULL")


def downgrade() -> None:
    op.drop_index("ix_guard_audit_events_authorization_revision_hash", table_name="guard_audit_events")
    op.drop_column("guard_audit_events", "occurred_at")
    op.drop_column("guard_audit_events", "authorization_revision_hash")
    op.drop_column("guard_audit_events", "authorization_revision")
    op.drop_table("authorization_revisions")
    op.drop_table("authorization_revision_sequences")
