"""Add durable idempotent Guard audit upload records."""
from alembic import op
import sqlalchemy as sa

revision = "c3d4e5f6a7b8"
down_revision = "b8f1c3d5e7a9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "guard_audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("guard_id", sa.String(36), sa.ForeignKey("guard_registrations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("application_id", sa.String(36), nullable=False),
        sa.Column("subject_id", sa.String(255), nullable=False),
        sa.Column("request_id", sa.String(255), nullable=False),
        sa.Column("result", sa.String(30), nullable=False),
        sa.Column("reason", sa.String(255), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("guard_id", "event_id", name="uq_guard_audit_event"),
    )
    op.create_index("ix_guard_audit_events_organization_id", "guard_audit_events", ["organization_id"])
    op.create_index("ix_guard_audit_events_guard_id", "guard_audit_events", ["guard_id"])
    op.create_index("ix_guard_audit_events_application_id", "guard_audit_events", ["application_id"])
    op.create_index("ix_guard_audit_events_subject_id", "guard_audit_events", ["subject_id"])
    op.create_index("ix_guard_audit_events_request_id", "guard_audit_events", ["request_id"])


def downgrade() -> None:
    op.drop_table("guard_audit_events")
