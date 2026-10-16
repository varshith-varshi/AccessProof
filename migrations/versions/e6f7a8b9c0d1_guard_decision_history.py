"""Add durable metadata-only Guard decision history fields.

Revision ID: e6f7a8b9c0d1
Revises: d4e5f6a7b8c9
"""

from alembic import op
import sqlalchemy as sa


revision = "e6f7a8b9c0d1"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("guard_audit_events", sa.Column("decision_id", sa.String(64), nullable=True))
    op.add_column(
        "guard_audit_events",
        sa.Column("layer", sa.String(20), nullable=False, server_default="layer1"),
    )
    op.add_column(
        "guard_audit_events",
        sa.Column("resources_json", sa.Text(), nullable=False, server_default="[]"),
    )
    op.create_index("ix_guard_audit_events_decision_id", "guard_audit_events", ["decision_id"])


def downgrade() -> None:
    op.drop_index("ix_guard_audit_events_decision_id", table_name="guard_audit_events")
    op.drop_column("guard_audit_events", "resources_json")
    op.drop_column("guard_audit_events", "layer")
    op.drop_column("guard_audit_events", "decision_id")
