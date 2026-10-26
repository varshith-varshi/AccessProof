"""Add runner enrollment and capability metadata.

Revision ID: c7e82b9d4fa2
Revises: b91e2ac7d4f1
"""

from alembic import op
import sqlalchemy as sa


revision = "c7e82b9d4fa2"
down_revision = "b91e2ac7d4f1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("runners", sa.Column("platform", sa.String(80), nullable=True))
    op.add_column("runners", sa.Column("architecture", sa.String(80), nullable=True))
    op.add_column(
        "runners",
        sa.Column("capabilities_json", sa.Text(), nullable=False, server_default="{}"),
    )
    op.add_column("runners", sa.Column("installed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "runners",
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.add_column("runner_registrations", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("runner_registrations", sa.Column("display_name", sa.String(200), nullable=True))
    op.add_column(
        "runner_registrations",
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )


def downgrade() -> None:
    op.drop_column("runner_registrations", "created_at")
    op.drop_column("runner_registrations", "display_name")
    op.drop_column("runner_registrations", "revoked_at")
    op.drop_column("runners", "created_at")
    op.drop_column("runners", "installed_at")
    op.drop_column("runners", "capabilities_json")
    op.drop_column("runners", "architecture")
    op.drop_column("runners", "platform")
