"""Track email verification timestamps and token creation times.

Revision ID: d4a1e8f90b21
Revises: c7e82b9d4fa2
"""

from alembic import op
import sqlalchemy as sa


revision = "d4a1e8f90b21"
down_revision = "c7e82b9d4fa2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "one_time_tokens",
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )


def downgrade() -> None:
    op.drop_column("one_time_tokens", "created_at")
    op.drop_column("users", "email_verified_at")
