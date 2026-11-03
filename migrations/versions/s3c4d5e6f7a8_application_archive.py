"""Archive AI applications without deleting their evidence (O-05).

Revision ID: s3c4d5e6f7a8
Revises: r2b3c4d5e6f7
"""
from alembic import op
import sqlalchemy as sa

revision = "s3c4d5e6f7a8"
down_revision = "r2b3c4d5e6f7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("ai_applications") as batch:
        batch.add_column(sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("ai_applications") as batch:
        batch.drop_column("archived_at")
