"""store provider group email for ACL principal resolution

Revision ID: b1c2d3e4f5a6
Revises: a1b2c3d4e5f6
"""
from alembic import op
import sqlalchemy as sa

revision = "b1c2d3e4f5a6"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("guard_groups", sa.Column("provider_email", sa.String(320), nullable=True))


def downgrade() -> None:
    op.drop_column("guard_groups", "provider_email")
