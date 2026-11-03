"""Record the last accepted TOTP step so codes cannot be replayed (RT-03).

Revision ID: v6f7a8b9c0d1
Revises: u5e6f7a8b9c0
"""
from alembic import op
import sqlalchemy as sa

revision = "v6f7a8b9c0d1"
down_revision = "u5e6f7a8b9c0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("mfa_methods") as batch:
        batch.add_column(sa.Column("last_totp_step", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("mfa_methods") as batch:
        batch.drop_column("last_totp_step")
