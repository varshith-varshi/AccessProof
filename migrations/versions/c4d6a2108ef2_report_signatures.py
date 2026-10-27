"""report signatures

Revision ID: c4d6a2108ef2
Revises: 9b1f4a7c2d10
Create Date: 2026-09-30 18:10:00
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "c4d6a2108ef2"
down_revision: Union[str, Sequence[str], None] = "9b1f4a7c2d10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("reports", sa.Column("signature", sa.Text(), nullable=True))
    op.add_column("reports", sa.Column("signing_public_key", sa.Text(), nullable=True))
    op.add_column("reports", sa.Column("signed_manifest_json", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("reports", "signed_manifest_json")
    op.drop_column("reports", "signing_public_key")
    op.drop_column("reports", "signature")
