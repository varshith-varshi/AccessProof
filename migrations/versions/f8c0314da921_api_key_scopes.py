"""api key scopes

Revision ID: f8c0314da921
Revises: c4d6a2108ef2
Create Date: 2026-09-30 18:35:00
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "f8c0314da921"
down_revision: Union[str, Sequence[str], None] = "c4d6a2108ef2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "api_keys", sa.Column("scopes_json", sa.Text(), nullable=False, server_default="[]")
    )


def downgrade() -> None:
    op.drop_column("api_keys", "scopes_json")
