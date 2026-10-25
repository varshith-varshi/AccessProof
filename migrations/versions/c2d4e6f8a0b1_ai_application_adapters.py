"""store the selected RAG adapter contract on AI applications

Revision ID: c2d4e6f8a0b1
Revises: b1c2d3e4f5a6
Create Date: 2026-10-18 12:00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c2d4e6f8a0b1"
down_revision: Union[str, Sequence[str], None] = "b1c2d3e4f5a6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ai_applications",
        sa.Column("adapter_type", sa.String(length=50), nullable=False, server_default="generic-python"),
    )
    op.add_column(
        "ai_applications",
        sa.Column("adapter_contract_version", sa.String(length=50), nullable=False, server_default="accessproof.rag/v1"),
    )


def downgrade() -> None:
    op.drop_column("ai_applications", "adapter_contract_version")
    op.drop_column("ai_applications", "adapter_type")

