"""retention policies and deletion receipts

Revision ID: e37c4d981a02
Revises: d12a9c7e4b31
"""

from alembic import op
import sqlalchemy as sa

revision = "e37c4d981a02"
down_revision = "d12a9c7e4b31"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "retention_policies",
        sa.Column("organization_id", sa.String(length=36), primary_key=True),
        sa.Column("detailed_evidence_days", sa.Integer(), nullable=False),
        sa.Column("report_days", sa.Integer(), nullable=False),
        sa.Column("audit_days", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "deletion_receipts",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id_hash", sa.String(length=64), nullable=False),
        sa.Column("actor_user_id_hash", sa.String(length=64), nullable=False),
        sa.Column("organization_name_hash", sa.String(length=64), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_deletion_receipts_organization_id_hash", "deletion_receipts", ["organization_id_hash"]
    )


def downgrade() -> None:
    op.drop_table("deletion_receipts")
    op.drop_table("retention_policies")
