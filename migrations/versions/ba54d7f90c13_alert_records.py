"""durable alert records

Revision ID: ba54d7f90c13
Revises: a1f3d94c7b20
"""

from alembic import op
import sqlalchemy as sa

revision = "ba54d7f90c13"
down_revision = "a1f3d94c7b20"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "alert_records",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=True),
        sa.Column("kind", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("dedupe_key", sa.String(length=300), nullable=False, unique=True),
        sa.Column("subject", sa.String(length=300), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_alert_records_organization_id", "alert_records", ["organization_id"])
    op.create_index("ix_alert_records_project_id", "alert_records", ["project_id"])
    op.create_index("ix_alert_records_kind", "alert_records", ["kind"])
    op.create_index("ix_alert_records_dedupe_key", "alert_records", ["dedupe_key"])


def downgrade():
    op.drop_table("alert_records")
