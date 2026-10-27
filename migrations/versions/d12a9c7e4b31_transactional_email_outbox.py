"""transactional email outbox

Revision ID: d12a9c7e4b31
Revises: f8c0314da921
"""

from alembic import op
import sqlalchemy as sa

revision = "d12a9c7e4b31"
down_revision = "f8c0314da921"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "email_outbox",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), nullable=True),
        sa.Column("recipient", sa.String(length=320), nullable=False),
        sa.Column("template", sa.String(length=80), nullable=False),
        sa.Column("subject", sa.String(length=300), nullable=False),
        sa.Column("encrypted_payload", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_email_outbox_organization_id", "email_outbox", ["organization_id"])
    op.create_index("ix_email_outbox_recipient", "email_outbox", ["recipient"])
    op.create_index("ix_email_outbox_template", "email_outbox", ["template"])
    op.create_index("ix_email_outbox_status", "email_outbox", ["status"])
    op.create_index("ix_email_outbox_next_attempt_at", "email_outbox", ["next_attempt_at"])


def downgrade() -> None:
    op.drop_table("email_outbox")
