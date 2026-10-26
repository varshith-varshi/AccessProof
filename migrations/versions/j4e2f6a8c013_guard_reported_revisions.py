"""Guard-reported active authorization revisions for lag measurement

Revision ID: j4e2f6a8c013
Revises: i3c9e5b7d102
"""
from alembic import op
import sqlalchemy as sa

revision = "j4e2f6a8c013"
down_revision = "i3c9e5b7d102"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "guard_registrations",
        sa.Column(
            "active_authorization_revisions_json", sa.Text(),
            nullable=False, server_default="{}",
        ),
    )


def downgrade() -> None:
    op.drop_column("guard_registrations", "active_authorization_revisions_json")
