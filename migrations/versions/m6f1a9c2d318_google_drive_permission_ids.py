"""Resolve Google Drive permission principals by provider-backed opaque ID.

Revision ID: m6f1a9c2d318
Revises: k5d3e7a9b214
"""
from alembic import op
import sqlalchemy as sa

revision = "m6f1a9c2d318"
down_revision = "k5d3e7a9b214"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("guard_subjects", sa.Column("drive_permission_id", sa.String(255), nullable=True))
    op.add_column("guard_groups", sa.Column("drive_permission_id", sa.String(255), nullable=True))
    op.create_index("ix_guard_subjects_drive_permission_id", "guard_subjects", ["drive_permission_id"])
    op.create_index("ix_guard_groups_drive_permission_id", "guard_groups", ["drive_permission_id"])
    op.create_unique_constraint(
        "uq_guard_subject_drive_permission_id", "guard_subjects",
        ["organization_id", "provider", "drive_permission_id"],
    ) if op.get_bind().dialect.name == "postgresql" else None
    op.create_unique_constraint(
        "uq_guard_group_drive_permission_id", "guard_groups",
        ["organization_id", "provider", "drive_permission_id"],
    ) if op.get_bind().dialect.name == "postgresql" else None


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.drop_constraint("uq_guard_group_drive_permission_id", "guard_groups", type_="unique")
        op.drop_constraint("uq_guard_subject_drive_permission_id", "guard_subjects", type_="unique")
    op.drop_index("ix_guard_groups_drive_permission_id", table_name="guard_groups")
    op.drop_index("ix_guard_subjects_drive_permission_id", table_name="guard_subjects")
    op.drop_column("guard_groups", "drive_permission_id")
    op.drop_column("guard_subjects", "drive_permission_id")
