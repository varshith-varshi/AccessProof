"""runner durability journal and cleanup queue

Revision ID: 9b1f4a7c2d10
Revises: 2bf8a73e6ebe
Create Date: 2026-09-30 17:30:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "9b1f4a7c2d10"
down_revision: Union[str, Sequence[str], None] = "2bf8a73e6ebe"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runner_checkpoints",
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("runner_id", sa.String(length=36), nullable=True),
        sa.Column("phase", sa.String(length=80), nullable=False),
        sa.Column("checkpoint_json", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["test_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("run_id"),
    )
    op.create_index(
        "ix_runner_checkpoints_organization_id", "runner_checkpoints", ["organization_id"]
    )
    op.create_index("ix_runner_checkpoints_project_id", "runner_checkpoints", ["project_id"])
    op.create_index("ix_runner_checkpoints_runner_id", "runner_checkpoints", ["runner_id"])
    op.create_index("ix_runner_checkpoints_phase", "runner_checkpoints", ["phase"])

    op.create_table(
        "mutation_journal",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("operation_id", sa.String(length=64), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("resource_id", sa.String(length=500), nullable=True),
        sa.Column("principal", sa.String(length=320), nullable=True),
        sa.Column("mutation_type", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("pre_state_json", sa.Text(), nullable=False),
        sa.Column("post_state_json", sa.Text(), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider_request_id", sa.String(length=200), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["test_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("operation_id"),
    )
    op.create_index("ix_mutation_journal_organization_id", "mutation_journal", ["organization_id"])
    op.create_index("ix_mutation_journal_project_id", "mutation_journal", ["project_id"])
    op.create_index("ix_mutation_journal_run_id", "mutation_journal", ["run_id"])
    op.create_index(
        "ix_mutation_journal_operation_id", "mutation_journal", ["operation_id"], unique=True
    )
    op.create_index("ix_mutation_journal_status", "mutation_journal", ["status"])

    op.create_table(
        "cleanup_tasks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("provider_resource_id", sa.String(length=500), nullable=False),
        sa.Column("resource_json", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["test_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cleanup_tasks_organization_id", "cleanup_tasks", ["organization_id"])
    op.create_index("ix_cleanup_tasks_project_id", "cleanup_tasks", ["project_id"])
    op.create_index("ix_cleanup_tasks_run_id", "cleanup_tasks", ["run_id"])
    op.create_index("ix_cleanup_tasks_status", "cleanup_tasks", ["status"])
    op.create_index("ix_cleanup_tasks_next_attempt_at", "cleanup_tasks", ["next_attempt_at"])


def downgrade() -> None:
    op.drop_table("cleanup_tasks")
    op.drop_table("mutation_journal")
    op.drop_table("runner_checkpoints")
