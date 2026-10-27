"""Bind runner evidence to a server-issued run oracle."""
from alembic import op
import sqlalchemy as sa

revision = "e6f8a2c4d9b0"
down_revision = "d5e7f9a1b3c5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("test_runs", sa.Column("oracle_canary", sa.String(80), nullable=True))
    # Existing terminal runs predate this invariant. They remain readable but can
    # never be re-leased; all newly queued runs receive an unpredictable value.
    op.execute("UPDATE test_runs SET oracle_canary = 'legacy-' || id WHERE oracle_canary IS NULL")
    # SQLite cannot ALTER COLUMN to add NOT NULL in place. Alembic's batch
    # mode rebuilds the table while retaining its existing data, constraints
    # and indexes. On PostgreSQL, use a regular ALTER to avoid a table rebuild.
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("test_runs") as batch_op:
            batch_op.alter_column(
                "oracle_canary", existing_type=sa.String(80), nullable=False
            )
    else:
        op.alter_column(
            "test_runs", "oracle_canary",
            existing_type=sa.String(80), nullable=False,
        )


def downgrade() -> None:
    op.drop_column("test_runs", "oracle_canary")
