"""source metadata and runner lifecycle

Revision ID: a1f3d94c7b20
Revises: e37c4d981a02
"""

from alembic import op
import sqlalchemy as sa

revision = "a1f3d94c7b20"
down_revision = "e37c4d981a02"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("source_connections") as batch:
        batch.add_column(
            sa.Column("provider_identity_json", sa.Text(), nullable=False, server_default="{}")
        )
        batch.add_column(
            sa.Column("granted_scopes_json", sa.Text(), nullable=False, server_default="[]")
        )
        batch.add_column(
            sa.Column("missing_scopes_json", sa.Text(), nullable=False, server_default="[]")
        )
        batch.add_column(sa.Column("provider_api_version", sa.String(length=100), nullable=True))
        batch.add_column(sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(
            sa.Column("last_capability_refresh_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(sa.Column("last_error", sa.Text(), nullable=True))
    with op.batch_alter_table("runners") as batch:
        batch.add_column(
            sa.Column("disabled", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch.add_column(sa.Column("last_job_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(
            sa.Column("credential_rotated_at", sa.DateTime(timezone=True), nullable=True)
        )


def downgrade():
    with op.batch_alter_table("runners") as batch:
        batch.drop_column("credential_rotated_at")
        batch.drop_column("last_job_at")
        batch.drop_column("disabled")
    with op.batch_alter_table("source_connections") as batch:
        batch.drop_column("last_error")
        batch.drop_column("last_capability_refresh_at")
        batch.drop_column("last_validated_at")
        batch.drop_column("provider_api_version")
        batch.drop_column("missing_scopes_json")
        batch.drop_column("granted_scopes_json")
        batch.drop_column("provider_identity_json")
