"""Record directory tenant and account kind on synchronized principals.

Enables automatic, directory-verified Microsoft identity bindings: only an
active MEMBER account read from the source's own tenant may be bound.
Additive and nullable: existing rows stay ineligible until the next directory
sync records their tenant, so nothing becomes authorized by the migration.

Revision ID: w7a8b9c0d1e2
Revises: v6f7a8b9c0d1
"""
from alembic import op
import sqlalchemy as sa

revision = "w7a8b9c0d1e2"
down_revision = "v6f7a8b9c0d1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("guard_subjects") as batch:
        batch.add_column(sa.Column("provider_tenant_id", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("account_kind", sa.String(length=20), nullable=True))
    op.create_index("ix_guard_subjects_org_provider_tenant", "guard_subjects",
                    ["organization_id", "provider", "provider_tenant_id"])
    op.create_index("ix_guard_identity_mappings_org_source_status", "guard_identity_mappings",
                    ["organization_id", "source_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_guard_identity_mappings_org_source_status", table_name="guard_identity_mappings")
    op.drop_index("ix_guard_subjects_org_provider_tenant", table_name="guard_subjects")
    with op.batch_alter_table("guard_subjects") as batch:
        batch.drop_column("account_kind")
        batch.drop_column("provider_tenant_id")
