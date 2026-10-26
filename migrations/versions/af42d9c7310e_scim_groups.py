"""SCIM group provisioning and role mapping

Revision ID: af42d9c7310e
Revises: 8f21c6d4aa10
"""

from alembic import op
import sqlalchemy as sa

revision = "af42d9c7310e"
down_revision = "8f21c6d4aa10"
branch_labels = None
depends_on = None


def _rls_predicate() -> str:
    return (
        "(current_setting('accessproof.rls_bypass', true) = 'on' "
        "OR organization_id = current_setting('accessproof.organization_id', true))"
    )


def upgrade() -> None:
    op.create_table(
        "scim_groups",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("display_name", sa.String(length=500), nullable=False),
        sa.Column("external_id", sa.String(length=500), nullable=True),
        sa.Column("mapped_role", sa.String(length=20), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "display_name", name="uq_scim_group_display_name"),
        sa.UniqueConstraint("organization_id", "external_id", name="uq_scim_group_external_id"),
    )
    op.create_index("ix_scim_groups_organization_id", "scim_groups", ["organization_id"])
    op.create_index("ix_scim_groups_display_name", "scim_groups", ["display_name"])
    op.create_index("ix_scim_groups_external_id", "scim_groups", ["external_id"])

    op.create_table(
        "scim_group_members",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "group_id",
            sa.String(length=36),
            sa.ForeignKey("scim_groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scim_identity_id",
            sa.String(length=36),
            sa.ForeignKey("scim_identities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("group_id", "scim_identity_id", name="uq_scim_group_member"),
    )
    op.create_index(
        "ix_scim_group_members_organization_id", "scim_group_members", ["organization_id"]
    )
    op.create_index("ix_scim_group_members_group_id", "scim_group_members", ["group_id"])
    op.create_index(
        "ix_scim_group_members_scim_identity_id", "scim_group_members", ["scim_identity_id"]
    )

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        predicate = _rls_predicate()
        for table in ("scim_groups", "scim_group_members"):
            op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            op.execute(
                f'CREATE POLICY accessproof_tenant_isolation ON "{table}" '
                f"USING ({predicate}) WITH CHECK ({predicate})"
            )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in ("scim_group_members", "scim_groups"):
            op.execute(f'DROP POLICY IF EXISTS accessproof_tenant_isolation ON "{table}"')
            op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
    op.drop_table("scim_group_members")
    op.drop_table("scim_groups")
