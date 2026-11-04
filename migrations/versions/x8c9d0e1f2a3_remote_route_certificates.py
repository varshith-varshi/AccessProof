"""Remote RAG route certificates (tenant scoped, canonical RLS).

Additive: a new table only. No existing row changes meaning; applications
without a remote route certificate are unaffected.

Revision ID: x8c9d0e1f2a3
Revises: w7a8b9c0d1e2
"""
from alembic import op
import sqlalchemy as sa

from apps.api.accessproof_api.db_security import apply_tenant_policies, grant_runtime_privileges

revision = "x8c9d0e1f2a3"
down_revision = "w7a8b9c0d1e2"
branch_labels = None
depends_on = None

TABLE = "remote_route_certificates"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("application_row_id", sa.String(36), sa.ForeignKey("ai_applications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("key_id", sa.String(128), nullable=False),
        sa.Column("route_url", sa.String(512), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("status_reason", sa.String(100), nullable=True),
        sa.Column("certificate_json", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_attested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attestation_json", sa.Text(), nullable=True),
        sa.UniqueConstraint("organization_id", "application_row_id", "fingerprint",
                            name="uq_remote_route_certificate_fingerprint"),
    )
    op.create_index("ix_remote_route_certificates_organization_id", TABLE, ["organization_id"])
    op.create_index("ix_remote_route_certificates_application_row_id", TABLE, ["application_row_id"])
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        apply_tenant_policies(bind, [TABLE])
        grant_runtime_privileges(bind)


def downgrade() -> None:
    op.drop_index("ix_remote_route_certificates_application_row_id", table_name=TABLE)
    op.drop_index("ix_remote_route_certificates_organization_id", table_name=TABLE)
    op.drop_table(TABLE)
