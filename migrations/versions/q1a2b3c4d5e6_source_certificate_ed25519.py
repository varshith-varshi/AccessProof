"""Ed25519 source certificates: widen signature column (defect D-01).

The control plane now verifies source effective-permission certificates with
pinned public keys only. Legacy HMAC-signed rows can no longer verify and are
ineligible by design (production held zero such rows when this was written).

Revision ID: q1a2b3c4d5e6
Revises: p8c1e2f3a4b5
"""
from alembic import op
import sqlalchemy as sa

revision = "q1a2b3c4d5e6"
down_revision = "p8c1e2f3a4b5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("source_effective_certifications") as batch:
        batch.alter_column("signature", existing_type=sa.String(64), type_=sa.String(160),
                           existing_nullable=False)


def downgrade() -> None:
    # Ed25519 signatures do not fit the legacy width; invalidate rather than truncate.
    op.execute("DELETE FROM source_effective_certifications WHERE length(signature) > 64")
    with op.batch_alter_table("source_effective_certifications") as batch:
        batch.alter_column("signature", existing_type=sa.String(160), type_=sa.String(64),
                           existing_nullable=False)
