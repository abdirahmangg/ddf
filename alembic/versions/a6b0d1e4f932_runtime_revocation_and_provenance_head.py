"""Add assertion revocations and serialized provenance chain head.

Revision ID: a6b0d1e4f932
Revises: 2a7f61c4d5e8
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a6b0d1e4f932"
down_revision: str | Sequence[str] | None = "2a7f61c4d5e8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ddf_capability_revocations",
        sa.Column("grant_id", sa.String(length=36), nullable=False),
        sa.Column("actor", sa.String(length=512), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["grant_id"],
            ["ddf_universal_assertions.grant_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("grant_id"),
    )
    op.create_table(
        "ddf_provenance_chain_head",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("latest_hash", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_ddf_provenance_chain_head_singleton"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("ddf_provenance_chain_head")
    op.drop_table("ddf_capability_revocations")
