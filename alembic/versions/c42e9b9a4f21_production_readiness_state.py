"""production readiness state

Revision ID: c42e9b9a4f21
Revises: 9f1c0c0a1b10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "c42e9b9a4f21"
down_revision: str | None = "9f1c0c0a1b10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ddf_idempotency_v2",
        sa.Column(
            "tenant_id",
            sa.String(length=128),
            nullable=False,
        ),
        sa.Column(
            "idempotency_key",
            sa.String(length=256),
            nullable=False,
        ),
        sa.Column(
            "request_hash",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "state",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "status_code",
            sa.Integer(),
            nullable=True,
        ),
        sa.Column(
            "response_body",
            sa.LargeBinary(),
            nullable=True,
        ),
        sa.Column(
            "content_type",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "idempotency_key",
        ),
    )

    op.create_index(
        "ix_ddf_idempotency_v2_state",
        "ddf_idempotency_v2",
        [
            "state",
        ],
    )

    op.create_table(
        "ddf_identity_keys",
        sa.Column(
            "tenant_id",
            sa.String(length=128),
            nullable=False,
        ),
        sa.Column(
            "subject",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "key_id",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "public_key",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "not_before",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "revoked_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "subject",
            "key_id",
        ),
    )

    op.create_index(
        "ix_ddf_identity_keys_lookup",
        "ddf_identity_keys",
        [
            "tenant_id",
            "subject",
            "status",
        ],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_ddf_identity_keys_lookup",
        table_name="ddf_identity_keys",
    )

    op.drop_table(
        "ddf_identity_keys"
    )

    op.drop_index(
        "ix_ddf_idempotency_v2_state",
        table_name="ddf_idempotency_v2",
    )

    op.drop_table(
        "ddf_idempotency_v2"
    )
