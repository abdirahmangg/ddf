"""Commercial trust plane.

Revision ID: 9f1c0c0a1b10
Revises: 71b06b4139c9
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "9f1c0c0a1b10"
down_revision: str | Sequence[str] | None = "71b06b4139c9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ddf_tenants",
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("display_name", sa.String(256)),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "ddf_trusted_principals",
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("subject", sa.String(256), nullable=False),
        sa.Column("identity_type", sa.String(32), nullable=False),
        sa.Column("key_id", sa.String(256), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("roles_json", sa.JSON(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["ddf_tenants.tenant_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("tenant_id", "subject"),
        sa.UniqueConstraint(
            "tenant_id",
            "key_id",
            name="uq_ddf_principal_key",
        ),
    )
    op.create_index(
        "ix_ddf_principal_subject",
        "ddf_trusted_principals",
        ["subject"],
    )

    op.create_table(
        "ddf_replay_nonces",
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("nonce", sa.String(256), nullable=False),
        sa.Column("principal_id", sa.String(256), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "nonce"),
    )
    op.create_index(
        "ix_ddf_nonce_expires",
        "ddf_replay_nonces",
        ["expires_at"],
    )

    op.create_table(
        "ddf_authority_tenants",
        sa.Column("authority_id", sa.String(256), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("issuer", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["ddf_tenants.tenant_id"],
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_ddf_authority_tenants_tenant_id",
        "ddf_authority_tenants",
        ["tenant_id"],
    )

    op.create_table(
        "ddf_agent_cards",
        sa.Column("card_id", sa.String(256), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("agent_id", sa.String(256), nullable=False),
        sa.Column("issuer", sa.String(256), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("card_json", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id",
            "agent_id",
            name="uq_ddf_agent_card_agent",
        ),
    )
    op.create_index(
        "ix_ddf_agent_cards_tenant_id",
        "ddf_agent_cards",
        ["tenant_id"],
    )

    op.create_table(
        "ddf_capabilities",
        sa.Column("capability_id", sa.String(256), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("authority_id", sa.String(256), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("action", sa.String(256), nullable=False),
        sa.Column("resource", sa.String(512), nullable=False),
        sa.Column("purpose", sa.String(256), nullable=False),
        sa.Column("task_id", sa.String(256), nullable=False),
        sa.Column("holder_public_key", sa.Text(), nullable=False),
        sa.Column("capability_json", sa.JSON(), nullable=False),
        sa.Column("uses_remaining", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id",
            "task_id",
            name="uq_ddf_capability_task",
        ),
    )
    op.create_index(
        "ix_ddf_capabilities_tenant_id",
        "ddf_capabilities",
        ["tenant_id"],
    )
    op.create_index(
        "ix_ddf_capabilities_expires_at",
        "ddf_capabilities",
        ["expires_at"],
    )

    op.create_table(
        "ddf_evidence_envelopes",
        sa.Column("evidence_id", sa.String(256), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("principal_id", sa.String(256)),
        sa.Column("authority_id", sa.String(256)),
        sa.Column("capability_id", sa.String(256)),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("previous_hash", sa.String(64)),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("key_id", sa.String(256), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_ddf_evidence_envelopes_tenant_id",
        "ddf_evidence_envelopes",
        ["tenant_id"],
    )
    op.create_index(
        "ix_ddf_evidence_envelopes_created_at",
        "ddf_evidence_envelopes",
        ["created_at"],
    )

    op.create_table(
        "ddf_policy_config",
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("policy_key", sa.String(256), nullable=False),
        sa.Column("value_json", sa.JSON(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.String(256), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "policy_key"),
    )

    op.create_table(
        "ddf_idempotency",
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("principal_id", sa.String(256), nullable=False),
        sa.Column("operation", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(256), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("response_json", sa.JSON()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "principal_id",
            "operation",
            "idempotency_key",
        ),
    )


def downgrade() -> None:
    op.drop_table("ddf_idempotency")
    op.drop_table("ddf_policy_config")

    op.drop_index(
        "ix_ddf_evidence_envelopes_created_at",
        table_name="ddf_evidence_envelopes",
    )
    op.drop_index(
        "ix_ddf_evidence_envelopes_tenant_id",
        table_name="ddf_evidence_envelopes",
    )
    op.drop_table("ddf_evidence_envelopes")

    op.drop_index(
        "ix_ddf_capabilities_expires_at",
        table_name="ddf_capabilities",
    )
    op.drop_index(
        "ix_ddf_capabilities_tenant_id",
        table_name="ddf_capabilities",
    )
    op.drop_table("ddf_capabilities")

    op.drop_index(
        "ix_ddf_agent_cards_tenant_id",
        table_name="ddf_agent_cards",
    )
    op.drop_table("ddf_agent_cards")

    op.drop_index(
        "ix_ddf_authority_tenants_tenant_id",
        table_name="ddf_authority_tenants",
    )
    op.drop_table("ddf_authority_tenants")

    op.drop_index(
        "ix_ddf_nonce_expires",
        table_name="ddf_replay_nonces",
    )
    op.drop_table("ddf_replay_nonces")

    op.drop_index(
        "ix_ddf_principal_subject",
        table_name="ddf_trusted_principals",
    )
    op.drop_table("ddf_trusted_principals")

    op.drop_table("ddf_tenants")
