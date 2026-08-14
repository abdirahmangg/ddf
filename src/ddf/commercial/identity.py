"""Tenant principal registry and signed agent identity cards."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.commercial.crypto import canonical_json, get_system_signer
from ddf.commercial.db import AgentCardRecord, TrustedPrincipal
from ddf.commercial.evidence import record_evidence
from ddf.commercial.models import (
    AgentCard,
    AuthenticatedPrincipal,
    RegisterAgentRequest,
)


async def register_agent(
    session: AsyncSession,
    *,
    principal: AuthenticatedPrincipal,
    request: RegisterAgentRequest,
) -> AgentCard:
    signer = get_system_signer()

    existing = (
        await session.execute(
            select(AgentCardRecord).where(
                AgentCardRecord.tenant_id == principal.tenant_id,
                AgentCardRecord.agent_id == request.agent_id,
            )
        )
    ).scalar_one_or_none()

    if existing is not None:
        raise ValueError(f"agent already registered: {request.agent_id}")

    card = AgentCard(
        tenant_id=principal.tenant_id,
        agent_id=request.agent_id,
        issuer=principal.subject,
        public_key=request.public_key,
        protocols=request.protocols,
        capabilities=request.capabilities,
        organization=request.organization,
        expires_at=request.expires_at,
        metadata=request.metadata,
        signing_key_id=signer.key_id,
    )

    unsigned = card.model_dump(mode="json")
    unsigned["signature"] = None
    card.signature = await signer.sign(canonical_json(unsigned))

    session.add(
        AgentCardRecord(
            card_id=card.card_id,
            tenant_id=card.tenant_id,
            agent_id=card.agent_id,
            issuer=card.issuer,
            public_key=card.public_key,
            card_json=card.model_dump(mode="json"),
            status="active",
        )
    )

    # Agent becomes a trusted PoP identity but receives no admin roles.
    session.add(
        TrustedPrincipal(
            tenant_id=principal.tenant_id,
            subject=request.agent_id,
            identity_type="agent",
            key_id=f"{request.agent_id}:primary",
            public_key=request.public_key,
            roles_json=[],
            active=True,
        )
    )

    await record_evidence(
        session,
        tenant_id=principal.tenant_id,
        event_type="agent_registered",
        principal_id=principal.subject,
        payload={"agent_id": request.agent_id, "card_id": card.card_id},
    )

    await session.commit()
    return card


async def identity_public_key(
    session: AsyncSession,
    *,
    tenant_id: str,
    subject: str,
) -> str:
    row = (
        await session.execute(
            select(TrustedPrincipal).where(
                TrustedPrincipal.tenant_id == tenant_id,
                TrustedPrincipal.subject == subject,
                TrustedPrincipal.active.is_(True),
            )
        )
    ).scalar_one_or_none()

    if row is None:
        raise ValueError(f"unregistered identity: {subject}")

    return row.public_key
