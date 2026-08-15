"""JIT short-lived, PoP-bound, single-use capability broker."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.authority.effective import (
    calculate_effective_authority,
    load_authority_chain,
)
from ddf.authorization.service import AuthorizationService
from ddf.commercial.crypto import (
    canonical_json,
    get_system_signer,
    verify_ed25519,
)
from ddf.commercial.db import AuthorityTenant, CapabilityRecord
from ddf.commercial.evidence import record_evidence
from ddf.commercial.identity import identity_public_key
from ddf.commercial.models import (
    AuthenticatedPrincipal,
    CapabilityDocument,
    ConsumeCapabilityRequest,
    MintCapabilityRequest,
)
from ddf.commercial.production_readiness import capability_caller_allowed
from ddf.revocation.service import RevocationService


def _resource_matches(requested: str, permitted: str) -> bool:
    if requested == permitted:
        return True

    if permitted.endswith("/*"):
        return requested.startswith(permitted[:-1])

    return False


async def mint_capability(
    session: AsyncSession,
    *,
    principal: AuthenticatedPrincipal,
    request: MintCapabilityRequest,
) -> CapabilityDocument:
    mapping = await session.get(AuthorityTenant, request.authority_id)

    if mapping is None or mapping.tenant_id != principal.tenant_id:
        raise ValueError("authority not found in tenant")

    if not capability_caller_allowed(
        principal,
        request.actor,
    ):
        raise ValueError(
            "authenticated principal is not authorized "
            "to mint for capability actor"
        )

    if await RevocationService.is_effectively_revoked(
        session,
        request.authority_id,
    ):
        raise ValueError("authority is revoked")

    chain = await load_authority_chain(session, request.authority_id)

    now = datetime.now(UTC)

    for authority in chain:
        if authority.proof is None:
            raise ValueError(f"authority is missing required signature: {authority.authority_id}")

        AuthorizationService.verify_authority_signature(authority)

        if authority.expires_at <= now:
            raise ValueError(f"authority is expired: {authority.authority_id}")

    effective = calculate_effective_authority(chain)

    if request.actor != effective.actor:
        raise ValueError("capability actor does not match authority holder")

    if request.action not in effective.actions:
        raise ValueError("capability action exceeds effective authority")

    if not any(_resource_matches(request.resource, allowed) for allowed in effective.resources):
        raise ValueError("capability resource exceeds effective authority")

    if request.purpose not in effective.purposes:
        raise ValueError("capability purpose exceeds effective authority")

    max_amount = getattr(effective.constraints, "max_amount", None)
    amount = request.context.get("amount")

    if max_amount is not None and amount is not None and float(amount) > float(max_amount):
        raise ValueError("capability amount exceeds effective authority")

    holder_public_key = await identity_public_key(
        session,
        tenant_id=principal.tenant_id,
        subject=request.actor,
    )

    expires_at = min(
        now + timedelta(seconds=request.ttl_seconds),
        effective.valid_until,
    )

    signer = get_system_signer()

    unsigned = {
        "tenant_id": principal.tenant_id,
        "authority_id": request.authority_id,
        "actor": request.actor,
        "action": request.action,
        "resource": request.resource,
        "purpose": request.purpose,
        "holder_public_key": holder_public_key,
        "task_id": request.task_id,
        "issued_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "uses_remaining": 1,
        "metadata": request.context,
        "issuer_key_id": signer.key_id,
        "issuer_public_key": signer.public_key_b64,
    }

    signature = await signer.sign(canonical_json(unsigned))

    document = CapabilityDocument(
        tenant_id=principal.tenant_id,
        authority_id=request.authority_id,
        actor=request.actor,
        action=request.action,
        resource=request.resource,
        purpose=request.purpose,
        holder_public_key=holder_public_key,
        task_id=request.task_id,
        issued_at=now,
        expires_at=expires_at,
        uses_remaining=1,
        metadata=request.context,
        issuer_key_id=signer.key_id,
        issuer_public_key=signer.public_key_b64,
        signature=signature,
    )

    session.add(
        CapabilityRecord(
            capability_id=document.capability_id,
            tenant_id=document.tenant_id,
            authority_id=document.authority_id,
            actor=document.actor,
            action=document.action,
            resource=document.resource,
            purpose=document.purpose,
            task_id=document.task_id,
            holder_public_key=document.holder_public_key,
            capability_json=document.model_dump(mode="json"),
            uses_remaining=1,
            status="active",
            expires_at=document.expires_at,
        )
    )

    await record_evidence(
        session,
        tenant_id=principal.tenant_id,
        event_type="capability_minted",
        principal_id=principal.subject,
        authority_id=request.authority_id,
        capability_id=document.capability_id,
        payload={
            "task_id": request.task_id,
            "actor": request.actor,
            "action": request.action,
            "resource": request.resource,
            "purpose": request.purpose,
            "expires_at": expires_at.isoformat(),
        },
    )

    await session.commit()
    return document


async def consume_capability(
    session: AsyncSession,
    *,
    principal: AuthenticatedPrincipal,
    capability_id: str,
    request: ConsumeCapabilityRequest,
) -> dict:
    row = (
        await session.execute(
            select(CapabilityRecord)
            .where(
                CapabilityRecord.capability_id == capability_id,
                CapabilityRecord.tenant_id == principal.tenant_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()

    if row is None:
        raise ValueError("capability not found")

    now = datetime.now(UTC)

    if row.status != "active":
        raise ValueError("capability has already been consumed")

    if row.uses_remaining != 1:
        raise ValueError("capability is not available")

    if row.expires_at <= now:
        row.status = "expired"
        await session.commit()
        raise ValueError("capability has expired")

    if row.actor != principal.subject:
        raise ValueError("capability holder does not match principal")

    pop_message = json.dumps(
        {
            "capability_id": capability_id,
            "task_id": row.task_id,
            "nonce": request.nonce,
            "context": request.context,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")

    if not verify_ed25519(
        row.holder_public_key,
        pop_message,
        request.signature,
    ):
        raise ValueError("capability proof-of-possession failed")

    # The SELECT ... FOR UPDATE above serializes concurrent consumers.
    row.uses_remaining = 0
    row.status = "consumed"

    await record_evidence(
        session,
        tenant_id=principal.tenant_id,
        event_type="capability_consumed",
        principal_id=principal.subject,
        authority_id=row.authority_id,
        capability_id=row.capability_id,
        payload={
            "task_id": row.task_id,
            "action": row.action,
            "resource": row.resource,
            "purpose": row.purpose,
        },
    )

    await session.commit()

    return {
        "decision": "ALLOW",
        "capability_id": row.capability_id,
        "task_id": row.task_id,
        "uses_remaining": 0,
        "status": "consumed",
    }
