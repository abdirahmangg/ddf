"""Protected tenant policy configuration."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from ddf.commercial.db import PolicyRecord
from ddf.commercial.evidence import record_evidence
from ddf.commercial.models import AuthenticatedPrincipal


async def set_policy(
    session: AsyncSession,
    *,
    principal: AuthenticatedPrincipal,
    key: str,
    value: dict,
) -> PolicyRecord:
    record = await session.get(
        PolicyRecord,
        {
            "tenant_id": principal.tenant_id,
            "policy_key": key,
        },
    )

    if record is None:
        record = PolicyRecord(
            tenant_id=principal.tenant_id,
            policy_key=key,
            value_json=value,
            version=1,
            updated_by=principal.subject,
        )
        session.add(record)
    else:
        record.value_json = value
        record.version += 1
        record.updated_by = principal.subject

    await record_evidence(
        session,
        tenant_id=principal.tenant_id,
        event_type="policy_updated",
        principal_id=principal.subject,
        payload={
            "policy_key": key,
            "version": record.version,
        },
    )

    await session.commit()
    return record
