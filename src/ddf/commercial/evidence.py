"""Signed, hash-linked enterprise evidence envelopes."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.commercial.crypto import canonical_json, get_system_signer, sha256_hex
from ddf.commercial.db import EvidenceRecord
from ddf.commercial.models import EvidenceEnvelope


async def record_evidence(
    session: AsyncSession,
    *,
    tenant_id: str,
    event_type: str,
    principal_id: str | None = None,
    authority_id: str | None = None,
    capability_id: str | None = None,
    payload: dict | None = None,
) -> EvidenceEnvelope:
    signer = get_system_signer()
    now = datetime.now(UTC)

    bind = session.get_bind()
    if bind.dialect.name == "postgresql":
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:tenant))"),
            {"tenant": f"ddf-evidence:{tenant_id}"},
        )

    previous = (
        await session.execute(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(
                EvidenceRecord.created_at.desc(),
                EvidenceRecord.evidence_id.desc(),
            )
            .limit(1)
        )
    ).scalar_one_or_none()

    previous_hash = previous.content_hash if previous else None
    evidence_id = f"ddf:evidence:{uuid4().hex}"

    material = {
        "version": "ddf-evidence/1",
        "evidence_id": evidence_id,
        "tenant_id": tenant_id,
        "event_type": event_type,
        "principal_id": principal_id,
        "authority_id": authority_id,
        "capability_id": capability_id,
        "payload": payload or {},
        "previous_hash": previous_hash,
        "created_at": now.isoformat(),
    }

    material_bytes = canonical_json(material)
    content_hash = sha256_hex(material_bytes)
    signature = await signer.sign(material_bytes)

    row = EvidenceRecord(
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        event_type=event_type,
        principal_id=principal_id,
        authority_id=authority_id,
        capability_id=capability_id,
        payload_json=payload or {},
        previous_hash=previous_hash,
        content_hash=content_hash,
        key_id=signer.key_id,
        public_key=signer.public_key_b64,
        signature=signature,
        created_at=now,
    )
    session.add(row)

    return EvidenceEnvelope(
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        event_type=event_type,
        principal_id=principal_id,
        authority_id=authority_id,
        capability_id=capability_id,
        payload=payload or {},
        previous_hash=previous_hash,
        content_hash=content_hash,
        key_id=signer.key_id,
        public_key=signer.public_key_b64,
        signature=signature,
        created_at=now,
    )
