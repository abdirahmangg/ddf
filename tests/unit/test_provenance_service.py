"""Tests for tamper-evident provenance."""

import uuid

import pytest
from sqlalchemy import delete, select

from ddf.db.models import ProvenanceEvent
from ddf.provenance.service import ProvenanceService


@pytest.mark.asyncio
async def test_provenance_chain_detects_tampering(
    test_db,
):
    """A modified current-format event must invalidate its chain."""
    marker = uuid.uuid4().hex[:8]

    actor_one = f"agent:{marker}:1"
    actor_two = f"agent:{marker}:2"

    try:
        await ProvenanceService.record_event(
            test_db,
            event_type="test_event",
            actor=actor_one,
            details={"sequence": 1},
        )
        await test_db.commit()

        await ProvenanceService.record_event(
            test_db,
            event_type="test_event",
            actor=actor_two,
            details={"sequence": 2},
        )
        await test_db.commit()

        valid, violations = await ProvenanceService.verify_chain(test_db)

        assert valid
        assert violations == []

        result = await test_db.execute(
            select(ProvenanceEvent).where(ProvenanceEvent.actor == actor_two).limit(1)
        )

        event = result.scalar_one()

        event.details_json = {
            **event.details_json,
            "sequence": 999,
        }

        await test_db.commit()

        valid, violations = await ProvenanceService.verify_chain(test_db)

        assert not valid
        assert any("PROVENANCE_CONTENT_HASH_MISMATCH" in violation for violation in violations)

    finally:
        await test_db.execute(
            delete(ProvenanceEvent).where(ProvenanceEvent.actor.in_([actor_one, actor_two]))
        )
        await test_db.commit()
