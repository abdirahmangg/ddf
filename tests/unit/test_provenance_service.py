"""Tests for tamper-evident provenance."""

import uuid

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ddf.db.models import Base, ProvenanceEvent
from ddf.provenance.service import ProvenanceService


@pytest.fixture
async def isolated_test_db(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'provenance.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


@pytest.mark.asyncio
async def test_provenance_chain_detects_tampering(
    isolated_test_db,
):
    """A modified current-format event must invalidate its chain."""
    marker = uuid.uuid4().hex[:8]

    actor_one = f"agent:{marker}:1"
    actor_two = f"agent:{marker}:2"

    try:
        await ProvenanceService.record_event(
            isolated_test_db,
            event_type="test_event",
            actor=actor_one,
            details={"sequence": 1},
        )
        await isolated_test_db.commit()

        await ProvenanceService.record_event(
            isolated_test_db,
            event_type="test_event",
            actor=actor_two,
            details={"sequence": 2},
        )
        await isolated_test_db.commit()

        valid, violations = await ProvenanceService.verify_chain(isolated_test_db)

        assert valid
        assert violations == []

        result = await isolated_test_db.execute(
            select(ProvenanceEvent).where(ProvenanceEvent.actor == actor_two).limit(1)
        )

        event = result.scalar_one()

        event.details_json = {
            **event.details_json,
            "sequence": 999,
        }

        await isolated_test_db.commit()

        valid, violations = await ProvenanceService.verify_chain(isolated_test_db)

        assert not valid
        assert any("PROVENANCE_CONTENT_HASH_MISMATCH" in violation for violation in violations)

    finally:
        await isolated_test_db.execute(
            delete(ProvenanceEvent).where(ProvenanceEvent.actor.in_([actor_one, actor_two]))
        )
        await isolated_test_db.commit()
