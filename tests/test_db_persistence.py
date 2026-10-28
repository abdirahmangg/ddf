"""Cross-database persistence and provenance concurrency checks.

Set DDF_TEST_POSTGRES_URL to a dedicated PostgreSQL test database to include
the PostgreSQL variant; SQLite always runs using an isolated temporary file.
"""

import asyncio
import hashlib
import os
from itertools import pairwise
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ddf.authority.revocation import DatabaseRevocationRegistry
from ddf.db.models import Base, CapabilityRevocation, ProvenanceEvent, UniversalAssertionRecord
from ddf.provenance.service import ProvenanceService, _canonical_json


class RecordingOpenFGA:
    enabled = True

    def __init__(self) -> None:
        self.deleted: list[tuple[str, str, str]] = []

    async def delete_capability_tuple(
        self,
        *,
        principal: str,
        target_namespace: str,
        target_resource: str,
    ) -> None:
        self.deleted.append((principal, target_namespace, target_resource))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "database_kind",
    [
        pytest.param("sqlite", id="sqlite-pool"),
        pytest.param(
            "postgresql",
            id="postgresql-pool",
            marks=pytest.mark.skipif(
                not os.getenv("DDF_TEST_POSTGRES_URL"),
                reason="set DDF_TEST_POSTGRES_URL to run PostgreSQL persistence tests",
            ),
        ),
    ],
)
async def test_concurrent_provenance_persistence_is_hash_stable(
    database_kind: str,
    tmp_path: Path,
) -> None:
    if database_kind == "sqlite":
        database_url = f"sqlite+aiosqlite:///{tmp_path / 'persistence.db'}"
    else:
        database_url = os.environ["DDF_TEST_POSTGRES_URL"]
        if database_url.startswith("postgresql://"):
            database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    engine_options = {
        "pool_size": 1 if database_kind == "sqlite" else 4,
        "max_overflow": 0,
        "pool_timeout": 20,
        "pool_pre_ping": True,
    }
    if database_kind == "postgresql":
        engine_options["isolation_level"] = "READ COMMITTED"
    engine = create_async_engine(database_url, **engine_options)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        maker = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        await _assert_concurrent_provenance(maker)
        await _assert_revocation_persistence(maker)
    finally:
        await engine.dispose()


async def _assert_concurrent_provenance(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    marker = uuid4().hex

    async def append_event(index: int) -> str:
        async with maker() as session:
            event = await ProvenanceService.record_event(
                session,
                event_type="persistence_concurrency_test",
                actor=f"urn:agent:test:{marker}",
                details={"marker": marker, "sequence": index},
            )
            content_hash = event.content_hash
            await session.commit()
            return content_hash

    hashes = await asyncio.gather(*(append_event(index) for index in range(24)))
    assert len(set(hashes)) == len(hashes)

    async with maker() as session:
        events = list(
            (
                await session.execute(
                    select(ProvenanceEvent)
                    .where(ProvenanceEvent.actor == f"urn:agent:test:{marker}")
                    .order_by(ProvenanceEvent.created_at, ProvenanceEvent.event_id)
                )
            )
            .scalars()
            .all()
        )
        assert len(events) == 24
        assert all(
            event.content_hash
            == hashlib.sha256(
                _canonical_json(ProvenanceService._payload_for_event(event))
            ).hexdigest()
            for event in events
        )
        for previous, current in pairwise(events):
            assert current.details_json["_ddf_previous_hash"] == previous.content_hash
        valid, violations = await ProvenanceService.verify_chain(session)
        assert valid, violations


async def _assert_revocation_persistence(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    root_id, child_id = str(uuid4()), str(uuid4())
    root_subject, child_subject = "urn:agent:pool-root", "urn:agent:pool-child"
    async with maker() as session:
        session.add_all(
            [
                UniversalAssertionRecord(
                    grant_id=root_id,
                    assertion_json={
                        "grant_id": root_id,
                        "issuer": "did:key:issuer",
                        "subject": root_subject,
                        "capability": {
                            "target_namespace": "mcp",
                            "target_resource": "urn:mcp:tools/*",
                            "operations": ["execute"],
                            "constraints": {},
                        },
                    },
                    proof_json={"algorithm": "Ed25519"},
                ),
                UniversalAssertionRecord(
                    grant_id=child_id,
                    assertion_json={
                        "grant_id": child_id,
                        "issuer": root_subject,
                        "subject": child_subject,
                        "capability": {
                            "target_namespace": "mcp",
                            "target_resource": "urn:mcp:tools/sql_query",
                            "operations": ["execute"],
                            "constraints": {},
                        },
                    },
                    proof_json={"algorithm": "Ed25519"},
                    parent_grant_id=root_id,
                ),
            ]
        )
        await session.commit()

        openfga = RecordingOpenFGA()
        revoked = await DatabaseRevocationRegistry(
            session,
            openfga=openfga,
        ).revoke_subtree(
            root_id,
            actor="urn:agent:pool-controller",
            reason="persistence cross-database test",
        )
        assert set(revoked) == {root_id, child_id}
        assert set(openfga.deleted) == {
            (root_subject, "mcp", "urn:mcp:tools/*"),
            (child_subject, "mcp", "urn:mcp:tools/sql_query"),
        }

    async with maker() as session:
        revoked_ids = (
            await session.execute(
                select(CapabilityRevocation.grant_id).where(
                    CapabilityRevocation.grant_id.in_([root_id, child_id])
                )
            )
        ).scalars().all()
        assert set(revoked_ids) == {root_id, child_id}
        assert (await DatabaseRevocationRegistry(session).check_status(root_id)).revoked
        assert (await DatabaseRevocationRegistry(session).check_status(child_id)).revoked
        valid, violations = await ProvenanceService.verify_chain(session)
        assert valid, violations
