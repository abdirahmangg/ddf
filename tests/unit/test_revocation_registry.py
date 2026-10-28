"""Tests for persistent universal capability revocation."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import select

from ddf.authority.revocation import (
    DatabaseRevocationRegistry,
    RevocationStatus,
)
from ddf.db.models import CapabilityRevocation, UniversalAssertionRecord


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


class StaticStatusSource:
    async def check_status(self, grant_id: str) -> RevocationStatus:
        return RevocationStatus(
            grant_id=grant_id,
            revoked=True,
            checked_at=datetime.now(UTC),
            reason="listed in trusted revocation source",
            source="test-crl",
        )


def assertion_record(
    grant_id: str,
    subject: str,
    *,
    parent_grant_id: str | None = None,
) -> UniversalAssertionRecord:
    return UniversalAssertionRecord(
        grant_id=grant_id,
        assertion_json={
            "grant_id": grant_id,
            "issuer": "did:key:issuer",
            "subject": subject,
            "capability": {
                "target_namespace": "mcp",
                "target_resource": "urn:mcp:tools:sql_query",
                "operations": ["execute"],
                "constraints": {},
            },
        },
        proof_json={"algorithm": "Ed25519"},
        parent_grant_id=parent_grant_id,
    )


@pytest.mark.asyncio
async def test_revocation_marks_descendants_and_invalidates_openfga_tuples(test_db: Any) -> None:
    root_id, child_id, leaf_id = str(uuid4()), str(uuid4()), str(uuid4())
    test_db.add_all(
        [
            assertion_record(root_id, "urn:agent:root"),
            assertion_record(child_id, "urn:agent:child", parent_grant_id=root_id),
            assertion_record(leaf_id, "urn:agent:leaf", parent_grant_id=child_id),
        ]
    )
    await test_db.commit()
    openfga = RecordingOpenFGA()

    revoked = await DatabaseRevocationRegistry(test_db, openfga=openfga).revoke_subtree(
        root_id,
        actor="urn:agent:security-controller",
        reason="runtime posture fell below threshold",
    )

    assert set(revoked) == {root_id, child_id, leaf_id}
    statuses = (
        await test_db.execute(
            select(CapabilityRevocation.grant_id).where(
                CapabilityRevocation.grant_id.in_([root_id, child_id, leaf_id])
            )
        )
    ).scalars().all()
    assert set(statuses) == {root_id, child_id, leaf_id}
    assert set(openfga.deleted) == {
        ("urn:agent:root", "mcp", "urn:mcp:tools:sql_query"),
        ("urn:agent:child", "mcp", "urn:mcp:tools:sql_query"),
        ("urn:agent:leaf", "mcp", "urn:mcp:tools:sql_query"),
    }

    status = await DatabaseRevocationRegistry(test_db).check_status(child_id)
    assert status.revoked
    assert status.reason == "runtime posture fell below threshold"


@pytest.mark.asyncio
async def test_live_status_source_supports_crl_or_ocsp_style_checks(test_db: Any) -> None:
    status = await DatabaseRevocationRegistry(
        test_db,
        status_sources=[StaticStatusSource()],
    ).check_status(str(uuid4()))

    assert status.revoked
    assert status.source == "test-crl"
