"""Tests for cascading revocation."""

import uuid

import pytest

from ddf.delegation.service import (
    DelegationService,
    GrantService,
)
from ddf.revocation.service import RevocationService


@pytest.mark.asyncio
async def test_ancestor_revocation_invalidates_descendant(
    test_db,
):
    suffix = uuid.uuid4().hex[:6]

    root = await GrantService.create_grant(
        session=test_db,
        sponsor=f"user:alice-{suffix}@example.com",
        actor=f"agent:planner-{suffix}",
        actions=["purchase"],
        resources=["vendor/*"],
        purposes=["procurement"],
    )

    child, _ = await DelegationService.create_delegation(
        session=test_db,
        parent_authority_id=root.authority_id,
        delegated_to=f"agent:buyer-{suffix}",
    )

    assert not await RevocationService.is_effectively_revoked(
        test_db,
        child.authority_id,
    )

    await RevocationService.revoke(
        test_db,
        authority_id=root.authority_id,
        actor=root.sponsor,
        reason="test",
        cascades=True,
    )

    assert await RevocationService.is_effectively_revoked(
        test_db,
        child.authority_id,
    )
