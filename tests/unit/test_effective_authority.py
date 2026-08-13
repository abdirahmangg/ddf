"""Tests for effective multi-hop authority."""

import uuid

import pytest

from ddf.authority.effective import (
    calculate_effective_authority,
    load_authority_chain,
)
from ddf.authority.models import AuthorityConstraints
from ddf.delegation.service import (
    DelegationService,
    GrantService,
)


@pytest.mark.asyncio
async def test_effective_authority_across_three_hops(
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
        constraints=AuthorityConstraints(
            max_amount=10000,
            currency="GBP",
            geographies=["GB"],
        ),
    )

    middle, _ = await DelegationService.create_delegation(
        session=test_db,
        parent_authority_id=root.authority_id,
        delegated_to=f"agent:procurement-{suffix}",
        actions=["purchase"],
        resources=["vendor/dell/*"],
        purposes=["procurement"],
        constraints=AuthorityConstraints(
            max_amount=5000,
            currency="GBP",
            geographies=["GB"],
        ),
    )

    leaf, _ = await DelegationService.create_delegation(
        session=test_db,
        parent_authority_id=middle.authority_id,
        delegated_to=f"agent:buyer-{suffix}",
        actions=["purchase"],
        resources=["vendor/dell/order/*"],
        purposes=["procurement"],
        constraints=AuthorityConstraints(
            max_amount=2000,
            currency="GBP",
            geographies=["GB"],
        ),
    )

    chain = await load_authority_chain(
        test_db,
        leaf.authority_id,
    )

    effective = calculate_effective_authority(chain)

    assert len(chain) == 3
    assert effective.actor == leaf.actor
    assert effective.sponsor == root.sponsor
    assert effective.resources == ["vendor/dell/order/*"]
    assert effective.constraints.max_amount == 2000
