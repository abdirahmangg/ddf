"""Mandatory DDF authority laundering test."""

import uuid

import pytest
from sqlalchemy import select

from ddf.api.errors import InvalidAuthorityPathError
from ddf.authority.effective import load_authority_chain
from ddf.db.models import Authority as AuthorityDB
from ddf.delegation.service import (
    DelegationService,
    GrantService,
)


@pytest.mark.asyncio
async def test_fabricated_direct_path_is_denied(
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

    procurement, _ = await DelegationService.create_delegation(
        session=test_db,
        parent_authority_id=root.authority_id,
        delegated_to=(f"agent:procurement-{suffix}"),
    )

    buyer, _ = await DelegationService.create_delegation(
        session=test_db,
        parent_authority_id=(procurement.authority_id),
        delegated_to=f"agent:buyer-{suffix}",
    )

    result = await test_db.execute(
        select(AuthorityDB).where(AuthorityDB.authority_id == buyer.authority_id)
    )

    stored = result.scalar_one()

    stored.authority_path = [
        root.sponsor,
        buyer.actor,
    ]

    await test_db.commit()

    with pytest.raises(InvalidAuthorityPathError):
        await load_authority_chain(
            test_db,
            buyer.authority_id,
        )
