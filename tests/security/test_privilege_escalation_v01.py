"""Mandatory DDF privilege escalation test."""

from datetime import UTC, datetime, timedelta

from ddf.authority.attenuation import AttenuationEngine
from ddf.authority.models import (
    Authority,
    AuthorityConstraints,
)


def test_child_cannot_expand_purchase_limit():
    now = datetime.now(UTC)

    parent = Authority(
        actor="agent:parent",
        sponsor="user:alice@example.com",
        actions=["purchase"],
        resources=["vendor/*"],
        purposes=["procurement"],
        authority_path=[
            "user:alice@example.com",
            "agent:parent",
        ],
        constraints=AuthorityConstraints(
            max_amount=2000,
            currency="GBP",
        ),
        issued_at=now,
        expires_at=now + timedelta(hours=2),
        holder_public_key="",
    )

    child = Authority(
        actor="agent:child",
        sponsor="user:alice@example.com",
        actions=["purchase"],
        resources=["vendor/dell/*"],
        purposes=["procurement"],
        authority_path=[
            "user:alice@example.com",
            "agent:parent",
            "agent:child",
        ],
        constraints=AuthorityConstraints(
            max_amount=20000,
            currency="GBP",
        ),
        issued_at=now + timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        parent_authority_id=parent.authority_id,
        holder_public_key="",
    )

    result = AttenuationEngine.is_attenuation_valid(
        parent,
        child,
    )

    assert not result.allowed
    assert any("AUTHORITY_AMOUNT_EXPANSION" in violation for violation in result.violations)
