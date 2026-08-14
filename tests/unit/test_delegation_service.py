"""Tests for grant and delegation services."""

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ddf.api.errors import AttenuationViolationError
from ddf.authority.models import AuthorityConstraints
from ddf.delegation.service import DelegationService, GrantService
from ddf.settings import get_settings


@pytest.fixture
async def test_db():
    """Create test database session."""
    settings = get_settings()
    db_url = settings.database_url

    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

    engine = create_async_engine(db_url, echo=False)

    session_maker = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        future=True,
    )

    async with session_maker() as session:
        yield session


class TestGrantService:
    """Test grant service."""

    @pytest.mark.asyncio
    async def test_create_grant(self, test_db):
        """Test creating a root authority grant."""
        sponsor = f"user:alice-{uuid.uuid4().hex[:4]}@example.com"
        actor = f"agent:buyer-{uuid.uuid4().hex[:4]}"

        authority = await GrantService.create_grant(
            session=test_db,
            sponsor=sponsor,
            actor=actor,
            actions=["purchase"],
            resources=["vendor/dell/*"],
            purposes=["procurement"],
            expires_in_hours=24,
            reason="Initial procurement authority",
        )

        assert authority.sponsor == sponsor
        assert authority.actor == actor
        assert authority.actions == ["purchase"]
        assert authority.parent_authority_id is None
        assert authority.authority_path == [sponsor, actor]

    @pytest.mark.asyncio
    async def test_create_grant_with_constraints(self, test_db):
        """Test creating a grant with constraints."""
        sponsor = f"user:alice-{uuid.uuid4().hex[:4]}@example.com"
        actor = f"agent:buyer-{uuid.uuid4().hex[:4]}"
        constraints = AuthorityConstraints(
            max_amount=50000,
            currency="USD",
            geographies=["US", "CA"],
        )

        authority = await GrantService.create_grant(
            session=test_db,
            sponsor=sponsor,
            actor=actor,
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            constraints=constraints,
            expires_in_hours=24,
        )

        assert authority.constraints.max_amount == 50000
        assert authority.constraints.currency == "USD"
        assert "US" in authority.constraints.geographies


class TestDelegationService:
    """Test delegation service."""

    @pytest.mark.asyncio
    async def test_create_delegation(self, test_db):
        """Test delegating an authority."""
        # First create a parent grant
        sponsor = f"user:alice-{uuid.uuid4().hex[:4]}@example.com"
        actor = f"agent:buyer-{uuid.uuid4().hex[:4]}"

        parent_authority = await GrantService.create_grant(
            session=test_db,
            sponsor=sponsor,
            actor=actor,
            actions=["purchase", "quote"],
            resources=["vendor/dell/*"],
            purposes=["procurement"],
            expires_in_hours=24,
        )

        # Now delegate from the buyer to another agent
        delegated_to = f"agent:buyer-delegate-{uuid.uuid4().hex[:4]}"

        child_authority, delegation_id = await DelegationService.create_delegation(
            session=test_db,
            parent_authority_id=parent_authority.authority_id,
            delegated_to=delegated_to,
            actions=["purchase"],  # More restrictive
            resources=["vendor/dell/order/*"],  # More restrictive
            purposes=["procurement"],
        )

        assert child_authority.actor == delegated_to
        assert child_authority.sponsor == sponsor
        assert child_authority.actions == ["purchase"]
        assert child_authority.parent_authority_id == parent_authority.authority_id
        assert delegation_id.startswith("ddf:delegation:")

    @pytest.mark.asyncio
    async def test_delegation_inherits_parent_scope(self, test_db):
        """Test that delegation inherits parent scope when not specified."""
        sponsor = f"user:alice-{uuid.uuid4().hex[:4]}@example.com"
        actor = f"agent:buyer-{uuid.uuid4().hex[:4]}"

        parent_authority = await GrantService.create_grant(
            session=test_db,
            sponsor=sponsor,
            actor=actor,
            actions=["purchase", "quote"],
            resources=["vendor/*"],
            purposes=["procurement"],
            expires_in_hours=24,
        )

        delegated_to = f"agent:delegate-{uuid.uuid4().hex[:4]}"

        # Don't specify actions, resources, or purposes
        child_authority, _ = await DelegationService.create_delegation(
            session=test_db,
            parent_authority_id=parent_authority.authority_id,
            delegated_to=delegated_to,
        )

        # Should inherit from parent
        assert child_authority.actions == parent_authority.actions
        assert child_authority.resources == parent_authority.resources
        assert child_authority.purposes == parent_authority.purposes

    @pytest.mark.asyncio
    async def test_delegation_rejects_expansion(self, test_db):
        """Test that delegation rejects privilege expansion."""
        sponsor = f"user:alice-{uuid.uuid4().hex[:4]}@example.com"
        actor = f"agent:buyer-{uuid.uuid4().hex[:4]}"

        parent_authority = await GrantService.create_grant(
            session=test_db,
            sponsor=sponsor,
            actor=actor,
            actions=["purchase"],
            resources=["vendor/dell/*"],
            purposes=["procurement"],
            constraints=AuthorityConstraints(max_amount=10000),
            expires_in_hours=24,
        )

        delegated_to = f"agent:delegate-{uuid.uuid4().hex[:4]}"

        # Try to expand to more actions
        with pytest.raises(AttenuationViolationError):
            await DelegationService.create_delegation(
                session=test_db,
                parent_authority_id=parent_authority.authority_id,
                delegated_to=delegated_to,
                actions=["purchase", "delete"],  # Expansion!
            )

    @pytest.mark.asyncio
    async def test_delegation_chain_authority_path(self, test_db):
        """Test that delegation chains are tracked in authority_path."""
        sponsor = f"user:alice-{uuid.uuid4().hex[:4]}@example.com"
        buyer = f"agent:buyer-{uuid.uuid4().hex[:4]}"
        delegate1 = f"agent:delegate1-{uuid.uuid4().hex[:4]}"
        delegate2 = f"agent:delegate2-{uuid.uuid4().hex[:4]}"

        # Create root grant
        root_auth = await GrantService.create_grant(
            session=test_db,
            sponsor=sponsor,
            actor=buyer,
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            expires_in_hours=24,
        )

        # First delegation
        child1, _ = await DelegationService.create_delegation(
            session=test_db,
            parent_authority_id=root_auth.authority_id,
            delegated_to=delegate1,
        )

        assert child1.authority_path == [sponsor, buyer, delegate1]

        # Second delegation
        child2, _ = await DelegationService.create_delegation(
            session=test_db,
            parent_authority_id=child1.authority_id,
            delegated_to=delegate2,
        )

        assert child2.authority_path == [sponsor, buyer, delegate1, delegate2]
