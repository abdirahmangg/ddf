"""Tests for authorization service."""

from datetime import datetime, timedelta, timezone
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ddf.authority.models import AuthorizationRequest, AuthorityConstraints
from ddf.authorization.service import AuthorizationService
from ddf.delegation.service import GrantService
from ddf.settings import get_settings


@pytest.fixture
async def test_db():
    """Create test database session."""
    settings = get_settings()
    db_url = settings.database_url

    if db_url.startswith("postgresql://"):
        db_url = db_url.replace(
            "postgresql://",
            "postgresql+asyncpg://",
            1,
        )

    engine = create_async_engine(
        db_url,
        echo=False,
    )

    session_maker = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        future=True,
    )

    async with session_maker() as session:
        yield session

    await engine.dispose()


class TestAuthorizationService:
    """Test authorization service."""

    @pytest.mark.asyncio
    async def test_authorize_allowed(self, test_db):
        """Test successful authorization."""
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
        )

        request = AuthorizationRequest(
            actor=actor,
            action="purchase",
            resource="vendor/dell/order/123",
            purpose="procurement",
            authority_id=authority.authority_id,
        )

        decision = await AuthorizationService.authorize(
            session=test_db,
            request=request,
        )

        assert decision.decision == "ALLOW"
        assert decision.actor == actor
        assert "all_checks_passed" in decision.reasons

    @pytest.mark.asyncio
    async def test_authorize_denied_actor_mismatch(self, test_db):
        """Test authorization denied due to actor mismatch."""
        sponsor = f"user:alice-{uuid.uuid4().hex[:4]}@example.com"
        actor = f"agent:buyer-{uuid.uuid4().hex[:4]}"

        authority = await GrantService.create_grant(
            session=test_db,
            sponsor=sponsor,
            actor=actor,
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            expires_in_hours=24,
        )

        wrong_actor = f"agent:other-{uuid.uuid4().hex[:4]}"

        request = AuthorizationRequest(
            actor=wrong_actor,
            action="purchase",
            resource="vendor/dell/order/123",
            purpose="procurement",
            authority_id=authority.authority_id,
        )

        decision = await AuthorizationService.authorize(
            session=test_db,
            request=request,
        )

        assert decision.decision == "DENY"
        assert "actor_mismatch" in decision.reasons

    @pytest.mark.asyncio
    async def test_authorize_denied_action_not_permitted(self, test_db):
        """Test authorization denied due to unauthorized action."""
        sponsor = f"user:alice-{uuid.uuid4().hex[:4]}@example.com"
        actor = f"agent:buyer-{uuid.uuid4().hex[:4]}"

        authority = await GrantService.create_grant(
            session=test_db,
            sponsor=sponsor,
            actor=actor,
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            expires_in_hours=24,
        )

        request = AuthorizationRequest(
            actor=actor,
            action="delete",
            resource="vendor/dell/order/123",
            purpose="procurement",
            authority_id=authority.authority_id,
        )

        decision = await AuthorizationService.authorize(
            session=test_db,
            request=request,
        )

        assert decision.decision == "DENY"
        assert "action_not_permitted" in decision.reasons

    @pytest.mark.asyncio
    async def test_authorize_denied_resource_not_permitted(self, test_db):
        """Test authorization denied for unauthorized resource."""
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
        )

        request = AuthorizationRequest(
            actor=actor,
            action="purchase",
            resource="vendor/hp/order/456",
            purpose="procurement",
            authority_id=authority.authority_id,
        )

        decision = await AuthorizationService.authorize(
            session=test_db,
            request=request,
        )

        assert decision.decision == "DENY"
        assert "resource_not_permitted" in decision.reasons

    @pytest.mark.asyncio
    async def test_authorize_denied_expired_authority(self, test_db):
        """
        Test authorization denied for an expired authority.

        Create the authority through GrantService first so the stored
        authority has a valid cryptographic proof and satisfies all database
        invariants. Then modify only its expiry timestamp to simulate a
        previously valid authority that has expired.
        """
        from ddf.api.errors import AuthorityExpiredError
        from ddf.db.models import Authority as AuthorityDB

        sponsor = f"user:alice-{uuid.uuid4().hex[:4]}@example.com"
        actor = f"agent:buyer-{uuid.uuid4().hex[:4]}"

        authority = await GrantService.create_grant(
            session=test_db,
            sponsor=sponsor,
            actor=actor,
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            expires_in_hours=24,
        )

        result = await test_db.execute(
            select(AuthorityDB).where(
                AuthorityDB.authority_id == authority.authority_id
            )
        )
        stored_authority = result.scalar_one()

        stored_authority.expires_at = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        )

        await test_db.commit()

        request = AuthorizationRequest(
            actor=actor,
            action="purchase",
            resource="vendor/dell/order/123",
            purpose="procurement",
            authority_id=authority.authority_id,
        )

        with pytest.raises(AuthorityExpiredError):
            await AuthorizationService.authorize(
                session=test_db,
                request=request,
            )

    @pytest.mark.asyncio
    async def test_authorize_with_constraints(self, test_db):
        """Test authorization respects constraints."""
        sponsor = f"user:alice-{uuid.uuid4().hex[:4]}@example.com"
        actor = f"agent:buyer-{uuid.uuid4().hex[:4]}"

        authority = await GrantService.create_grant(
            session=test_db,
            sponsor=sponsor,
            actor=actor,
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            constraints=AuthorityConstraints(
                max_amount=50000,
                currency="USD",
            ),
            expires_in_hours=24,
        )

        request = AuthorizationRequest(
            actor=actor,
            action="purchase",
            resource="vendor/dell/order/123",
            purpose="procurement",
            authority_id=authority.authority_id,
        )

        decision = await AuthorizationService.authorize(
            session=test_db,
            request=request,
        )

        assert decision.decision == "ALLOW"
        assert decision.effective_constraints is not None
        assert decision.effective_constraints.max_amount == 50000
