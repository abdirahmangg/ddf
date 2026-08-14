"""Tests for database models and operations."""

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ddf.db.models import (
    Authority,
    AuthorityDelegation,
    AuthorizationLog,
    Identity,
    ProvenanceEvent,
    Revocation,
)
from ddf.settings import get_settings


@pytest.fixture
async def test_db():
    """Create test database and session."""
    # Use in-memory SQLite for testing (or test PostgreSQL)
    settings = get_settings()
    db_url = settings.database_url

    # Convert to async URL
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

    engine = create_async_engine(db_url, echo=False)

    # Create tables
    async with engine.begin():
        # Note: In a real test, you'd use a test-specific database
        pass

    session_maker = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        future=True,
    )

    async with session_maker() as session:
        yield session


def unique_id(prefix: str) -> str:
    """Generate a unique ID for testing."""
    return f"{prefix}{uuid.uuid4().hex[:8]}"


class TestIdentityModel:
    """Test Identity model."""

    @pytest.mark.asyncio
    async def test_create_agent_identity(self, test_db):
        """Test creating an agent identity."""
        agent_id = f"agent:arkstride:buyer-{uuid.uuid4().hex[:8]}"

        identity = Identity(
            id=agent_id,
            identity_type="agent",
            display_name="Buyer Agent",
            public_key="base64encodedpublickey",
            metadata_json={"organization": "ACME Corp"},
        )

        test_db.add(identity)
        await test_db.commit()

        # Verify identity was created
        assert identity.id == agent_id
        assert identity.identity_type == "agent"
        assert identity.created_at is not None

    @pytest.mark.asyncio
    async def test_create_user_identity(self, test_db):
        """Test creating a user identity."""
        user_email = f"alice-{uuid.uuid4().hex[:8]}@example.com"
        user_id = f"user:{user_email}"

        identity = Identity(
            id=user_id,
            identity_type="user",
            display_name="Alice",
            metadata_json={"email": user_email},
        )

        test_db.add(identity)
        await test_db.commit()

        assert identity.identity_type == "user"
        assert identity.metadata_json["email"] == user_email


class TestAuthorityModel:
    """Test Authority model."""

    @pytest.mark.asyncio
    async def test_create_authority(self, test_db):
        """Test creating an authority."""
        now = datetime.now(UTC)
        auth_id = f"ddf:authority:{uuid.uuid4().hex[:8]}"

        authority = Authority(
            authority_id=auth_id,
            version="ddf/0.1",
            actor="agent:arkstride:buyer-42",
            sponsor="user:alice@example.com",
            actions=["purchase", "quote"],
            resources=["vendor/dell/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com", "agent:arkstride:buyer-42"],
            issued_at=now,
            expires_at=now,
            holder_public_key="base64key",
            proof_json={"algorithm": "Ed25519", "key_id": "key:123", "signature": "sig"},
        )

        test_db.add(authority)
        await test_db.commit()

        assert authority.authority_id == auth_id
        assert authority.version == "ddf/0.1"
        assert "purchase" in authority.actions
        assert "vendor/dell/*" in authority.resources


class TestAuthorizationLogModel:
    """Test AuthorizationLog model."""

    @pytest.mark.asyncio
    async def test_log_authorization_decision(self, test_db):
        """Test logging an authorization decision."""
        decision_id = f"ddf:decision:{uuid.uuid4().hex[:8]}"

        decision = AuthorizationLog(
            decision_id=decision_id,
            actor="agent:arkstride:buyer-42",
            action="purchase",
            resource="vendor/dell/order/123",
            purpose="procurement",
            decision="ALLOW",
            authority_id="ddf:authority:test123",
            reasons=["authority_valid", "constraint_satisfied"],
        )

        test_db.add(decision)
        await test_db.commit()

        assert decision.decision == "ALLOW"
        assert "authority_valid" in decision.reasons


class TestDelegationModel:
    """Test AuthorityDelegation model."""

    @pytest.mark.asyncio
    async def test_create_delegation(self, test_db):
        """Test creating a delegation record."""
        # First create parent and child authorities with unique IDs
        now = datetime.now(UTC)
        parent_id = f"ddf:authority:parent-{uuid.uuid4().hex[:8]}"
        child_id = f"ddf:authority:child-{uuid.uuid4().hex[:8]}"

        parent_auth = Authority(
            authority_id=parent_id,
            version="ddf/0.1",
            actor="user:alice@example.com",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com"],
            issued_at=now,
            expires_at=now,
            holder_public_key="key1",
            proof_json={"algorithm": "Ed25519", "key_id": "key:1", "signature": "sig"},
        )
        test_db.add(parent_auth)

        child_auth = Authority(
            authority_id=child_id,
            version="ddf/0.1",
            actor="agent:arkstride:buyer-42",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/dell/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com", "agent:arkstride:buyer-42"],
            issued_at=now,
            expires_at=now,
            holder_public_key="key2",
            proof_json={"algorithm": "Ed25519", "key_id": "key:2", "signature": "sig"},
        )
        test_db.add(child_auth)
        await test_db.commit()

        # Now create delegation
        delegation = AuthorityDelegation(
            parent_authority_id=parent_id,
            child_authority_id=child_id,
            actor="user:alice@example.com",
            delegated_to="agent:arkstride:buyer-42",
            reason="Delegating procurement authority",
        )

        test_db.add(delegation)
        await test_db.commit()

        assert delegation.actor == "user:alice@example.com"
        assert delegation.delegated_to == "agent:arkstride:buyer-42"


class TestRevocationModel:
    """Test Revocation model."""

    @pytest.mark.asyncio
    async def test_create_revocation(self, test_db):
        """Test creating a revocation record."""
        # First create an authority
        now = datetime.now(UTC)
        auth_id = f"ddf:authority:{uuid.uuid4().hex[:8]}"

        authority = Authority(
            authority_id=auth_id,
            version="ddf/0.1",
            actor="user:alice@example.com",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com"],
            issued_at=now,
            expires_at=now,
            holder_public_key="key1",
            proof_json={"algorithm": "Ed25519", "key_id": "key:1", "signature": "sig"},
        )
        test_db.add(authority)
        await test_db.commit()

        # Now revoke it
        revocation = Revocation(
            authority_id=auth_id,
            actor="user:alice@example.com",
            reason="Revoking compromised authority",
            cascades=True,
        )

        test_db.add(revocation)
        await test_db.commit()

        assert revocation.authority_id == auth_id
        assert revocation.cascades is True


class TestProvenanceEventModel:
    """Test ProvenanceEvent model."""

    @pytest.mark.asyncio
    async def test_create_provenance_event(self, test_db):
        """Test creating a provenance event."""
        auth_id = f"ddf:authority:{uuid.uuid4().hex[:8]}"

        event = ProvenanceEvent(
            event_type="authority_issued",
            authority_id=auth_id,
            actor="user:alice@example.com",
            sponsor="user:alice@example.com",
            action="grant",
            resource="vendor/dell/*",
            details_json={"constraint": {"max_amount": 50000}},
            content_hash="abc123def456",
        )

        test_db.add(event)
        await test_db.commit()

        assert event.event_type == "authority_issued"
        assert event.details_json["constraint"]["max_amount"] == 50000
