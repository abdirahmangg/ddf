"""Tests for authority attenuation engine."""

from datetime import datetime, timezone, timedelta

import pytest

from ddf.authority.attenuation import AttenuationEngine
from ddf.authority.models import Authority, AuthorityConstraints


class TestAttenuationValidation:
    """Test authority attenuation validation."""

    @pytest.fixture
    def base_parent(self) -> Authority:
        """Create a base parent authority for testing."""
        now = datetime.now(timezone.utc)
        return Authority(
            actor="agent:planner",
            sponsor="user:alice@example.com",
            actions=["purchase", "quote"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com", "agent:planner"],
            issued_at=now,
            expires_at=now + timedelta(hours=3),
            holder_public_key="parent_public_key",
            constraints=AuthorityConstraints(
                max_amount=10000.0,
                currency="GBP",
                geographies=["GB", "US"],
                delegation_depth_remaining=3,
            ),
        )

    def test_valid_narrowing(self, base_parent):
        """Test that valid narrowing is accepted."""
        now = datetime.now(timezone.utc)
        child = Authority(
            actor="agent:procurement",
            sponsor="user:alice@example.com",
            actions=["purchase"],  # Narrower
            resources=["vendor/dell/*"],  # Narrower
            purposes=["procurement"],  # Same
            authority_path=[
                "user:alice@example.com",
                "agent:planner",
                "agent:procurement",
            ],
            issued_at=now,
            expires_at=now + timedelta(hours=2),  # Earlier
            holder_public_key="child_public_key",
            parent_authority_id=base_parent.authority_id,
            constraints=AuthorityConstraints(
                max_amount=5000.0,  # Less
                currency="GBP",
                geographies=["GB"],  # Subset
                delegation_depth_remaining=2,  # Less
            ),
        )

        result = AttenuationEngine.is_attenuation_valid(base_parent, child)
        assert result.allowed
        assert len(result.violations) == 0
        assert result.effective_constraints is not None
        assert result.effective_constraints.max_amount == 5000.0

    def test_action_expansion_denied(self, base_parent):
        """Test that expanding actions is denied."""
        now = datetime.now(timezone.utc)
        child = Authority(
            actor="agent:procurement",
            sponsor="user:alice@example.com",
            actions=["purchase", "quote", "delete"],  # Expansion!
            resources=["vendor/dell/*"],
            purposes=["procurement"],
            authority_path=[
                "user:alice@example.com",
                "agent:planner",
                "agent:procurement",
            ],
            issued_at=now,
            expires_at=now + timedelta(hours=2),
            holder_public_key="child_public_key",
            parent_authority_id=base_parent.authority_id,
            constraints=AuthorityConstraints(
                max_amount=5000.0,
                currency="GBP",
            ),
        )

        result = AttenuationEngine.is_attenuation_valid(base_parent, child)
        assert not result.allowed
        assert any("ACTION_EXPANSION" in v for v in result.violations)

    def test_resource_expansion_denied(self, base_parent):
        """Test that expanding resources is denied."""
        now = datetime.now(timezone.utc)
        child = Authority(
            actor="agent:procurement",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*", "crm/*"],  # Expansion!
            purposes=["procurement"],
            authority_path=[
                "user:alice@example.com",
                "agent:planner",
                "agent:procurement",
            ],
            issued_at=now,
            expires_at=now + timedelta(hours=2),
            holder_public_key="child_public_key",
            parent_authority_id=base_parent.authority_id,
            constraints=AuthorityConstraints(
                max_amount=5000.0,
                currency="GBP",
            ),
        )

        result = AttenuationEngine.is_attenuation_valid(base_parent, child)
        assert not result.allowed
        assert any("RESOURCE_EXPANSION" in v for v in result.violations)

    def test_purpose_expansion_denied(self, base_parent):
        """Test that expanding purposes is denied."""
        now = datetime.now(timezone.utc)
        child = Authority(
            actor="agent:procurement",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/dell/*"],
            purposes=["procurement", "marketing"],  # Expansion!
            authority_path=[
                "user:alice@example.com",
                "agent:planner",
                "agent:procurement",
            ],
            issued_at=now,
            expires_at=now + timedelta(hours=2),
            holder_public_key="child_public_key",
            parent_authority_id=base_parent.authority_id,
            constraints=AuthorityConstraints(
                max_amount=5000.0,
                currency="GBP",
            ),
        )

        result = AttenuationEngine.is_attenuation_valid(base_parent, child)
        assert not result.allowed
        assert any("PURPOSE_EXPANSION" in v for v in result.violations)

    def test_amount_expansion_denied(self, base_parent):
        """Test that expanding max_amount is denied."""
        now = datetime.now(timezone.utc)
        child = Authority(
            actor="agent:procurement",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/dell/*"],
            purposes=["procurement"],
            authority_path=[
                "user:alice@example.com",
                "agent:planner",
                "agent:procurement",
            ],
            issued_at=now,
            expires_at=now + timedelta(hours=2),
            holder_public_key="child_public_key",
            parent_authority_id=base_parent.authority_id,
            constraints=AuthorityConstraints(
                max_amount=15000.0,  # Expansion!
                currency="GBP",
            ),
        )

        result = AttenuationEngine.is_attenuation_valid(base_parent, child)
        assert not result.allowed
        assert any("AMOUNT_EXPANSION" in v for v in result.violations)

    def test_geography_expansion_denied(self, base_parent):
        """Test that expanding geographies is denied."""
        now = datetime.now(timezone.utc)
        child = Authority(
            actor="agent:procurement",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/dell/*"],
            purposes=["procurement"],
            authority_path=[
                "user:alice@example.com",
                "agent:planner",
                "agent:procurement",
            ],
            issued_at=now,
            expires_at=now + timedelta(hours=2),
            holder_public_key="child_public_key",
            parent_authority_id=base_parent.authority_id,
            constraints=AuthorityConstraints(
                max_amount=5000.0,
                currency="GBP",
                geographies=["GB", "US", "CA"],  # Expansion!
            ),
        )

        result = AttenuationEngine.is_attenuation_valid(base_parent, child)
        assert not result.allowed
        assert any("GEOGRAPHY_EXPANSION" in v for v in result.violations)


class TestAttenuationChain:
    """Test attenuation across chains of authorities."""

    def test_valid_three_level_chain(self):
        """Test valid attenuation across three levels."""
        now = datetime.now(timezone.utc)

        root = Authority(
            actor="user:alice@example.com",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com"],
            issued_at=now,
            expires_at=now + timedelta(hours=3),
            holder_public_key="root_key",
            constraints=AuthorityConstraints(
                max_amount=10000.0,
                geographies=["GB", "US"],
                delegation_depth_remaining=3,
            ),
        )

        level1 = Authority(
            actor="agent:planner",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com", "agent:planner"],
            issued_at=now,
            expires_at=now + timedelta(hours=2),
            holder_public_key="level1_key",
            parent_authority_id=root.authority_id,
            constraints=AuthorityConstraints(
                max_amount=5000.0,
                geographies=["GB"],
                delegation_depth_remaining=2,
            ),
        )

        level2 = Authority(
            actor="agent:buyer",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/dell/*"],
            purposes=["procurement"],
            authority_path=[
                "user:alice@example.com",
                "agent:planner",
                "agent:buyer",
            ],
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            holder_public_key="level2_key",
            parent_authority_id=level1.authority_id,
            constraints=AuthorityConstraints(
                max_amount=2000.0,
                geographies=["GB"],
                delegation_depth_remaining=1,
            ),
        )

        result = AttenuationEngine.attenuation_chain_valid([root, level1, level2])
        assert result.allowed
        assert len(result.violations) == 0
        assert result.effective_constraints.max_amount == 2000.0
        assert result.effective_constraints.delegation_depth_remaining == 1

    def test_chain_with_violation_at_level_2(self):
        """Test chain validation catches violation at level 2."""
        now = datetime.now(timezone.utc)

        root = Authority(
            actor="user:alice@example.com",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com"],
            issued_at=now,
            expires_at=now + timedelta(hours=3),
            holder_public_key="root_key",
            constraints=AuthorityConstraints(
                max_amount=10000.0,
                delegation_depth_remaining=3,
            ),
        )

        level1 = Authority(
            actor="agent:planner",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com", "agent:planner"],
            issued_at=now,
            expires_at=now + timedelta(hours=2),
            holder_public_key="level1_key",
            parent_authority_id=root.authority_id,
            constraints=AuthorityConstraints(
                max_amount=5000.0,
                delegation_depth_remaining=2,
            ),
        )

        level2 = Authority(
            actor="agent:buyer",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/dell/*"],
            purposes=["procurement"],
            authority_path=[
                "user:alice@example.com",
                "agent:planner",
                "agent:buyer",
            ],
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            holder_public_key="level2_key",
            parent_authority_id=level1.authority_id,
            constraints=AuthorityConstraints(
                max_amount=7000.0,  # Expansion!
                delegation_depth_remaining=1,
            ),
        )

        result = AttenuationEngine.attenuation_chain_valid([root, level1, level2])
        assert not result.allowed
        assert any("AMOUNT_EXPANSION" in v for v in result.violations)
        assert any("delegation 1 → 2" in v for v in result.violations)

    def test_empty_chain_denied(self):
        """Test that empty authority chain is denied."""
        result = AttenuationEngine.attenuation_chain_valid([])
        assert not result.allowed
        assert "EMPTY_AUTHORITY_CHAIN" in result.violations

    def test_single_authority_chain(self):
        """Test that single authority (root) chain is valid."""
        now = datetime.now(timezone.utc)

        root = Authority(
            actor="user:alice@example.com",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com"],
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            holder_public_key="root_key",
        )

        result = AttenuationEngine.attenuation_chain_valid([root])
        assert result.allowed
        assert len(result.violations) == 0
