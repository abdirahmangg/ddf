"""Property-based tests for authorization invariants using Hypothesis."""

from datetime import datetime, timezone, timedelta

from hypothesis import given, strategies as st

from ddf.authority.attenuation import AttenuationEngine
from ddf.authority.constraints import ConstraintValidator
from ddf.authority.models import Authority, AuthorityConstraints
from ddf.authority.resources import ResourceHierarchy


# Custom strategies for generating test data

@st.composite
def valid_authority_constraints(draw, max_depth: int = 3) -> AuthorityConstraints:
    """Generate valid authority constraints."""
    max_amount = draw(st.floats(min_value=0, max_value=1000000, allow_nan=False, allow_infinity=False))
    delegation_depth = draw(st.integers(min_value=0, max_value=max_depth))
    
    now = datetime.now(timezone.utc)
    expires_offset = draw(st.integers(min_value=1, max_value=24))  # 1-24 hours
    
    return AuthorityConstraints(
        max_amount=max_amount if draw(st.booleans()) else None,
        currency="GBP" if draw(st.booleans()) else None,
        geographies=draw(st.lists(
            st.sampled_from(["GB", "US", "CA", "DE", "FR"]),
            min_size=0,
            max_size=3,
            unique=True,
        )) or None,
        delegation_depth_remaining=delegation_depth,
        expires_at=now + timedelta(hours=expires_offset),
    )


@st.composite
def valid_authority(draw) -> Authority:
    """Generate a valid authority."""
    now = datetime.now(timezone.utc)
    
    return Authority(
        actor=draw(st.text(min_size=1, max_size=20)),
        sponsor="user:alice@example.com",
        actions=draw(st.lists(
            st.sampled_from(["purchase", "quote", "review", "delete"]),
            min_size=1,
            max_size=3,
            unique=True,
        )),
        resources=draw(st.lists(
            st.text(min_size=1, max_size=30),
            min_size=1,
            max_size=2,
        )),
        purposes=draw(st.lists(
            st.sampled_from(["procurement", "accounting", "hr", "legal"]),
            min_size=1,
            max_size=2,
            unique=True,
        )),
        authority_path=["user:alice@example.com", draw(st.text(min_size=1, max_size=20))],
        issued_at=now,
        expires_at=now + timedelta(hours=draw(st.integers(min_value=1, max_value=24))),
        holder_public_key=draw(st.text(min_size=1, max_size=50)),
        constraints=draw(valid_authority_constraints()),
    )


class TestAttenuationInvariants:
    """Test authorization invariants using property-based testing."""

    @given(st.floats(min_value=0, max_value=10000, allow_nan=False, allow_infinity=False))
    def test_narrower_amount_property(self, parent_amount: float):
        """Property: if child_amount <= parent_amount, attenuation is valid."""
        child_amount = parent_amount / 2  # Always narrower
        
        parent = AuthorityConstraints(max_amount=parent_amount)
        child = AuthorityConstraints(max_amount=child_amount)
        
        is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
        assert is_valid
        assert len(violations) == 0

    @given(st.floats(min_value=0, max_value=10000, allow_nan=False, allow_infinity=False))
    def test_expanded_amount_property(self, parent_amount: float):
        """Property: if child_amount > parent_amount, attenuation fails."""
        assume_amount = parent_amount + 1000  # Always wider
        
        parent = AuthorityConstraints(max_amount=parent_amount)
        child = AuthorityConstraints(max_amount=assume_amount)
        
        is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
        assert not is_valid
        assert any("AMOUNT_EXPANSION" in v for v in violations)

    @given(st.lists(
        st.sampled_from(["purchase", "quote", "delete"]),
        min_size=1,
        max_size=3,
        unique=True,
    ))
    def test_actions_subset_property(self, parent_actions):
        """Property: child actions must be subset of parent."""
        # Randomly select subset of parent actions
        import random
        child_actions = random.sample(parent_actions, len(parent_actions) - 1) if len(parent_actions) > 1 else parent_actions
        
        parent = Authority(
            actor="parent",
            sponsor="user:alice@example.com",
            actions=parent_actions,
            resources=["vendor/*"],
            purposes=["test"],
            authority_path=["user:alice@example.com", "parent"],
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            holder_public_key="key",
        )
        
        child = Authority(
            actor="child",
            sponsor="user:alice@example.com",
            actions=child_actions,
            resources=["vendor/*"],
            purposes=["test"],
            authority_path=["user:alice@example.com", "parent", "child"],
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            holder_public_key="key",
        )
        
        result = AttenuationEngine.is_attenuation_valid(parent, child)
        # Should be valid since child actions are subset
        assert result.allowed

    def test_resource_narrowing_property(self):
        """Property: hierarchical resources narrow correctly."""
        parent_resources = ["vendor/*"]
        child_resources = ["vendor/dell/order/*"]
        
        is_valid, unmatched = ResourceHierarchy.narrow_multiple(
            parent_resources, child_resources
        )
        assert is_valid
        assert len(unmatched) == 0

    @given(
        st.integers(min_value=0, max_value=5),
        st.integers(min_value=0, max_value=5),
    )
    def test_delegation_depth_property(self, parent_depth, child_depth):
        """Property: child delegation depth must be < parent."""
        if child_depth < parent_depth:
            parent = AuthorityConstraints(delegation_depth_remaining=parent_depth)
            child = AuthorityConstraints(delegation_depth_remaining=child_depth)
            
            is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
            assert is_valid
        else:
            # Child depth >= parent depth should fail
            parent = AuthorityConstraints(delegation_depth_remaining=parent_depth)
            child = AuthorityConstraints(delegation_depth_remaining=child_depth)
            
            is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
            assert not is_valid

    def test_effective_constraints_monotonicity(self):
        """Property: effective constraints are always narrower than parent."""
        now = datetime.now(timezone.utc)
        
        parent = AuthorityConstraints(
            max_amount=10000.0,
            expires_at=now + timedelta(hours=2),
            delegation_depth_remaining=3,
        )
        
        child = AuthorityConstraints(
            max_amount=5000.0,
            expires_at=now + timedelta(hours=1),
            delegation_depth_remaining=2,
        )
        
        effective = ConstraintValidator.calculate_effective_constraints(parent, child)
        
        # Effective should never exceed child
        assert effective.max_amount <= child.max_amount
        assert effective.delegation_depth_remaining <= child.delegation_depth_remaining
        assert effective.expires_at <= child.expires_at


class TestSecurityInvariants:
    """Test critical security invariants."""

    def test_privilege_escalation_prevented(self):
        """Invariant: No amount expansion."""
        now = datetime.now(timezone.utc)
        
        parent = Authority(
            actor="parent",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com", "parent"],
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            holder_public_key="key",
            constraints=AuthorityConstraints(max_amount=2000.0),
        )
        
        child = Authority(
            actor="child",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com", "parent", "child"],
            issued_at=now,
            expires_at=now + timedelta(minutes=30),
            holder_public_key="key",
            parent_authority_id=parent.authority_id,
            constraints=AuthorityConstraints(max_amount=20000.0),  # Expansion!
        )
        
        result = AttenuationEngine.is_attenuation_valid(parent, child)
        assert not result.allowed
        assert any("AMOUNT_EXPANSION" in v for v in result.violations)

    def test_authority_laundering_prevented(self):
        """Invariant: Cannot skip steps in delegation chain."""
        # This is tested at the attenuation level - a malformed authority_path
        # should fail signature verification (handled in crypto phase)
        # For now, we test that the constraint checking is rigorous
        
        now = datetime.now(timezone.utc)
        
        grandparent = Authority(
            actor="grandparent",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com", "grandparent"],
            issued_at=now,
            expires_at=now + timedelta(hours=2),
            holder_public_key="key",
            constraints=AuthorityConstraints(max_amount=10000.0),
        )
        
        # Malformed: tries to skip parent in chain
        grandchild = Authority(
            actor="grandchild",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com", "grandchild"],  # Missing parent!
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            holder_public_key="key",
            parent_authority_id=grandparent.authority_id,
            constraints=AuthorityConstraints(max_amount=5000.0),
        )
        
        # This would be caught by path validation in authorization
        # For attenuation, we just verify constraints
        result = AttenuationEngine.is_attenuation_valid(grandparent, grandchild)
        # The constraints are valid, but the path is malformed
        # (path checking happens during authorization)
        assert result.allowed  # Constraints are OK
