# ruff: noqa: RUF059
"""Tests for constraint validation and narrowing."""

from datetime import UTC, datetime, timedelta

from ddf.authority.constraints import ConstraintValidator
from ddf.authority.models import AuthorityConstraints


class TestConstraintNarrowing:
    """Test constraint narrowing validation."""

    def test_max_amount_narrowing(self):
        """Test that child max_amount must be ≤ parent."""
        parent = AuthorityConstraints(max_amount=10000.0)
        child = AuthorityConstraints(max_amount=5000.0)

        is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
        assert is_valid
        assert len(violations) == 0

    def test_max_amount_expansion_denied(self):
        """Test that child max_amount cannot exceed parent."""
        parent = AuthorityConstraints(max_amount=5000.0)
        child = AuthorityConstraints(max_amount=10000.0)

        is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
        assert not is_valid
        assert any("AMOUNT_EXPANSION" in v for v in violations)

    def test_currency_consistency(self):
        """Test that currencies must match if both specified."""
        parent = AuthorityConstraints(currency="GBP")
        child = AuthorityConstraints(currency="USD")

        is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
        assert not is_valid
        assert any("CURRENCY_MISMATCH" in v for v in violations)

    def test_geography_narrowing(self):
        """Test that child geographies must be subset of parent."""
        parent = AuthorityConstraints(geographies=["GB", "US", "CA"])
        child = AuthorityConstraints(geographies=["GB"])

        is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
        assert is_valid

    def test_geography_expansion_denied(self):
        """Test that child cannot add geographies."""
        parent = AuthorityConstraints(geographies=["GB"])
        child = AuthorityConstraints(geographies=["GB", "US"])

        is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
        assert not is_valid
        assert any("GEOGRAPHY_EXPANSION" in v for v in violations)

    def test_audience_narrowing(self):
        """Test that child audiences must be subset of parent."""
        parent = AuthorityConstraints(audiences=["vendor-api", "internal-api"])
        child = AuthorityConstraints(audiences=["vendor-api"])

        is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
        assert is_valid

    def test_audience_expansion_denied(self):
        """Test that child cannot add audiences."""
        parent = AuthorityConstraints(audiences=["vendor-api"])
        child = AuthorityConstraints(audiences=["vendor-api", "internal-api"])

        is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
        assert not is_valid
        assert any("AUDIENCE_EXPANSION" in v for v in violations)

    def test_expiration_narrowing(self):
        """Test that child must expire before or at parent."""
        now = datetime.now(UTC)
        parent_expires = now + timedelta(hours=2)
        child_expires = now + timedelta(hours=1)

        parent = AuthorityConstraints(expires_at=parent_expires)
        child = AuthorityConstraints(expires_at=child_expires)

        is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
        assert is_valid

    def test_expiration_expansion_denied(self):
        """Test that child cannot extend expiration past parent."""
        now = datetime.now(UTC)
        parent_expires = now + timedelta(hours=1)
        child_expires = now + timedelta(hours=2)

        parent = AuthorityConstraints(expires_at=parent_expires)
        child = AuthorityConstraints(expires_at=child_expires)

        is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
        assert not is_valid
        assert any("EXPIRY_EXPANSION" in v for v in violations)

    def test_delegation_depth_narrowing(self):
        """Test that child delegation depth decreases."""
        parent = AuthorityConstraints(delegation_depth_remaining=3)
        child = AuthorityConstraints(delegation_depth_remaining=2)

        is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
        assert is_valid

    def test_delegation_depth_expansion_denied(self):
        """Test that child cannot increase delegation depth."""
        parent = AuthorityConstraints(delegation_depth_remaining=2)
        child = AuthorityConstraints(delegation_depth_remaining=3)

        is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
        assert not is_valid
        assert any("DELEGATION_DEPTH_EXPANSION" in v for v in violations)

    def test_delegation_depth_zero_allowed(self):
        """Test that child can reach delegation_depth = 0 (terminal)."""
        parent = AuthorityConstraints(delegation_depth_remaining=2)
        child = AuthorityConstraints(delegation_depth_remaining=0)

        is_valid, violations = ConstraintValidator.is_narrower_or_equal(child, parent)
        assert is_valid


class TestConstraintExpiration:
    """Test constraint expiration checks."""

    def test_is_expired_true(self):
        """Test that expired constraints return true."""
        now = datetime.now(UTC)
        past = now - timedelta(hours=1)
        constraints = AuthorityConstraints(expires_at=past)

        assert ConstraintValidator.is_expired(constraints, now)

    def test_is_expired_false(self):
        """Test that non-expired constraints return false."""
        now = datetime.now(UTC)
        future = now + timedelta(hours=1)
        constraints = AuthorityConstraints(expires_at=future)

        assert not ConstraintValidator.is_expired(constraints, now)

    def test_is_expired_none(self):
        """Test that None expiration is treated as non-expired."""
        constraints = AuthorityConstraints(expires_at=None)
        assert not ConstraintValidator.is_expired(constraints)

    def test_is_valid_now_in_range(self):
        """Test that authority valid within time range."""
        now = datetime.now(UTC)
        valid_from = now - timedelta(hours=1)
        expires_at = now + timedelta(hours=1)

        constraints = AuthorityConstraints(valid_from=valid_from, expires_at=expires_at)
        assert ConstraintValidator.is_valid_now(constraints, now)

    def test_is_valid_now_before_start(self):
        """Test that authority invalid before valid_from."""
        now = datetime.now(UTC)
        valid_from = now + timedelta(hours=1)
        expires_at = now + timedelta(hours=2)

        constraints = AuthorityConstraints(valid_from=valid_from, expires_at=expires_at)
        assert not ConstraintValidator.is_valid_now(constraints, now)

    def test_is_valid_now_after_expiry(self):
        """Test that authority invalid after expiry."""
        now = datetime.now(UTC)
        valid_from = now - timedelta(hours=2)
        expires_at = now - timedelta(hours=1)

        constraints = AuthorityConstraints(valid_from=valid_from, expires_at=expires_at)
        assert not ConstraintValidator.is_valid_now(constraints, now)


class TestEffectiveConstraints:
    """Test calculation of effective constraints."""

    def test_effective_max_amount_minimum(self):
        """Test that effective max_amount is the minimum."""
        parent = AuthorityConstraints(max_amount=10000.0)
        child = AuthorityConstraints(max_amount=5000.0)

        effective = ConstraintValidator.calculate_effective_constraints(parent, child)
        assert effective.max_amount == 5000.0

    def test_effective_geographies_intersection(self):
        """Test that effective geographies is the intersection."""
        parent = AuthorityConstraints(geographies=["GB", "US", "CA"])
        child = AuthorityConstraints(geographies=["GB", "US"])

        effective = ConstraintValidator.calculate_effective_constraints(parent, child)
        assert set(effective.geographies) == {"GB", "US"}

    def test_effective_expiration_earliest(self):
        """Test that effective expiration is earliest."""
        now = datetime.now(UTC)
        parent_expires = now + timedelta(hours=2)
        child_expires = now + timedelta(hours=1)

        parent = AuthorityConstraints(expires_at=parent_expires)
        child = AuthorityConstraints(expires_at=child_expires)

        effective = ConstraintValidator.calculate_effective_constraints(parent, child)
        assert effective.expires_at == child_expires

    def test_effective_constraints_full_chain(self):
        """Test calculating effective constraints across full chain."""
        now = datetime.now(UTC)

        root = AuthorityConstraints(
            max_amount=10000.0,
            currency="GBP",
            geographies=["GB", "US", "CA"],
            expires_at=now + timedelta(hours=3),
            delegation_depth_remaining=3,
        )

        level1 = AuthorityConstraints(
            max_amount=5000.0,
            geographies=["GB", "US"],
            expires_at=now + timedelta(hours=2),
            delegation_depth_remaining=2,
        )

        level2 = AuthorityConstraints(
            max_amount=2000.0,
            geographies=["GB"],
            expires_at=now + timedelta(hours=1),
            delegation_depth_remaining=1,
        )

        # Calculate step-by-step
        effective_1 = ConstraintValidator.calculate_effective_constraints(root, level1)
        assert effective_1.max_amount == 5000.0
        assert set(effective_1.geographies) == {"GB", "US"}

        effective_2 = ConstraintValidator.calculate_effective_constraints(effective_1, level2)
        assert effective_2.max_amount == 2000.0
        assert effective_2.geographies == ["GB"]
        assert effective_2.delegation_depth_remaining == 1
