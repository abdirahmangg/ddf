"""Constraint validation for DDF authorities.

Constraints limit the scope of what an authority permits.
A child authority cannot expand constraints beyond its parent.
"""

from datetime import datetime, timezone
from typing import Any, Optional

from ddf.authority.models import AuthorityConstraints


class ConstraintValidator:
    """Validates that child constraints are narrower than parent."""

    @staticmethod
    def is_narrower_or_equal(
        child: AuthorityConstraints, parent: AuthorityConstraints
    ) -> tuple[bool, list[str]]:
        """
        Check if child constraints are narrower than or equal to parent.

        Args:
            child: Child authority constraints
            parent: Parent authority constraints

        Returns:
            Tuple of (is_valid, violations)
            - is_valid: True if child properly narrows parent
            - violations: List of specific violations

        The invariant is: child must be narrower or equal to parent.
        Examples of violations:
            - child.max_amount > parent.max_amount
            - child.delegation_depth_remaining > parent.delegation_depth_remaining
            - child.expires_at > parent.expires_at
        """
        violations: list[str] = []

        # Check max_amount
        if (
            parent.max_amount is not None
            and child.max_amount is not None
            and child.max_amount > parent.max_amount
        ):
            violations.append(
                f"AUTHORITY_AMOUNT_EXPANSION: child={child.max_amount}, "
                f"parent={parent.max_amount}"
            )

        # Check currency (must match if both specified)
        if (
            parent.currency is not None
            and child.currency is not None
            and child.currency != parent.currency
        ):
            violations.append(
                f"AUTHORITY_CURRENCY_MISMATCH: child={child.currency}, "
                f"parent={parent.currency}"
            )

        # Check geographies (child must be subset)
        if parent.geographies is not None and child.geographies is not None:
            child_set = set(child.geographies)
            parent_set = set(parent.geographies)
            if not child_set.issubset(parent_set):
                extra = child_set - parent_set
                violations.append(
                    f"AUTHORITY_GEOGRAPHY_EXPANSION: extra={list(extra)}"
                )

        # Check audiences (child must be subset)
        if parent.audiences is not None and child.audiences is not None:
            child_set = set(child.audiences)
            parent_set = set(parent.audiences)
            if not child_set.issubset(parent_set):
                extra = child_set - parent_set
                violations.append(
                    f"AUTHORITY_AUDIENCE_EXPANSION: extra={list(extra)}"
                )

        # Check valid_from (child must be after or equal to parent)
        if (
            parent.valid_from is not None
            and child.valid_from is not None
            and child.valid_from < parent.valid_from
        ):
            violations.append(
                f"AUTHORITY_VALID_FROM_EXPANSION: "
                f"child={child.valid_from}, parent={parent.valid_from}"
            )

        # Check expires_at (child must expire before or at parent expiry)
        if (
            parent.expires_at is not None
            and child.expires_at is not None
            and child.expires_at > parent.expires_at
        ):
            violations.append(
                f"AUTHORITY_EXPIRY_EXPANSION: "
                f"child={child.expires_at}, parent={parent.expires_at}"
            )

        # Check delegation_depth_remaining
        if (
            parent.delegation_depth_remaining is not None
            and child.delegation_depth_remaining is not None
        ):
            # Child depth must be strictly less (cannot delegate further than parent)
            if child.delegation_depth_remaining >= parent.delegation_depth_remaining:
                violations.append(
                    f"AUTHORITY_DELEGATION_DEPTH_EXPANSION: "
                    f"child={child.delegation_depth_remaining}, "
                    f"parent={parent.delegation_depth_remaining}"
                )

        return len(violations) == 0, violations

    @staticmethod
    def is_expired(constraints: AuthorityConstraints, now: Optional[datetime] = None) -> bool:
        """
        Check if constraints have expired.

        Args:
            constraints: Authority constraints
            now: Current time (defaults to now UTC)

        Returns:
            True if expired
        """
        if constraints.expires_at is None:
            return False

        if now is None:
            now = datetime.now(timezone.utc)

        return now > constraints.expires_at

    @staticmethod
    def is_valid_now(constraints: AuthorityConstraints, now: Optional[datetime] = None) -> bool:
        """
        Check if constraints are valid at the given time.

        Args:
            constraints: Authority constraints
            now: Current time (defaults to now UTC)

        Returns:
            True if valid (between valid_from and expires_at)
        """
        if now is None:
            now = datetime.now(timezone.utc)

        # Check valid_from
        if constraints.valid_from is not None and now < constraints.valid_from:
            return False

        # Check expires_at
        if constraints.expires_at is not None and now > constraints.expires_at:
            return False

        return True

    @staticmethod
    def calculate_effective_constraints(
        parent: AuthorityConstraints, child: AuthorityConstraints
    ) -> AuthorityConstraints:
        """
        Calculate the effective constraints (intersection).

        The effective constraints are the most restrictive of parent and child.

        Args:
            parent: Parent authority constraints
            child: Child authority constraints

        Returns:
            Effective constraints
        """
        effective = AuthorityConstraints()

        # For max_amount, take minimum
        if parent.max_amount is not None and child.max_amount is not None:
            effective.max_amount = min(parent.max_amount, child.max_amount)
        elif parent.max_amount is not None:
            effective.max_amount = parent.max_amount
        elif child.max_amount is not None:
            effective.max_amount = child.max_amount

        # For currency, prefer child if set, else parent
        effective.currency = child.currency or parent.currency

        # For geographies, take intersection
        if parent.geographies is not None and child.geographies is not None:
            effective.geographies = list(set(parent.geographies) & set(child.geographies))
        elif parent.geographies is not None:
            effective.geographies = parent.geographies
        elif child.geographies is not None:
            effective.geographies = child.geographies

        # For audiences, take intersection
        if parent.audiences is not None and child.audiences is not None:
            effective.audiences = list(set(parent.audiences) & set(child.audiences))
        elif parent.audiences is not None:
            effective.audiences = parent.audiences
        elif child.audiences is not None:
            effective.audiences = child.audiences

        # For valid_from, take maximum (most restrictive start time)
        if parent.valid_from is not None and child.valid_from is not None:
            effective.valid_from = max(parent.valid_from, child.valid_from)
        elif parent.valid_from is not None:
            effective.valid_from = parent.valid_from
        elif child.valid_from is not None:
            effective.valid_from = child.valid_from

        # For expires_at, take minimum (earliest expiry)
        if parent.expires_at is not None and child.expires_at is not None:
            effective.expires_at = min(parent.expires_at, child.expires_at)
        elif parent.expires_at is not None:
            effective.expires_at = parent.expires_at
        elif child.expires_at is not None:
            effective.expires_at = child.expires_at

        # For delegation_depth_remaining, take minimum (most restrictive)
        if (
            parent.delegation_depth_remaining is not None
            and child.delegation_depth_remaining is not None
        ):
            effective.delegation_depth_remaining = min(
                parent.delegation_depth_remaining, child.delegation_depth_remaining
            )
        elif parent.delegation_depth_remaining is not None:
            effective.delegation_depth_remaining = parent.delegation_depth_remaining
        elif child.delegation_depth_remaining is not None:
            effective.delegation_depth_remaining = child.delegation_depth_remaining

        return effective
