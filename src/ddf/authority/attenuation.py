"""Authority attenuation engine for DDF.

The attenuation engine validates that child authorities are properly narrowed
relative to their parents, enforcing the core security invariant:

    Authority(child) ⊆ Authority(parent)

This module is the heart of DDF's security model.
"""

from dataclasses import dataclass
from typing import Optional

from ddf.authority.constraints import ConstraintValidator
from ddf.authority.models import Authority, AuthorityConstraints
from ddf.authority.resources import ResourceHierarchy


@dataclass
class AttenuationResult:
    """Result of attenuation validation."""

    allowed: bool
    """Whether attenuation is valid (child properly narrows parent)."""

    violations: list[str]
    """Specific violations if attenuation failed."""

    effective_constraints: Optional[AuthorityConstraints]
    """Effective constraints after attenuation (if allowed)."""


class AttenuationEngine:
    """Validates and enforces authority attenuation."""

    @staticmethod
    def is_attenuation_valid(
        parent: Authority, child: Authority
    ) -> AttenuationResult:
        """
        Validate that child authority properly attenuates parent.

        This is the primary security check in DDF.

        Args:
            parent: Parent (delegating) authority
            child: Child (delegated) authority

        Returns:
            AttenuationResult with validation details

        The validation checks:
            1. Actions: child.actions ⊆ parent.actions
            2. Resources: child.resources ⊆ parent.resources
            3. Purposes: child.purposes ⊆ parent.purposes
            4. Max amount: child.max_amount ≤ parent.max_amount
            5. Geographies: child.geographies ⊆ parent.geographies
            6. Audiences: child.audiences ⊆ parent.audiences
            7. Expiration: child.expires_at ≤ parent.expires_at
            8. Valid from: child.valid_from ≥ parent.valid_from
            9. Delegation depth: child.delegation_depth_remaining < parent.delegation_depth_remaining
        """
        violations: list[str] = []

        # Check actions (child must be subset)
        if not set(child.actions).issubset(set(parent.actions)):
            extra_actions = set(child.actions) - set(parent.actions)
            violations.append(
                f"AUTHORITY_ACTION_EXPANSION: extra={list(extra_actions)}"
            )

        # Check resources (child must be narrower or equal)
        resources_valid, unmatched_resources = ResourceHierarchy.narrow_multiple(
            parent.resources, child.resources
        )
        if not resources_valid:
            violations.append(
                f"AUTHORITY_RESOURCE_EXPANSION: unmatched={unmatched_resources}"
            )

        # Check purposes (child must be subset)
        if not set(child.purposes).issubset(set(parent.purposes)):
            extra_purposes = set(child.purposes) - set(parent.purposes)
            violations.append(
                f"AUTHORITY_PURPOSE_EXPANSION: extra={list(extra_purposes)}"
            )

        # Check constraints
        constraints_valid, constraint_violations = ConstraintValidator.is_narrower_or_equal(
            child.constraints, parent.constraints
        )
        if not constraints_valid:
            violations.extend(constraint_violations)

        # If we have violations, return DENY
        if violations:
            return AttenuationResult(
                allowed=False,
                violations=violations,
                effective_constraints=None,
            )

        # Calculate effective constraints
        effective_constraints = ConstraintValidator.calculate_effective_constraints(
            parent.constraints, child.constraints
        )

        return AttenuationResult(
            allowed=True,
            violations=[],
            effective_constraints=effective_constraints,
        )

    @staticmethod
    def attenuation_chain_valid(authorities: list[Authority]) -> AttenuationResult:
        """
        Validate attenuation across a full chain of authorities.

        Args:
            authorities: List of authorities from root to current (in order)

        Returns:
            AttenuationResult for the full chain

        This checks that each authority in the chain properly attenuates its parent.
        """
        if not authorities:
            return AttenuationResult(
                allowed=False,
                violations=["EMPTY_AUTHORITY_CHAIN"],
                effective_constraints=None,
            )

        if len(authorities) == 1:
            # Root authority, no parent to check
            return AttenuationResult(
                allowed=True,
                violations=[],
                effective_constraints=authorities[0].constraints,
            )

        # Check each delegation step
        current_effective = authorities[0].constraints

        for i in range(1, len(authorities)):
            parent = authorities[i - 1]
            child = authorities[i]

            result = AttenuationEngine.is_attenuation_valid(parent, child)

            if not result.allowed:
                # Augment violations with chain position
                violations = [
                    f"[delegation {i - 1} → {i}] {v}" for v in result.violations
                ]
                return AttenuationResult(
                    allowed=False,
                    violations=violations,
                    effective_constraints=None,
                )

            # Update effective constraints
            if result.effective_constraints:
                current_effective = result.effective_constraints

        return AttenuationResult(
            allowed=True,
            violations=[],
            effective_constraints=current_effective,
        )
