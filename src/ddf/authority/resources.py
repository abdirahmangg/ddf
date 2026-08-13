"""Resource hierarchy and narrowing logic for DDF.

Resources in DDF use hierarchical identifiers:
  - vendor/*
  - vendor/dell/*
  - vendor/dell/order/*
  - vendor/dell/order/9281

A resource is "narrower" if it matches fewer resources.
"""

from typing import Optional


class ResourceHierarchy:
    """Validates and compares resource permissions."""

    @staticmethod
    def is_narrower_or_equal(child: str, parent: str) -> bool:
        """
        Check if child resource is narrower than or equal to parent.

        Args:
            child: Child resource identifier
            parent: Parent resource identifier

        Returns:
            True if child ⊆ parent

        Examples:
            vendor/dell/order/9281 is narrower than vendor/dell/order/*
            vendor/dell/* is narrower than vendor/*
            vendor/* is narrower than or equal to vendor/*
        """
        # Same resource
        if child == parent:
            return True

        # Child must be at least as long as parent
        if len(child) < len(parent):
            return False

        # If parent ends with *, child must start with parent prefix
        if parent.endswith("/*"):
            parent_prefix = parent[:-2]  # Remove the /*
            return child.startswith(parent_prefix + "/") or child == parent_prefix

        # Parent doesn't end with *, so child must match exactly
        return child == parent

    @staticmethod
    def narrow_multiple(
        parent_resources: list[str], child_resources: list[str]
    ) -> tuple[bool, list[str]]:
        """
        Check if child resource list is narrower than parent.

        Every child resource must be narrower than or equal to at least one parent resource.

        Args:
            parent_resources: List of permitted parent resources
            child_resources: List of requested child resources

        Returns:
            Tuple of (is_narrower, unmatched_child_resources)
            - is_narrower: True if valid narrowing
            - unmatched_child_resources: Child resources that don't match any parent

        Examples:
            parent: ["vendor/*"]
            child: ["vendor/dell/order/*"]
            Result: (True, [])

            parent: ["vendor/dell/order/*"]
            child: ["vendor/dell/order/9281", "vendor/dell/order/9282"]
            Result: (True, [])

            parent: ["vendor/dell/*"]
            child: ["vendor/dell/order/*", "vendor/ibm/*"]
            Result: (False, ["vendor/ibm/*"])
        """
        unmatched = []

        for child_resource in child_resources:
            matched = any(
                ResourceHierarchy.is_narrower_or_equal(child_resource, parent)
                for parent in parent_resources
            )
            if not matched:
                unmatched.append(child_resource)

        return len(unmatched) == 0, unmatched

    @staticmethod
    def calculate_intersection(
        parent_resources: list[str], child_resources: list[str]
    ) -> list[str]:
        """
        Calculate effective resources (intersection of parent and child).

        The effective resources are the narrowest set that satisfies both.

        Args:
            parent_resources: Parent resource list
            child_resources: Child resource list

        Returns:
            Effective resource list (child if narrower, parent otherwise)
        """
        # For v0.1, effective resources = child resources (must be narrower)
        # A more sophisticated implementation would compute true intersection
        return child_resources
