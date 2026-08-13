"""Tests for resource hierarchy and narrowing."""

import pytest

from ddf.authority.resources import ResourceHierarchy


class TestResourceNarrowing:
    """Test resource narrowing logic."""

    def test_identical_resources(self):
        """Test that identical resources are considered equal narrowing."""
        assert ResourceHierarchy.is_narrower_or_equal("vendor/*", "vendor/*")

    def test_specific_narrower_than_wildcard(self):
        """Test that specific resources are narrower than wildcards."""
        assert ResourceHierarchy.is_narrower_or_equal(
            "vendor/dell/order/123", "vendor/dell/order/*"
        )

    def test_nested_wildcards(self):
        """Test narrowing with nested wildcards."""
        assert ResourceHierarchy.is_narrower_or_equal("vendor/dell/*", "vendor/*")

    def test_deeply_nested_narrowing(self):
        """Test deeply nested resource hierarchy."""
        assert ResourceHierarchy.is_narrower_or_equal(
            "vendor/dell/order/9281", "vendor/dell/order/*"
        )
        assert ResourceHierarchy.is_narrower_or_equal(
            "vendor/dell/order/*", "vendor/dell/*"
        )
        assert ResourceHierarchy.is_narrower_or_equal("vendor/dell/*", "vendor/*")

    def test_wider_resource_not_narrower(self):
        """Test that wider resources are not considered narrower."""
        assert not ResourceHierarchy.is_narrower_or_equal("vendor/*", "vendor/dell/*")
        assert not ResourceHierarchy.is_narrower_or_equal("vendor/*", "vendor/dell/order/123")

    def test_sibling_resources_not_narrower(self):
        """Test that sibling resources are not narrower."""
        assert not ResourceHierarchy.is_narrower_or_equal(
            "vendor/dell/*", "vendor/ibm/*"
        )

    def test_multiple_resource_narrowing(self):
        """Test narrowing with multiple resources."""
        parent_resources = ["vendor/*"]
        child_resources = ["vendor/dell/order/*", "vendor/dell/quote/*"]

        is_valid, unmatched = ResourceHierarchy.narrow_multiple(
            parent_resources, child_resources
        )
        assert is_valid
        assert len(unmatched) == 0

    def test_multiple_resource_expansion(self):
        """Test that expanding resources is caught."""
        parent_resources = ["vendor/dell/*"]
        child_resources = ["vendor/dell/order/*", "vendor/ibm/*"]

        is_valid, unmatched = ResourceHierarchy.narrow_multiple(
            parent_resources, child_resources
        )
        assert not is_valid
        assert "vendor/ibm/*" in unmatched

    def test_resource_intersection(self):
        """Test calculating intersection of resources."""
        parent_resources = ["vendor/*", "crm/*"]
        child_resources = ["vendor/dell/*"]

        effective = ResourceHierarchy.calculate_intersection(
            parent_resources, child_resources
        )
        assert effective == ["vendor/dell/*"]


class TestResourceEdgeCases:
    """Test edge cases in resource handling."""

    def test_empty_path_segment(self):
        """Test handling of empty path segments."""
        # vendor// should not match vendor/*
        assert not ResourceHierarchy.is_narrower_or_equal("vendor/", "vendor/*")

    def test_trailing_slash(self):
        """Test handling of trailing slashes."""
        assert ResourceHierarchy.is_narrower_or_equal(
            "vendor/dell/", "vendor/*"
        )

    def test_case_sensitive(self):
        """Test that resource matching is case-sensitive."""
        assert not ResourceHierarchy.is_narrower_or_equal(
            "Vendor/Dell/*", "vendor/dell/*"
        )

    def test_exact_prefix_match(self):
        """Test exact prefix matching without wildcard."""
        assert ResourceHierarchy.is_narrower_or_equal(
            "vendor/dell", "vendor/dell"
        )
        # A specific resource IS narrower than a wildcard
        assert ResourceHierarchy.is_narrower_or_equal(
            "vendor/dell", "vendor/*"
        )
        # vendor/dell/* should also match vendor/*
        assert ResourceHierarchy.is_narrower_or_equal(
            "vendor/dell/*", "vendor/*"
        )
