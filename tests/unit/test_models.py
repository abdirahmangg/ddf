"""Tests for authority models."""

import pytest
from datetime import datetime, timezone, timedelta

from ddf.authority.models import (
    Authority,
    AuthorityConstraints,
    AuthorityProof,
    AuthorizationRequest,
    AuthorizationDecision,
)


def test_authority_constraints_valid():
    """Test creating valid authority constraints."""
    constraints = AuthorityConstraints(
        max_amount=5000.0,
        currency="GBP",
        geographies=["GB"],
        delegation_depth_remaining=2,
    )
    assert constraints.max_amount == 5000.0
    assert constraints.currency == "GBP"
    assert constraints.geographies == ["GB"]
    assert constraints.delegation_depth_remaining == 2


def test_authority_proof_valid():
    """Test creating valid authority proof."""
    proof = AuthorityProof(
        algorithm="Ed25519",
        key_id="ddf:key:test",
        signature="base64_signature_here",
    )
    assert proof.algorithm == "Ed25519"
    assert proof.key_id == "ddf:key:test"


def test_authority_valid():
    """Test creating valid authority."""
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=1)

    authority = Authority(
        actor="agent:test",
        sponsor="user:alice@example.com",
        actions=["purchase"],
        resources=["vendor/*"],
        purposes=["procurement"],
        authority_path=["user:alice@example.com", "agent:test"],
        issued_at=now,
        expires_at=expires,
        holder_public_key="test_public_key",
    )

    assert authority.actor == "agent:test"
    assert authority.sponsor == "user:alice@example.com"
    assert authority.version == "ddf/0.1"
    assert authority.authority_id.startswith("ddf:authority:")


def test_authority_expires_after_issued():
    """Test that expires_at must be after issued_at."""
    now = datetime.now(timezone.utc)

    with pytest.raises(ValueError, match="expires_at must be after issued_at"):
        Authority(
            actor="agent:test",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com"],
            issued_at=now,
            expires_at=now - timedelta(hours=1),  # Before issued_at!
            holder_public_key="test_public_key",
        )


def test_authority_empty_path_invalid():
    """Test that authority path cannot be empty."""
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=1)

    with pytest.raises(ValueError, match="authority_path cannot be empty"):
        Authority(
            actor="agent:test",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=[],  # Empty!
            issued_at=now,
            expires_at=expires,
            holder_public_key="test_public_key",
        )


def test_authorization_request_valid():
    """Test creating valid authorization request."""
    request = AuthorizationRequest(
        actor="agent:test",
        action="purchase",
        resource="vendor/dell/order/123",
        purpose="procurement",
        authority_id="ddf:authority:test",
        context={"amount": 1000, "currency": "GBP"},
    )

    assert request.actor == "agent:test"
    assert request.action == "purchase"
    assert request.context["amount"] == 1000


def test_authorization_decision_valid():
    """Test creating valid authorization decision."""
    now = datetime.now(timezone.utc)

    decision = AuthorizationDecision(
        decision="ALLOW",
        actor="agent:test",
        action="purchase",
        resource="vendor/dell/order/123",
        purpose="procurement",
        sponsor="user:alice@example.com",
        authority_path=["user:alice@example.com", "agent:test"],
        effective_constraints=AuthorityConstraints(max_amount=5000.0),
        valid_until=now + timedelta(hours=1),
        reasons=["signature_valid", "authority_chain_valid"],
    )

    assert decision.decision == "ALLOW"
    assert decision.decision_id.startswith("ddf:decision:")
    assert len(decision.reasons) == 2


def test_authorization_decision_deny():
    """Test creating DENY decision."""
    now = datetime.now(timezone.utc)

    decision = AuthorizationDecision(
        decision="DENY",
        actor="agent:test",
        action="purchase",
        resource="vendor/dell/order/123",
        purpose="procurement",
        sponsor="user:alice@example.com",
        authority_path=["user:alice@example.com", "agent:test"],
        effective_constraints=AuthorityConstraints(),
        valid_until=now,
        reasons=["amount_exceeds_limit"],
    )

    assert decision.decision == "DENY"
    assert "amount_exceeds_limit" in decision.reasons
