"""Core authority domain models for DDF."""

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class AuthorityConstraints(BaseModel):
    """Constraints that limit the scope of an authority.

    Constraints define the outer boundaries of what an authority permits.
    A child authority cannot expand any constraint beyond its parent.
    """

    max_amount: Optional[float] = Field(
        default=None,
        description="Maximum monetary amount permitted (e.g., in base currency units)",
    )
    currency: Optional[str] = Field(
        default=None, description="ISO 4217 currency code (e.g., GBP, USD)"
    )
    geographies: Optional[list[str]] = Field(
        default=None,
        description="ISO 3166-1 alpha-2 country codes (e.g., ['GB', 'US'])",
    )
    audiences: Optional[list[str]] = Field(
        default=None,
        description="Intended recipients (e.g., ['vendor-api', 'internal-system'])",
    )
    valid_from: Optional[datetime] = Field(
        default=None, description="Earliest time this authority is valid"
    )
    expires_at: Optional[datetime] = Field(
        default=None, description="Latest time this authority is valid"
    )
    delegation_depth_remaining: Optional[int] = Field(
        default=None,
        description="Maximum number of further delegations permitted (0 = terminal)",
    )

    class Config:
        """Pydantic config."""

        json_schema_extra = {
            "example": {
                "max_amount": 5000.0,
                "currency": "GBP",
                "geographies": ["GB"],
                "audiences": ["vendor-api"],
                "expires_at": "2026-08-13T17:00:00Z",
                "delegation_depth_remaining": 2,
            }
        }


class AuthorityProof(BaseModel):
    """Cryptographic proof that this authority was validly signed."""

    algorithm: str = Field(
        default="Ed25519",
        description="Cryptographic algorithm used (only Ed25519 in v0.1)",
    )
    key_id: str = Field(
        description="Key ID of the signer for verification lookup"
    )
    signature: str = Field(
        description="Base64-encoded signature of canonical authority document"
    )

    class Config:
        """Pydantic config."""

        json_schema_extra = {
            "example": {
                "algorithm": "Ed25519",
                "key_id": "ddf:key:01ARZ3NHHzB...",
                "signature": "MEUCIQDz...",
            }
        }


class Authority(BaseModel):
    """
    A DDF Authority grants an actor permission to perform actions on resources.

    Conceptually answers:
    - Which actor (actor)
    - can perform which action (actions)
    - on which resource (resources)
    - for what purpose (purposes)
    - under whose sponsorship (sponsor)
    - through what authority path (authority_path)
    - with what effective constraints (constraints)
    - until when (expires_at)
    - proved by what cryptographic evidence (proof)

    This is the canonical representation used for signing.
    """

    version: str = Field(
        default="ddf/0.1",
        description="DDF protocol version",
    )

    authority_id: str = Field(
        default_factory=lambda: f"ddf:authority:{uuid4().hex[:12]}",
        description="Unique authority identifier",
    )

    actor: str = Field(
        description="The entity granted authority (e.g., 'agent:arkstride:buyer-42')"
    )

    sponsor: str = Field(
        description="Ultimate sponsor of this authority (e.g., 'user:alice@example.com')"
    )

    actions: list[str] = Field(
        description="Permitted actions (e.g., ['purchase', 'quote'])"
    )

    resources: list[str] = Field(
        description="Permitted resources (hierarchical, e.g., ['vendor/dell/*'])"
    )

    purposes: list[str] = Field(
        description="Permitted purposes (e.g., ['procurement'])"
    )

    constraints: AuthorityConstraints = Field(
        default_factory=AuthorityConstraints,
        description="Scope-limiting constraints",
    )

    authority_path: list[str] = Field(
        description="Chain of actors from sponsor to current actor"
    )

    issued_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this authority was issued (UTC)",
    )

    expires_at: datetime = Field(
        description="When this authority expires (UTC)"
    )

    parent_authority_id: Optional[str] = Field(
        default=None,
        description="ID of the immediate parent authority (None for root)",
    )

    audience: list[str] = Field(
        default_factory=list,
        description="Intended recipients/systems (e.g., ['vendor-api'])",
    )

    holder_public_key: str = Field(
        description="Base64-encoded public key of the authority holder (for proof-of-possession)"
    )

    proof: Optional[AuthorityProof] = Field(
        default=None,
        description="Cryptographic proof of validity",
    )

    @field_validator("expires_at")
    @classmethod
    def expires_after_issued(cls, v: datetime, data: Any) -> datetime:
        """Ensure expires_at is after issued_at."""
        if "issued_at" in data.data:
            if v <= data.data["issued_at"]:
                raise ValueError("expires_at must be after issued_at")
        return v

    @field_validator("authority_path")
    @classmethod
    def validate_authority_path(cls, v: list[str]) -> list[str]:
        """Ensure authority path is non-empty and well-formed."""
        if not v:
            raise ValueError("authority_path cannot be empty")
        return v

    @field_validator("actions", "resources", "purposes")
    @classmethod
    def validate_non_empty_lists(cls, v: list[str]) -> list[str]:
        """Ensure critical lists are non-empty."""
        if not v:
            raise ValueError("List cannot be empty")
        return v

    class Config:
        """Pydantic config."""

        json_schema_extra = {
            "example": {
                "version": "ddf/0.1",
                "authority_id": "ddf:authority:01ARZ3NHHzB",
                "actor": "agent:arkstride:buyer-42",
                "sponsor": "user:alice@example.com",
                "actions": ["purchase"],
                "resources": ["vendor/dell/order/*"],
                "purposes": ["engineering-laptop-procurement"],
                "constraints": {
                    "max_amount": 5000,
                    "currency": "GBP",
                    "geographies": ["GB"],
                },
                "authority_path": [
                    "user:alice@example.com",
                    "agent:arkstride:assistant",
                    "agent:arkstride:procurement",
                    "agent:arkstride:buyer-42",
                ],
                "issued_at": "2026-08-13T12:00:00Z",
                "expires_at": "2026-08-13T13:00:00Z",
                "parent_authority_id": "ddf:authority:parent",
                "holder_public_key": "...",
                "proof": {
                    "algorithm": "Ed25519",
                    "key_id": "ddf:key:01ARZ3NHHzB",
                    "signature": "...",
                },
            }
        }


class AuthorizationRequest(BaseModel):
    """Request to perform an authorization check."""

    actor: str = Field(
        description="Actor attempting the action (e.g., 'agent:arkstride:buyer')"
    )
    action: str = Field(
        description="Action being requested (e.g., 'purchase')"
    )
    resource: str = Field(
        description="Resource being accessed (e.g., 'vendor/dell/order/9281')"
    )
    purpose: str = Field(
        description="Purpose of the request (e.g., 'procurement')"
    )
    authority_id: str = Field(
        description="ID of the authority being exercised"
    )

    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Request context (amount, currency, geography, etc.)",
    )

    class Config:
        """Pydantic config."""

        json_schema_extra = {
            "example": {
                "actor": "agent:arkstride:buyer",
                "action": "purchase",
                "resource": "vendor/dell/order/9281",
                "purpose": "procurement",
                "authority_id": "ddf:authority:01ARZ3NHHzB",
                "context": {
                    "amount": 4200,
                    "currency": "GBP",
                    "geography": "GB",
                    "audience": "vendor-api",
                },
            }
        }


class AuthorizationDecision(BaseModel):
    """The result of an authorization evaluation."""

    decision: str = Field(
        description="ALLOW or DENY",
        pattern="^(ALLOW|DENY)$",
    )

    actor: str = Field(
        description="Actor evaluated"
    )
    action: str = Field(
        description="Action evaluated"
    )
    resource: str = Field(
        description="Resource evaluated"
    )
    purpose: str = Field(
        description="Purpose evaluated"
    )
    sponsor: str = Field(
        description="Ultimate sponsor of the authority"
    )

    authority_path: list[str] = Field(
        description="Full delegation chain"
    )

    effective_constraints: Optional[AuthorityConstraints] = Field(
        default=None,
        description="Effective constraints after full chain evaluation (ALLOW only)"
    )

    valid_until: Optional[datetime] = Field(
        default=None,
        description="Authority validity deadline (ALLOW only)"
    )

    decision_id: str = Field(
        default_factory=lambda: f"ddf:decision:{uuid4().hex[:12]}",
        description="Unique ID for this decision for audit/explanation lookup",
    )

    reasons: list[str] = Field(
        description="Machine-readable reasons for decision"
    )

    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional details about the decision",
    )

    class Config:
        """Pydantic config."""

        json_schema_extra = {
            "example": {
                "decision": "ALLOW",
                "actor": "agent:arkstride:buyer",
                "action": "purchase",
                "resource": "vendor/dell/order/9281",
                "purpose": "procurement",
                "sponsor": "user:alice@example.com",
                "authority_path": [
                    "user:alice@example.com",
                    "agent:arkstride:assistant",
                    "agent:arkstride:procurement",
                    "agent:arkstride:buyer",
                ],
                "effective_constraints": {
                    "max_amount": 2000.0,
                    "currency": "GBP",
                    "geographies": ["GB"],
                },
                "valid_until": "2026-08-13T16:00:00Z",
                "decision_id": "ddf:decision:01ARZ3NHHzB",
                "reasons": [
                    "signature_valid",
                    "authority_chain_valid",
                    "resource_allowed",
                    "purpose_allowed",
                    "amount_within_limit",
                ],
            }
        }
