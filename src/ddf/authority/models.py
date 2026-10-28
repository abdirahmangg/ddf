"""Core authority domain models for DDF."""

from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ddf.authority.predicates import PredicateEngine

CANONICAL_OPERATIONS = frozenset({"read", "write", "execute", "invoke", "delegate", "admin"})


class Capability(BaseModel):
    """Sector-neutral resource scope and constraints carried by a capability."""

    target_namespace: str = Field(min_length=1)
    target_resource: str
    operations: list[str] = Field(min_length=1)
    constraints: dict[str, Any]

    @field_validator("target_namespace")
    @classmethod
    def validate_namespace(cls, value: str) -> str:
        if not value:
            raise ValueError("target_namespace cannot be empty")
        return value

    @field_validator("operations")
    @classmethod
    def validate_operations(cls, value: list[str]) -> list[str]:
        if (
            not value
            or len(value) != len(set(value))
            or not set(value).issubset(CANONICAL_OPERATIONS)
        ):
            raise ValueError(
                "operations must be a non-empty, unique subset of canonical operations "
                f"{sorted(CANONICAL_OPERATIONS)}"
            )
        return value

    @field_validator("target_resource")
    @classmethod
    def validate_resource_uri(cls, value: str) -> str:
        if not urlsplit(value).scheme or any(character.isspace() for character in value):
            raise ValueError("target_resource must be a valid URI")
        return value

    @field_validator("constraints")
    @classmethod
    def validate_constraint_predicates(cls, value: dict[str, Any]) -> dict[str, Any]:
        if value:
            PredicateEngine.validate(value)
        return value

    model_config = ConfigDict(extra="forbid")


class UniversalDDFCapabilityAssertion(BaseModel):
    """Canonical, sector-neutral DDF capability assertion."""

    grant_id: str = Field(
        description="UUID of this grant",
        json_schema_extra={"format": "uuid"},
    )
    issuer: str = Field(
        description="URI of delegating entity",
        json_schema_extra={"format": "uri"},
    )
    subject: str = Field(
        description="URI of delegated actor",
        json_schema_extra={"format": "uri"},
    )
    capability: Capability

    @field_validator("grant_id")
    @classmethod
    def validate_grant_id(cls, value: str) -> str:
        return str(UUID(value))

    @field_validator("issuer", "subject")
    @classmethod
    def validate_principal_uri(cls, value: str) -> str:
        parsed = urlsplit(value)
        if not parsed.scheme or any(character.isspace() for character in value):
            raise ValueError("principal identifiers must be valid URIs")
        return value

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"title": "UniversalDDFCapabilityAssertion"},
    )


class CapabilityAssertionProof(BaseModel):
    """Detached Ed25519 proof for a universal capability assertion."""

    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str
    signature: str
    public_key: str

    model_config = ConfigDict(extra="forbid")


class SignedCapabilityAssertion(BaseModel):
    """Universal assertion and detached issuer proof used by v0.2 APIs."""

    assertion: UniversalDDFCapabilityAssertion
    proof: CapabilityAssertionProof

    model_config = ConfigDict(extra="forbid")


class AuthorityConstraints(BaseModel):
    """Constraints that limit the scope of an authority.

    Constraints define the outer boundaries of what an authority permits.
    A child authority cannot expand any constraint beyond its parent.
    """

    max_amount: float | None = Field(
        default=None,
        description="Maximum monetary amount permitted (e.g., in base currency units)",
    )
    currency: str | None = Field(
        default=None, description="ISO 4217 currency code (e.g., GBP, USD)"
    )
    geographies: list[str] | None = Field(
        default=None,
        description="ISO 3166-1 alpha-2 country codes (e.g., ['GB', 'US'])",
    )
    audiences: list[str] | None = Field(
        default=None,
        description="Intended recipients (e.g., ['vendor-api', 'internal-system'])",
    )
    valid_from: datetime | None = Field(
        default=None, description="Earliest time this authority is valid"
    )
    expires_at: datetime | None = Field(
        default=None, description="Latest time this authority is valid"
    )
    delegation_depth_remaining: int | None = Field(
        default=None,
        description="Maximum number of further delegations permitted (0 = terminal)",
    )
    predicates: dict[str, Any] | None = Field(
        default=None,
        description="Declarative request-context predicates evaluated by the predicate engine",
    )

    @field_validator("predicates")
    @classmethod
    def validate_predicates(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is not None:
            PredicateEngine.validate(value)
        return value

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "predicates": {
                    "all": [
                        {
                            "path": "context.classification",
                            "op": "in",
                            "value": ["public", "internal"],
                        }
                    ]
                },
            }
        },
    )


class AuthorityProof(BaseModel):
    """Cryptographic proof that this authority was validly signed."""

    algorithm: str = Field(
        default="Ed25519",
        description="Cryptographic algorithm used (only Ed25519 in v0.1)",
    )
    key_id: str = Field(description="Key ID of the signer for verification lookup")
    signature: str = Field(description="Base64-encoded signature of canonical authority document")
    public_key: str | None = Field(
        default=None,
        description="Base64 Ed25519 verification key of the authority issuer",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "algorithm": "Ed25519",
                "key_id": "ddf:key:01ARZ3NHHzB...",
                "signature": "MEUCIQDz...",
            }
        },
    )


class Authority(BaseModel):
    """
    Legacy v0.1 authority record retained for compatibility.

    New capability payloads should use UniversalDDFCapabilityAssertion.
    """

    version: str = Field(
        default="ddf/0.1",
        description="DDF protocol version",
    )

    authority_id: str = Field(
        default_factory=lambda: f"ddf:authority:{uuid4().hex[:12]}",
        description="Unique authority identifier",
    )

    actor: str = Field(description="Legacy identifier of the entity granted authority")

    sponsor: str = Field(description="Legacy identifier of the original authority source")

    actions: list[str] = Field(description="Legacy operation identifiers")

    resources: list[str] = Field(description="Legacy resource identifiers")

    purposes: list[str] = Field(description="Legacy use labels")

    constraints: AuthorityConstraints = Field(
        default_factory=AuthorityConstraints,
        description="Scope-limiting constraints",
    )

    authority_path: list[str] = Field(description="Chain of actors from sponsor to current actor")

    issued_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this authority was issued (UTC)",
    )

    expires_at: datetime = Field(description="When this authority expires (UTC)")

    parent_authority_id: str | None = Field(
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

    proof: AuthorityProof | None = Field(
        default=None,
        description="Cryptographic proof of validity",
    )

    @field_validator("expires_at")
    @classmethod
    def expires_after_issued(cls, v: datetime, data: Any) -> datetime:
        """Ensure expires_at is after issued_at."""
        if "issued_at" in data.data:
            issued_at = data.data["issued_at"]
            if issued_at is None:
                return v

            if issued_at.tzinfo is None:
                issued_at = issued_at.replace(tzinfo=UTC)
            else:
                issued_at = issued_at.astimezone(UTC)

            if v.tzinfo is None:
                v = v.replace(tzinfo=UTC)
            else:
                v = v.astimezone(UTC)

            if v <= issued_at:
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

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "version": "ddf/0.1",
                "authority_id": "ddf:authority:01ARZ3NHHzB",
                "actor": "urn:agent:ddf:worker",
                "sponsor": "did:key:z6Mksponsor",
                "actions": ["execute"],
                "resources": ["urn:mcp:tools/*"],
                "purposes": ["service"],
                "constraints": {
                    "predicates": {
                        "all": [
                            {
                                "path": "context.tenant_id",
                                "op": "eq",
                                "value": "tenant-7",
                            }
                        ]
                    }
                },
                "authority_path": ["did:key:z6Mksponsor", "urn:agent:ddf:worker"],
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
        },
    )


class AuthorizationRequest(BaseModel):
    """Request to perform an authorization check."""

    actor: str = Field(description="Legacy identifier of the requesting subject")
    action: str = Field(description="Legacy operation identifier")
    resource: str = Field(description="Resource identifier")
    purpose: str = Field(description="Legacy use label")
    authority_id: str = Field(description="ID of the authority being exercised")
    target_namespace: str | None = Field(
        default=None,
        description="Namespace taxonomy for the requested resource",
    )

    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Request context evaluated against generic capability predicates",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "actor": "urn:agent:ddf:worker",
                "action": "execute",
                "resource": "urn:mcp:tools:sql_query",
                "purpose": "service",
                "authority_id": "ddf:authority:01ARZ3NHHzB",
                "target_namespace": "mcp",
                "context": {"tenant_id": "tenant-7"},
            }
        },
    )


class AuthorizationDecision(BaseModel):
    """The result of an authorization evaluation."""

    decision: str = Field(
        description="ALLOW or DENY",
        pattern="^(ALLOW|DENY)$",
    )

    actor: str = Field(description="Actor evaluated")
    action: str = Field(description="Action evaluated")
    resource: str = Field(description="Resource evaluated")
    purpose: str = Field(description="Purpose evaluated")
    sponsor: str = Field(description="Ultimate sponsor of the authority")

    authority_path: list[str] = Field(description="Full delegation chain")

    effective_constraints: AuthorityConstraints | None = Field(
        default=None, description="Effective constraints after full chain evaluation (ALLOW only)"
    )

    valid_until: datetime | None = Field(
        default=None, description="Authority validity deadline (ALLOW only)"
    )

    decision_id: str = Field(
        default_factory=lambda: f"ddf:decision:{uuid4().hex[:12]}",
        description="Unique ID for this decision for audit/explanation lookup",
    )

    reasons: list[str] = Field(description="Machine-readable reasons for decision")

    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional details about the decision",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "decision": "ALLOW",
                "actor": "urn:agent:ddf:worker",
                "action": "execute",
                "resource": "urn:mcp:tools:sql_query",
                "purpose": "service",
                "sponsor": "did:key:z6Mksponsor",
                "authority_path": ["did:key:z6Mksponsor", "urn:agent:ddf:worker"],
                "effective_constraints": {
                    "predicates": {
                        "all": [
                            {
                                "path": "context.tenant_id",
                                "op": "eq",
                                "value": "tenant-7",
                            }
                        ]
                    }
                },
                "valid_until": "2026-08-13T16:00:00Z",
                "decision_id": "ddf:decision:01ARZ3NHHzB",
                "reasons": [
                    "signature_valid",
                    "authority_chain_valid",
                    "resource_allowed",
                    "capability_predicate_satisfied",
                ],
            }
        },
    )
