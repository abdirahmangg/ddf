"""Domain models for DDF's production trust plane."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class AuthenticatedPrincipal(BaseModel):
    """Cryptographically authenticated human, agent, service, or workload."""

    tenant_id: str
    subject: str
    identity_type: Literal["human", "user", "agent", "service", "workload"]
    key_id: str
    public_key: str
    roles: list[str] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True)

    def has_role(self, *roles: str) -> bool:
        return bool(set(self.roles).intersection(roles))


class BootstrapRequest(BaseModel):
    """Create the first trusted principal for a tenant."""

    tenant_id: str = Field(min_length=1, max_length=128)
    subject: str = Field(min_length=1, max_length=256)
    identity_type: Literal["human", "user", "service"]
    key_id: str = Field(min_length=1, max_length=256)
    public_key: str
    roles: list[str] = Field(
        default_factory=lambda: [
            "tenant_admin",
            "authority_issuer",
            "policy_admin",
            "agent_registrar",
            "rebac_admin",
            "auditor",
        ]
    )


class AgentCard(BaseModel):
    """Signed A2A-compatible identity description."""

    card_id: str = Field(default_factory=lambda: f"ddf:agent-card:{uuid4().hex}")
    tenant_id: str
    agent_id: str
    issuer: str
    public_key: str
    protocols: list[str] = Field(default_factory=lambda: ["ddf"])
    capabilities: list[str] = Field(default_factory=list)
    organization: str | None = None
    valid_from: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    status: Literal["active", "revoked"] = "active"
    metadata: dict[str, Any] = Field(default_factory=dict)
    signature: str | None = None
    signing_key_id: str | None = None

    model_config = ConfigDict(extra="forbid")


class RegisterAgentRequest(BaseModel):
    agent_id: str
    public_key: str
    protocols: list[str] = Field(default_factory=lambda: ["ddf"])
    capabilities: list[str] = Field(default_factory=list)
    organization: str | None = None
    expires_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CommercialGrantRequest(BaseModel):
    actor: str
    actions: list[str] = Field(min_length=1)
    resources: list[str] = Field(min_length=1)
    purposes: list[str] = Field(min_length=1)
    constraints: dict[str, Any] = Field(default_factory=dict)
    expires_in_hours: int = Field(default=24, ge=1, le=720)
    reason: str | None = None


class CommercialDelegationRequest(BaseModel):
    delegated_to: str
    actions: list[str] | None = None
    resources: list[str] | None = None
    purposes: list[str] | None = None
    constraints: dict[str, Any] | None = None
    reason: str | None = None


class CapabilityDocument(BaseModel):
    """Short-lived PoP-bound DDF capability."""

    capability_id: str = Field(default_factory=lambda: f"ddf:capability:{uuid4().hex}")
    tenant_id: str
    authority_id: str
    actor: str
    action: str
    resource: str
    purpose: str
    holder_public_key: str
    task_id: str
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    uses_remaining: int = 1
    metadata: dict[str, Any] = Field(default_factory=dict)
    issuer_key_id: str
    issuer_public_key: str
    signature: str

    model_config = ConfigDict(extra="forbid")


class MintCapabilityRequest(BaseModel):
    authority_id: str
    actor: str
    action: str
    resource: str
    purpose: str
    task_id: str = Field(default_factory=lambda: f"task:{uuid4().hex}")
    ttl_seconds: int = Field(default=60, ge=1, le=300)
    context: dict[str, Any] = Field(default_factory=dict)


class ConsumeCapabilityRequest(BaseModel):
    nonce: str = Field(min_length=16, max_length=256)
    signature: str
    context: dict[str, Any] = Field(default_factory=dict)


class IntentProposal(BaseModel):
    """Untrusted structured proposal produced from natural-language intent."""

    action: str
    resource: str
    purpose: str
    amount: float | None = None
    currency: str | None = None
    geography: str | None = None
    audience: str | None = None
    confidence: float = Field(default=1.0, ge=0, le=1)
    source: Literal["structured", "rule"] = "rule"


class CompileIntentRequest(BaseModel):
    text: str = Field(min_length=1, max_length=8000)


class EvidenceEnvelope(BaseModel):
    evidence_id: str
    tenant_id: str
    event_type: str
    principal_id: str | None
    authority_id: str | None
    capability_id: str | None
    payload: dict[str, Any]
    previous_hash: str | None
    content_hash: str
    key_id: str
    public_key: str
    signature: str
    created_at: datetime


class ReBACCheckRequest(BaseModel):
    user: str
    relation: str
    object: str


class ReBACTupleRequest(BaseModel):
    user: str
    relation: str
    object: str


class PolicyUpdateRequest(BaseModel):
    value: dict[str, Any]
