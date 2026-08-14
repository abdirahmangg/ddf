"""Request and response models for delegation API endpoints."""

from pydantic import BaseModel, Field

from ddf.authority.models import AuthorityConstraints


class CreateGrantRequest(BaseModel):
    """Request to create a root authority grant."""

    actor: str = Field(description="Actor ID receiving the authority (e.g., 'agent:buyer-42')")
    actions: list[str] = Field(description="Permitted actions (e.g., ['purchase'])")
    resources: list[str] = Field(description="Permitted resources (e.g., ['vendor/dell/*'])")
    purposes: list[str] = Field(description="Permitted purposes (e.g., ['procurement'])")
    constraints: AuthorityConstraints | None = Field(
        default=None, description="Optional scope-limiting constraints"
    )
    expires_in_hours: int = Field(default=24, description="Hours until expiration")
    reason: str | None = Field(default=None, description="Reason for the grant")


class CreateDelegationRequest(BaseModel):
    """Request to delegate an authority."""

    delegated_to: str = Field(
        description="Actor ID receiving the delegated authority (e.g., 'agent:delegate-42')"
    )
    actions: list[str] | None = Field(
        default=None, description="Actions to delegate (defaults to parent's actions)"
    )
    resources: list[str] | None = Field(
        default=None, description="Resources to delegate (defaults to parent's resources)"
    )
    purposes: list[str] | None = Field(
        default=None, description="Purposes to delegate (defaults to parent's purposes)"
    )
    constraints: AuthorityConstraints | None = Field(
        default=None, description="Optional scope-limiting constraints"
    )
    reason: str | None = Field(default=None, description="Reason for delegation")


class AuthorityResponse(BaseModel):
    """Response containing an authority."""

    authority_id: str = Field(description="Unique authority identifier")
    version: str = Field(description="DDF protocol version")
    actor: str = Field(description="Actor granted this authority")
    sponsor: str = Field(description="Sponsor of this authority")
    actions: list[str] = Field(description="Permitted actions")
    resources: list[str] = Field(description="Permitted resources")
    purposes: list[str] = Field(description="Permitted purposes")
    authority_path: list[str] = Field(description="Chain of actors")
    constraints: AuthorityConstraints = Field(description="Scope-limiting constraints")
    issued_at: str = Field(description="When issued (ISO 8601)")
    expires_at: str = Field(description="When expires (ISO 8601)")
    parent_authority_id: str | None = Field(description="Parent authority (if delegated)")
    holder_public_key: str = Field(description="Holder's public key (base64)")
    proof: dict | None = Field(description="Cryptographic proof")


class GrantResponse(BaseModel):
    """Response to a successful grant."""

    authority: AuthorityResponse = Field(description="Created authority")
    message: str = Field(description="Success message")


class DelegationResponse(BaseModel):
    """Response to a successful delegation."""

    authority: AuthorityResponse = Field(description="Created authority")
    delegation_id: str = Field(description="Delegation record ID")
    message: str = Field(description="Success message")
