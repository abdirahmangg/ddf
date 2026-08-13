"""DDF database models using SQLAlchemy 2.0+."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    JSON,
    UUID,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
import uuid

from ddf.authority.models import AuthorizationDecision


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all DDF models."""

    pass


class Identity(Base):
    """Represents an identity (actor, user, or service)."""

    __tablename__ = "identities"

    id: Mapped[str] = mapped_column(String(256), primary_key=True)
    """Unique identity ID (e.g., 'agent:arkstride:buyer-42', 'user:alice@example.com')"""

    identity_type: Mapped[str] = mapped_column(String(50))
    """Type: 'agent', 'user', 'service'"""

    display_name: Mapped[Optional[str]] = mapped_column(String(256))
    """Human-readable name"""

    public_key: Mapped[Optional[str]] = mapped_column(Text)
    """Base64-encoded Ed25519 public key (if applicable)"""

    metadata_json: Mapped[Optional[dict]] = mapped_column(JSON)
    """Additional metadata (email, organization, etc.)"""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    """When this identity was registered"""

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    """When this identity was last updated"""

    __table_args__ = (
        Index("idx_identity_type", "identity_type"),
        Index("idx_created_at", "created_at"),
    )


class Authority(Base):
    """Persisted DDF authority."""

    __tablename__ = "authorities"

    authority_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    """Unique authority ID (e.g., 'ddf:authority:abc123')"""

    version: Mapped[str] = mapped_column(String(50), default="ddf/0.1")
    """DDF protocol version"""

    actor: Mapped[str] = mapped_column(String(256), index=True)
    """Actor ID granted this authority"""

    sponsor: Mapped[str] = mapped_column(String(256), index=True)
    """Sponsor ID (ultimate source of authority)"""

    actions: Mapped[list[str]] = mapped_column(JSON)
    """List of permitted actions"""

    resources: Mapped[list[str]] = mapped_column(JSON)
    """List of permitted resources (hierarchical)"""

    purposes: Mapped[list[str]] = mapped_column(JSON)
    """List of permitted purposes"""

    authority_path: Mapped[list[str]] = mapped_column(JSON)
    """Chain of actors from sponsor to current actor"""

    constraints_json: Mapped[dict] = mapped_column(JSON, default={})
    """Scope-limiting constraints (max_amount, geographies, etc.)"""

    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    """When this authority was issued"""

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    """When this authority expires"""

    parent_authority_id: Mapped[Optional[str]] = mapped_column(
        String(256),
        ForeignKey("authorities.authority_id"),
        nullable=True,
    )
    """ID of parent authority (for delegation chains)"""

    holder_public_key: Mapped[str] = mapped_column(Text)
    """Base64-encoded Ed25519 public key of authority holder"""

    proof_json: Mapped[dict] = mapped_column(JSON)
    """Signature proof (algorithm, key_id, signature)"""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    """When this authority was stored in database"""

    __table_args__ = (
        Index("idx_authority_actor", "actor"),
        Index("idx_authority_sponsor", "sponsor"),
        Index("idx_authority_issued_at", "issued_at"),
        Index("idx_authority_expires_at", "expires_at"),
    )


class AuthorityDelegation(Base):
    """Record of an authority delegation (grant or delegation action)."""

    __tablename__ = "authority_delegations"

    delegation_id: Mapped[str] = mapped_column(
        String(256),
        primary_key=True,
        default=lambda: f"ddf:delegation:{uuid.uuid4().hex[:12]}",
    )
    """Unique delegation ID"""

    parent_authority_id: Mapped[str] = mapped_column(
        String(256),
        ForeignKey("authorities.authority_id"),
    )
    """Parent authority being delegated from"""

    child_authority_id: Mapped[str] = mapped_column(
        String(256),
        ForeignKey("authorities.authority_id"),
    )
    """Child authority created by delegation"""

    actor: Mapped[str] = mapped_column(String(256), index=True)
    """Actor making the delegation"""

    delegated_to: Mapped[str] = mapped_column(String(256), index=True)
    """Actor receiving the delegated authority"""

    reason: Mapped[Optional[str]] = mapped_column(Text)
    """Reason for delegation"""

    metadata_json: Mapped[Optional[dict]] = mapped_column(JSON)
    """Additional delegation metadata"""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    """When delegation was performed"""

    __table_args__ = (
        Index("idx_delegation_actor", "actor"),
        Index("idx_delegation_delegated_to", "delegated_to"),
        Index("idx_delegation_created_at", "created_at"),
    )


class AuthorizationLog(Base):
    """Audit log of authorization decisions."""

    __tablename__ = "authorization_logs"

    decision_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    """Unique decision ID"""

    actor: Mapped[str] = mapped_column(String(256), index=True)
    """Actor making the request"""

    action: Mapped[str] = mapped_column(String(256), index=True)
    """Action being requested"""

    resource: Mapped[str] = mapped_column(String(512), index=True)
    """Resource being accessed"""

    purpose: Mapped[Optional[str]] = mapped_column(String(256))
    """Purpose of the access"""

    decision: Mapped[str] = mapped_column(String(50))
    """ALLOW or DENY"""

    authority_id: Mapped[Optional[str]] = mapped_column(String(256))
    """Authority used (if allowed)"""

    reasons: Mapped[list[str]] = mapped_column(JSON, default=[])
    """Reasons for decision"""

    context_json: Mapped[Optional[dict]] = mapped_column(JSON)
    """Additional context"""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    """When decision was made"""

    __table_args__ = (
        Index("idx_authlog_actor", "actor"),
        Index("idx_authlog_action", "action"),
        Index("idx_authlog_resource", "resource"),
        Index("idx_authlog_decision", "decision"),
        Index("idx_authlog_created_at", "created_at"),
    )


class Revocation(Base):
    """Record of an authority revocation."""

    __tablename__ = "revocations"

    revocation_id: Mapped[str] = mapped_column(
        String(256),
        primary_key=True,
        default=lambda: f"ddf:revocation:{uuid.uuid4().hex[:12]}",
    )
    """Unique revocation ID"""

    authority_id: Mapped[str] = mapped_column(
        String(256),
        ForeignKey("authorities.authority_id"),
    )
    """Authority being revoked"""

    actor: Mapped[str] = mapped_column(String(256), index=True)
    """Actor performing the revocation"""

    reason: Mapped[Optional[str]] = mapped_column(Text)
    """Reason for revocation"""

    cascades: Mapped[bool] = mapped_column(default=True)
    """Whether this revocation cascades to delegated authorities"""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    """When revocation was performed"""

    __table_args__ = (
        Index("idx_revocation_actor", "actor"),
        Index("idx_revocation_created_at", "created_at"),
    )


class ProvenanceEvent(Base):
    """Provenance audit trail event."""

    __tablename__ = "provenance_events"

    event_id: Mapped[str] = mapped_column(
        String(256),
        primary_key=True,
        default=lambda: f"ddf:event:{uuid.uuid4().hex[:12]}",
    )
    """Unique event ID"""

    event_type: Mapped[str] = mapped_column(String(50), index=True)
    """Event type (authority_issued, authority_delegated, authority_revoked, authorization_decision, etc.)"""

    authority_id: Mapped[Optional[str]] = mapped_column(String(256), index=True)
    """Authority involved (if applicable)"""

    actor: Mapped[Optional[str]] = mapped_column(String(256), index=True)
    """Actor involved"""

    sponsor: Mapped[Optional[str]] = mapped_column(String(256))
    """Sponsor involved (if applicable)"""

    action: Mapped[Optional[str]] = mapped_column(String(256))
    """Action being performed"""

    resource: Mapped[Optional[str]] = mapped_column(String(512))
    """Resource involved"""

    details_json: Mapped[dict] = mapped_column(JSON, default={})
    """Event-specific details"""

    content_hash: Mapped[Optional[str]] = mapped_column(String(64))
    """SHA-256 hash of event content (for tamper detection)"""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    """When event occurred"""

    __table_args__ = (
        Index("idx_provenance_event_type", "event_type"),
        Index("idx_provenance_authority", "authority_id"),
        Index("idx_provenance_actor", "actor"),
        Index("idx_provenance_created_at", "created_at"),
    )
