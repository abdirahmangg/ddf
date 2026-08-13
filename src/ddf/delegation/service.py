"""Services for managing authority grants and delegations."""

from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ddf.authority.models import Authority, AuthorityConstraints, AuthorityProof
from ddf.authority.attenuation import AttenuationEngine
from ddf.crypto.canonical import CanonicalSerializer
from ddf.crypto.signing import Ed25519Key
from ddf.db.models import Authority as AuthorityDB, AuthorityDelegation as DelegationDB, ProvenanceEvent as EventDB
from ddf.api.errors import AttenuationViolationError, InvalidAuthorityPathError


class GrantService:
    """Service for creating root authority grants."""

    @staticmethod
    async def create_grant(
        session: AsyncSession,
        sponsor: str,
        actor: str,
        actions: list[str],
        resources: list[str],
        purposes: list[str],
        constraints: Optional[AuthorityConstraints] = None,
        expires_in_hours: int = 24,
        reason: Optional[str] = None,
        signing_key: Optional[Ed25519Key] = None,
    ) -> Authority:
        """
        Create a root authority grant from sponsor to actor.

        A grant is a root authority where the authority_path is [sponsor, actor]
        and parent_authority_id is None.

        Args:
            session: Database session
            sponsor: Actor granting the authority (e.g., 'user:alice@example.com')
            actor: Actor receiving the authority (e.g., 'agent:buyer-42')
            actions: List of permitted actions
            resources: List of permitted resources
            purposes: List of permitted purposes
            constraints: Optional scope-limiting constraints
            expires_in_hours: How many hours until authority expires
            reason: Reason for the grant
            signing_key: Optional Ed25519 key for signing (defaults to unsigned)

        Returns:
            Created Authority object (signed if key provided)

        Raises:
            InvalidAuthorityPathError: If authority_path is invalid
        """
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=expires_in_hours)

        # Create authority
        authority = Authority(
            actor=actor,
            sponsor=sponsor,
            actions=actions,
            resources=resources,
            purposes=purposes,
            constraints=constraints or AuthorityConstraints(),
            authority_path=[sponsor, actor],  # Root authority
            issued_at=now,
            expires_at=expires_at,
            holder_public_key=signing_key.verify_key_b64 if signing_key else "",
        )

        # Sign if key provided
        if signing_key:
            canonical_bytes = CanonicalSerializer.serialize_authority_for_signing(
                authority.model_dump()
            )
            signature_b64 = signing_key.sign(canonical_bytes)
            authority.proof = AuthorityProof(
                algorithm="Ed25519",
                key_id=signing_key.key_id,
                signature=signature_b64,
            )

        # Store in database
        auth_db = AuthorityDB(
            authority_id=authority.authority_id,
            version=authority.version,
            actor=authority.actor,
            sponsor=authority.sponsor,
            actions=authority.actions,
            resources=authority.resources,
            purposes=authority.purposes,
            authority_path=authority.authority_path,
            constraints_json=authority.constraints.model_dump(),
            issued_at=authority.issued_at,
            expires_at=authority.expires_at,
            parent_authority_id=None,  # Root authority
            holder_public_key=authority.holder_public_key,
            proof_json=authority.proof.model_dump() if authority.proof else {},
        )
        session.add(auth_db)

        # Record provenance event
        event = EventDB(
            event_type="authority_issued",
            authority_id=authority.authority_id,
            actor=sponsor,
            sponsor=sponsor,
            action="grant",
            resource=",".join(resources),
            details_json={
                "reason": reason,
                "constraints": authority.constraints.model_dump(),
            },
        )
        session.add(event)

        await session.commit()
        return authority


class DelegationService:
    """Service for delegating authorities."""

    @staticmethod
    async def create_delegation(
        session: AsyncSession,
        parent_authority_id: str,
        delegated_to: str,
        actions: Optional[list[str]] = None,
        resources: Optional[list[str]] = None,
        purposes: Optional[list[str]] = None,
        constraints: Optional[AuthorityConstraints] = None,
        reason: Optional[str] = None,
        signing_key: Optional[Ed25519Key] = None,
    ) -> tuple[Authority, str]:
        """
        Delegate an authority to another actor.

        Creates a child authority that is attenuated from the parent.

        Args:
            session: Database session
            parent_authority_id: ID of parent authority to delegate from
            delegated_to: Actor receiving the delegated authority
            actions: Actions to delegate (defaults to parent's actions)
            resources: Resources to delegate (defaults to parent's resources)
            purposes: Purposes to delegate (defaults to parent's purposes)
            constraints: Scope-limiting constraints
            reason: Reason for delegation
            signing_key: Optional Ed25519 key for signing

        Returns:
            Tuple of (created Authority, delegation_id)

        Raises:
            AttenuationViolationError: If delegation violates attenuation rules
            InvalidAuthorityPathError: If authority_path would be invalid
        """
        # Fetch parent authority from database
        parent_db = await session.get(AuthorityDB, parent_authority_id)
        if not parent_db:
            raise ValueError(f"Parent authority not found: {parent_authority_id}")

        # Reconstruct parent Authority from DB record
        parent_authority = Authority(
            version=parent_db.version,
            authority_id=parent_db.authority_id,
            actor=parent_db.actor,
            sponsor=parent_db.sponsor,
            actions=parent_db.actions,
            resources=parent_db.resources,
            purposes=parent_db.purposes,
            constraints=AuthorityConstraints(**parent_db.constraints_json),
            authority_path=parent_db.authority_path,
            issued_at=parent_db.issued_at,
            expires_at=parent_db.expires_at,
            parent_authority_id=parent_db.parent_authority_id,
            holder_public_key=parent_db.holder_public_key,
        )

        # Use parent's scope if not specified
        child_actions = actions or parent_authority.actions
        child_resources = resources or parent_authority.resources
        child_purposes = purposes or parent_authority.purposes
        child_constraints = constraints or parent_authority.constraints

        # Create child authority
        now = datetime.now(timezone.utc)
        child_authority = Authority(
            actor=delegated_to,
            sponsor=parent_authority.sponsor,  # Same sponsor
            actions=child_actions,
            resources=child_resources,
            purposes=child_purposes,
            constraints=child_constraints,
            authority_path=parent_authority.authority_path + [delegated_to],
            issued_at=now,
            expires_at=parent_authority.expires_at,
            parent_authority_id=parent_authority_id,
            holder_public_key=signing_key.verify_key_b64 if signing_key else "",
        )

        # Validate attenuation
        attenuation_result = AttenuationEngine.is_attenuation_valid(
            parent_authority, child_authority
        )
        if not attenuation_result.allowed:
            raise AttenuationViolationError(
                f"Delegation violates authority attenuation: {attenuation_result.violations}"
            )

        # Sign if key provided
        if signing_key:
            canonical_bytes = CanonicalSerializer.serialize_authority_for_signing(
                child_authority.model_dump()
            )
            signature_b64 = signing_key.sign(canonical_bytes)
            child_authority.proof = AuthorityProof(
                algorithm="Ed25519",
                key_id=signing_key.key_id,
                signature=signature_b64,
            )

        # Store child authority in database
        child_db = AuthorityDB(
            authority_id=child_authority.authority_id,
            version=child_authority.version,
            actor=child_authority.actor,
            sponsor=child_authority.sponsor,
            actions=child_authority.actions,
            resources=child_authority.resources,
            purposes=child_authority.purposes,
            authority_path=child_authority.authority_path,
            constraints_json=child_authority.constraints.model_dump(),
            issued_at=child_authority.issued_at,
            expires_at=child_authority.expires_at,
            parent_authority_id=child_authority.parent_authority_id,
            holder_public_key=child_authority.holder_public_key,
            proof_json=child_authority.proof.model_dump() if child_authority.proof else {},
        )
        session.add(child_db)

        # Record delegation
        delegation_id = f"ddf:delegation:{child_authority.authority_id.split(':')[-1]}"
        delegation = DelegationDB(
            delegation_id=delegation_id,
            parent_authority_id=parent_authority_id,
            child_authority_id=child_authority.authority_id,
            actor=parent_authority.actor,
            delegated_to=delegated_to,
            reason=reason,
        )
        session.add(delegation)

        # Record provenance event
        event = EventDB(
            event_type="authority_delegated",
            authority_id=child_authority.authority_id,
            actor=parent_authority.actor,
            sponsor=parent_authority.sponsor,
            action="delegate",
            resource=",".join(child_authority.resources),
            details_json={
                "reason": reason,
                "parent_authority_id": parent_authority_id,
                "delegated_to": delegated_to,
            },
        )
        session.add(event)

        await session.commit()
        return child_authority, delegation_id
