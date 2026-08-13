"""Services for managing authority grants and delegations."""

from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from ddf.api.errors import AttenuationViolationError
from ddf.authority.attenuation import AttenuationEngine
from ddf.authority.models import (
    Authority,
    AuthorityConstraints,
    AuthorityProof,
)
from ddf.crypto.canonical import CanonicalSerializer
from ddf.crypto.signing import Ed25519Key
from ddf.db.models import (
    Authority as AuthorityDB,
)
from ddf.db.models import (
    AuthorityDelegation as DelegationDB,
)
from ddf.provenance.service import ProvenanceService


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
        constraints: AuthorityConstraints | None = None,
        expires_in_hours: int = 24,
        reason: str | None = None,
        signing_key: Ed25519Key | None = None,
    ) -> Authority:
        """Create a root authority grant."""
        now = datetime.now(UTC)
        expires_at = now + timedelta(hours=expires_in_hours)

        authority = Authority(
            actor=actor,
            sponsor=sponsor,
            actions=actions,
            resources=resources,
            purposes=purposes,
            constraints=(constraints if constraints is not None else AuthorityConstraints()),
            authority_path=[sponsor, actor],
            issued_at=now,
            expires_at=expires_at,
            holder_public_key=(signing_key.verify_key_b64 if signing_key is not None else ""),
        )

        if signing_key is not None:
            canonical_bytes = CanonicalSerializer.serialize_authority_for_signing(
                authority.model_dump()
            )

            authority.proof = AuthorityProof(
                algorithm="Ed25519",
                key_id=signing_key.key_id,
                signature=signing_key.sign(canonical_bytes),
            )

        persisted = AuthorityDB(
            authority_id=authority.authority_id,
            version=authority.version,
            actor=authority.actor,
            sponsor=authority.sponsor,
            actions=authority.actions,
            resources=authority.resources,
            purposes=authority.purposes,
            authority_path=authority.authority_path,
            constraints_json=(authority.constraints.model_dump()),
            issued_at=authority.issued_at,
            expires_at=authority.expires_at,
            parent_authority_id=None,
            holder_public_key=(authority.holder_public_key),
            proof_json=(authority.proof.model_dump() if authority.proof is not None else {}),
        )

        session.add(persisted)

        await ProvenanceService.record_event(
            session,
            event_type="authority_issued",
            authority_id=authority.authority_id,
            actor=sponsor,
            sponsor=sponsor,
            action="grant",
            resource=",".join(resources),
            details={
                "reason": reason,
                "constraints": (authority.constraints.model_dump()),
            },
            signing_key=signing_key,
        )

        await session.commit()

        return authority


class DelegationService:
    """Service for delegating authority."""

    @staticmethod
    async def create_delegation(
        session: AsyncSession,
        parent_authority_id: str,
        delegated_to: str,
        actions: list[str] | None = None,
        resources: list[str] | None = None,
        purposes: list[str] | None = None,
        constraints: AuthorityConstraints | None = None,
        reason: str | None = None,
        signing_key: Ed25519Key | None = None,
    ) -> tuple[Authority, str]:
        """Create an attenuated child authority."""
        parent_db = await session.get(
            AuthorityDB,
            parent_authority_id,
        )

        if parent_db is None:
            raise ValueError(f"Parent authority not found: {parent_authority_id}")

        parent_authority = Authority(
            version=parent_db.version,
            authority_id=parent_db.authority_id,
            actor=parent_db.actor,
            sponsor=parent_db.sponsor,
            actions=parent_db.actions,
            resources=parent_db.resources,
            purposes=parent_db.purposes,
            constraints=AuthorityConstraints(**(parent_db.constraints_json or {})),
            authority_path=parent_db.authority_path,
            issued_at=parent_db.issued_at,
            expires_at=parent_db.expires_at,
            parent_authority_id=(parent_db.parent_authority_id),
            holder_public_key=(parent_db.holder_public_key),
        )

        child_actions = actions if actions is not None else parent_authority.actions
        child_resources = resources if resources is not None else parent_authority.resources
        child_purposes = purposes if purposes is not None else parent_authority.purposes
        child_constraints = constraints if constraints is not None else parent_authority.constraints

        now = datetime.now(UTC)

        child_authority = Authority(
            actor=delegated_to,
            sponsor=parent_authority.sponsor,
            actions=child_actions,
            resources=child_resources,
            purposes=child_purposes,
            constraints=child_constraints,
            authority_path=[
                *parent_authority.authority_path,
                delegated_to,
            ],
            issued_at=now,
            expires_at=parent_authority.expires_at,
            parent_authority_id=(parent_authority_id),
            holder_public_key=(signing_key.verify_key_b64 if signing_key is not None else ""),
        )

        attenuation = AttenuationEngine.is_attenuation_valid(
            parent_authority,
            child_authority,
        )

        if not attenuation.allowed:
            raise AttenuationViolationError(
                attenuation.violations,
                details={
                    "parent_authority_id": (parent_authority_id),
                    "delegated_to": delegated_to,
                    "violations": (attenuation.violations),
                },
            )

        if signing_key is not None:
            canonical_bytes = CanonicalSerializer.serialize_authority_for_signing(
                child_authority.model_dump()
            )

            child_authority.proof = AuthorityProof(
                algorithm="Ed25519",
                key_id=signing_key.key_id,
                signature=signing_key.sign(canonical_bytes),
            )

        child_db = AuthorityDB(
            authority_id=child_authority.authority_id,
            version=child_authority.version,
            actor=child_authority.actor,
            sponsor=child_authority.sponsor,
            actions=child_authority.actions,
            resources=child_authority.resources,
            purposes=child_authority.purposes,
            authority_path=(child_authority.authority_path),
            constraints_json=(child_authority.constraints.model_dump()),
            issued_at=child_authority.issued_at,
            expires_at=child_authority.expires_at,
            parent_authority_id=(child_authority.parent_authority_id),
            holder_public_key=(child_authority.holder_public_key),
            proof_json=(
                child_authority.proof.model_dump() if child_authority.proof is not None else {}
            ),
        )

        session.add(child_db)

        delegation_id = f"ddf:delegation:{child_authority.authority_id.split(':')[-1]}"

        delegation = DelegationDB(
            delegation_id=delegation_id,
            parent_authority_id=(parent_authority_id),
            child_authority_id=(child_authority.authority_id),
            actor=parent_authority.actor,
            delegated_to=delegated_to,
            reason=reason,
        )

        session.add(delegation)

        await ProvenanceService.record_event(
            session,
            event_type="authority_delegated",
            authority_id=(child_authority.authority_id),
            actor=parent_authority.actor,
            sponsor=parent_authority.sponsor,
            action="delegate",
            resource=",".join(child_authority.resources),
            details={
                "reason": reason,
                "parent_authority_id": (parent_authority_id),
                "delegated_to": delegated_to,
            },
            signing_key=signing_key,
        )

        await session.commit()

        return child_authority, delegation_id
