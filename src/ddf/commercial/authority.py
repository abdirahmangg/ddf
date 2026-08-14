"""Tenant-scoped, authenticated authority issuance and delegation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from ddf.authority.attenuation import AttenuationEngine
from ddf.authority.effective import load_authority_chain
from ddf.authority.models import (
    Authority,
    AuthorityConstraints,
    AuthorityProof,
)
from ddf.authorization.service import AuthorizationService
from ddf.commercial.crypto import get_system_signer
from ddf.commercial.db import AuthorityTenant
from ddf.commercial.evidence import record_evidence
from ddf.commercial.identity import identity_public_key
from ddf.commercial.models import (
    AuthenticatedPrincipal,
    CommercialDelegationRequest,
    CommercialGrantRequest,
)
from ddf.crypto.canonical import CanonicalSerializer
from ddf.db.models import Authority as AuthorityDB
from ddf.db.models import AuthorityDelegation as DelegationDB
from ddf.revocation.service import RevocationService


def authority_from_db(row: AuthorityDB) -> Authority:
    proof = AuthorityProof(**row.proof_json) if row.proof_json else None

    return Authority(
        version=row.version,
        authority_id=row.authority_id,
        actor=row.actor,
        sponsor=row.sponsor,
        actions=row.actions,
        resources=row.resources,
        purposes=row.purposes,
        constraints=AuthorityConstraints(**row.constraints_json),
        authority_path=row.authority_path,
        issued_at=row.issued_at,
        expires_at=row.expires_at,
        parent_authority_id=row.parent_authority_id,
        holder_public_key=row.holder_public_key,
        proof=proof,
    )


async def _sign(authority: Authority) -> None:
    signer = get_system_signer()

    payload = authority.model_dump(mode="json")
    payload["proof"] = None

    canonical = CanonicalSerializer.serialize_authority_for_signing(payload)

    authority.proof = AuthorityProof(
        algorithm="Ed25519",
        key_id=signer.key_id,
        public_key=signer.public_key_b64,
        signature=await signer.sign(canonical),
    )


async def create_root_grant(
    session: AsyncSession,
    *,
    principal: AuthenticatedPrincipal,
    request: CommercialGrantRequest,
) -> Authority:
    holder_key = await identity_public_key(
        session,
        tenant_id=principal.tenant_id,
        subject=request.actor,
    )

    now = datetime.now(UTC)

    authority = Authority(
        actor=request.actor,
        sponsor=principal.subject,
        actions=request.actions,
        resources=request.resources,
        purposes=request.purposes,
        constraints=AuthorityConstraints(**request.constraints),
        authority_path=[principal.subject, request.actor],
        issued_at=now,
        expires_at=now + timedelta(hours=request.expires_in_hours),
        holder_public_key=holder_key,
    )

    await _sign(authority)

    if authority.proof is None:
        raise RuntimeError("authority signing did not produce a proof")

    session.add(
        AuthorityDB(
            authority_id=authority.authority_id,
            version=authority.version,
            actor=authority.actor,
            sponsor=authority.sponsor,
            actions=authority.actions,
            resources=authority.resources,
            purposes=authority.purposes,
            authority_path=authority.authority_path,
            constraints_json=authority.constraints.model_dump(mode="json"),
            issued_at=authority.issued_at,
            expires_at=authority.expires_at,
            parent_authority_id=None,
            holder_public_key=authority.holder_public_key,
            proof_json=authority.proof.model_dump(mode="json"),
        )
    )

    session.add(
        AuthorityTenant(
            authority_id=authority.authority_id,
            tenant_id=principal.tenant_id,
            issuer=principal.subject,
        )
    )

    await record_evidence(
        session,
        tenant_id=principal.tenant_id,
        event_type="root_authority_issued",
        principal_id=principal.subject,
        authority_id=authority.authority_id,
        payload={
            "actor": authority.actor,
            "actions": authority.actions,
            "resources": authority.resources,
            "purposes": authority.purposes,
            "reason": request.reason,
        },
    )

    await session.commit()
    return authority


async def create_delegation(
    session: AsyncSession,
    *,
    principal: AuthenticatedPrincipal,
    parent_authority_id: str,
    request: CommercialDelegationRequest,
) -> tuple[Authority, str]:
    mapping = await session.get(AuthorityTenant, parent_authority_id)

    if mapping is None or mapping.tenant_id != principal.tenant_id:
        raise ValueError("parent authority not found in tenant")

    if await RevocationService.is_effectively_revoked(
        session,
        parent_authority_id,
    ):
        raise ValueError("parent authority is revoked")

    chain = await load_authority_chain(
        session,
        parent_authority_id,
    )

    now = datetime.now(UTC)

    for ancestor in chain:
        if ancestor.proof is None:
            raise ValueError(f"authority is missing required signature: {ancestor.authority_id}")

        AuthorizationService.verify_authority_signature(ancestor)

        if ancestor.expires_at <= now:
            raise ValueError(f"authority is expired: {ancestor.authority_id}")

    parent = chain[-1]

    if principal.subject != parent.actor and not principal.has_role("tenant_admin"):
        raise ValueError("only the immediate authority holder may delegate")

    holder_key = await identity_public_key(
        session,
        tenant_id=principal.tenant_id,
        subject=request.delegated_to,
    )

    constraints = (
        AuthorityConstraints(**request.constraints)
        if request.constraints is not None
        else parent.constraints
    )

    child = Authority(
        actor=request.delegated_to,
        sponsor=parent.sponsor,
        actions=request.actions or parent.actions,
        resources=request.resources or parent.resources,
        purposes=request.purposes or parent.purposes,
        constraints=constraints,
        authority_path=[
            *parent.authority_path,
            request.delegated_to,
        ],
        issued_at=now,
        expires_at=min(
            parent.expires_at,
            constraints.expires_at or parent.expires_at,
        ),
        parent_authority_id=parent.authority_id,
        holder_public_key=holder_key,
    )

    attenuation = AttenuationEngine.is_attenuation_valid(
        parent,
        child,
    )

    if not attenuation.allowed:
        raise ValueError("delegation violates attenuation: " + "; ".join(attenuation.violations))

    await _sign(child)

    if child.proof is None:
        raise RuntimeError("delegation signing did not produce a proof")

    session.add(
        AuthorityDB(
            authority_id=child.authority_id,
            version=child.version,
            actor=child.actor,
            sponsor=child.sponsor,
            actions=child.actions,
            resources=child.resources,
            purposes=child.purposes,
            authority_path=child.authority_path,
            constraints_json=child.constraints.model_dump(mode="json"),
            issued_at=child.issued_at,
            expires_at=child.expires_at,
            parent_authority_id=child.parent_authority_id,
            holder_public_key=child.holder_public_key,
            proof_json=child.proof.model_dump(mode="json"),
        )
    )

    delegation_id = f"ddf:delegation:{uuid4().hex}"

    session.add(
        DelegationDB(
            delegation_id=delegation_id,
            parent_authority_id=parent.authority_id,
            child_authority_id=child.authority_id,
            actor=parent.actor,
            delegated_to=child.actor,
            reason=request.reason,
        )
    )

    session.add(
        AuthorityTenant(
            authority_id=child.authority_id,
            tenant_id=principal.tenant_id,
            issuer=principal.subject,
        )
    )

    await record_evidence(
        session,
        tenant_id=principal.tenant_id,
        event_type="authority_delegated",
        principal_id=principal.subject,
        authority_id=child.authority_id,
        payload={
            "parent_authority_id": parent.authority_id,
            "delegated_to": child.actor,
            "reason": request.reason,
        },
    )

    await session.commit()
    return child, delegation_id
