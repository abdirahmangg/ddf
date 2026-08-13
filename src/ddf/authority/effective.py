"""Effective multi-hop authority calculation for DDF."""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from ddf.api.errors import (
    AuthorityNotFoundError,
    InvalidAuthorityPathError,
)
from ddf.authority.attenuation import AttenuationEngine
from ddf.authority.models import (
    Authority,
    AuthorityConstraints,
    AuthorityProof,
)
from ddf.db.models import Authority as AuthorityDB


@dataclass(frozen=True)
class EffectiveAuthority:
    """Authority remaining after evaluating a complete delegation chain."""

    actor: str
    sponsor: str
    actions: list[str]
    resources: list[str]
    purposes: list[str]
    constraints: AuthorityConstraints
    authority_path: list[str]
    authority_ids: list[str]
    valid_until: datetime
    holder_public_key: str


def authority_from_db(record: AuthorityDB) -> Authority:
    """Reconstruct a domain Authority from a persisted record."""
    proof: AuthorityProof | None = None

    if record.proof_json:
        try:
            proof = AuthorityProof(**record.proof_json)
        except Exception:
            proof = None

    return Authority(
        version=record.version,
        authority_id=record.authority_id,
        actor=record.actor,
        sponsor=record.sponsor,
        actions=record.actions,
        resources=record.resources,
        purposes=record.purposes,
        constraints=AuthorityConstraints(**(record.constraints_json or {})),
        authority_path=record.authority_path,
        issued_at=record.issued_at,
        expires_at=record.expires_at,
        parent_authority_id=record.parent_authority_id,
        holder_public_key=record.holder_public_key or "",
        proof=proof,
    )


async def load_authority_chain(
    session: AsyncSession,
    authority_id: str,
) -> list[Authority]:
    """
    Load and validate the complete authority chain from root to leaf.

    Client-supplied authority_path values are not trusted by themselves.
    Parent records are followed from persistent storage and every path
    transition is validated.
    """
    records: list[AuthorityDB] = []
    visited: set[str] = set()

    current_id: str | None = authority_id

    while current_id is not None:
        if current_id in visited:
            raise InvalidAuthorityPathError(
                {
                    "reason": "authority_cycle",
                    "authority_id": current_id,
                }
            )

        visited.add(current_id)

        record = await session.get(AuthorityDB, current_id)

        if record is None:
            if current_id == authority_id:
                raise AuthorityNotFoundError(authority_id)

            raise InvalidAuthorityPathError(
                {
                    "reason": "missing_parent",
                    "authority_id": current_id,
                }
            )

        records.append(record)
        current_id = record.parent_authority_id

    records.reverse()

    authorities = [authority_from_db(record) for record in records]

    if not authorities:
        raise AuthorityNotFoundError(authority_id)

    root = authorities[0]

    expected_root_path = [root.sponsor, root.actor]

    if root.parent_authority_id is not None:
        raise InvalidAuthorityPathError({"reason": "root_has_parent"})

    if root.authority_path != expected_root_path:
        raise InvalidAuthorityPathError(
            {
                "reason": "invalid_root_path",
                "expected": expected_root_path,
                "actual": root.authority_path,
            }
        )

    sponsor = root.sponsor

    for index in range(1, len(authorities)):
        parent = authorities[index - 1]
        child = authorities[index]

        if child.sponsor != sponsor:
            raise InvalidAuthorityPathError(
                {
                    "reason": "sponsor_substitution",
                    "authority_id": child.authority_id,
                }
            )

        if child.parent_authority_id != parent.authority_id:
            raise InvalidAuthorityPathError(
                {
                    "reason": "parent_link_mismatch",
                    "authority_id": child.authority_id,
                }
            )

        expected_path = [*parent.authority_path, child.actor]

        if child.authority_path != expected_path:
            raise InvalidAuthorityPathError(
                {
                    "reason": "authority_path_mismatch",
                    "authority_id": child.authority_id,
                    "expected": expected_path,
                    "actual": child.authority_path,
                }
            )

    attenuation = AttenuationEngine.attenuation_chain_valid(authorities)

    if not attenuation.allowed:
        raise InvalidAuthorityPathError(
            {
                "reason": "attenuation_violation",
                "violations": attenuation.violations,
            }
        )

    return authorities


def calculate_effective_authority(
    authorities: list[Authority],
) -> EffectiveAuthority:
    """Calculate authority remaining across a validated delegation chain."""
    if not authorities:
        raise InvalidAuthorityPathError({"reason": "empty_authority_chain"})

    attenuation = AttenuationEngine.attenuation_chain_valid(authorities)

    if not attenuation.allowed:
        raise InvalidAuthorityPathError(
            {
                "reason": "attenuation_violation",
                "violations": attenuation.violations,
            }
        )

    root = authorities[0]
    leaf = authorities[-1]

    actions = sorted(set.intersection(*(set(authority.actions) for authority in authorities)))

    purposes = sorted(set.intersection(*(set(authority.purposes) for authority in authorities)))

    # Because every hop has already passed resource attenuation,
    # the leaf resource scope is the narrowest effective resource scope.
    resources = list(leaf.resources)

    constraints = (
        attenuation.effective_constraints
        if attenuation.effective_constraints is not None
        else leaf.constraints
    )

    valid_until = min(authority.expires_at for authority in authorities)

    return EffectiveAuthority(
        actor=leaf.actor,
        sponsor=root.sponsor,
        actions=actions,
        resources=resources,
        purposes=purposes,
        constraints=constraints,
        authority_path=list(leaf.authority_path),
        authority_ids=[authority.authority_id for authority in authorities],
        valid_until=valid_until,
        holder_public_key=leaf.holder_public_key,
    )


async def get_effective_authority(
    session: AsyncSession,
    authority_id: str,
) -> EffectiveAuthority:
    """Load a chain and calculate its effective authority."""
    chain = await load_authority_chain(session, authority_id)
    return calculate_effective_authority(chain)
