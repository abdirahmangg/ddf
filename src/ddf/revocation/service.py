"""Authority revocation and cascading invalidation."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.api.errors import AuthorityNotFoundError
from ddf.db.models import (
    Authority as AuthorityDB,
)
from ddf.db.models import (
    Revocation as RevocationDB,
)
from ddf.provenance.service import ProvenanceService


class RevocationService:
    """Manage DDF authority revocation."""

    @staticmethod
    async def revoke(
        session: AsyncSession,
        *,
        authority_id: str,
        actor: str,
        reason: str | None = None,
        cascades: bool = True,
    ) -> RevocationDB:
        """Revoke an authority."""
        authority = await session.get(
            AuthorityDB,
            authority_id,
        )

        if authority is None:
            raise AuthorityNotFoundError(authority_id)

        stmt = (
            select(RevocationDB)
            .where(RevocationDB.authority_id == authority_id)
            .order_by(RevocationDB.created_at.desc())
            .limit(1)
        )

        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing is not None:
            return existing

        revocation = RevocationDB(
            authority_id=authority_id,
            actor=actor,
            reason=reason,
            cascades=cascades,
        )

        session.add(revocation)

        await ProvenanceService.record_event(
            session,
            event_type="authority_revoked",
            authority_id=authority_id,
            actor=actor,
            sponsor=authority.sponsor,
            action="revoke",
            resource=",".join(authority.resources),
            details={
                "reason": reason,
                "cascades": cascades,
            },
        )

        await session.commit()
        await session.refresh(revocation)

        return revocation

    @staticmethod
    async def direct_revocations(
        session: AsyncSession,
        authority_id: str,
    ) -> list[RevocationDB]:
        """Return revocations directly attached to an authority."""
        stmt = select(RevocationDB).where(RevocationDB.authority_id == authority_id)

        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def is_revoked(
        session: AsyncSession,
        authority_id: str,
    ) -> bool:
        """Return whether the authority itself is revoked."""
        return bool(
            await RevocationService.direct_revocations(
                session,
                authority_id,
            )
        )

    @staticmethod
    async def is_effectively_revoked(
        session: AsyncSession,
        authority_id: str,
    ) -> bool:
        """
        Return whether authority is invalid due to direct or ancestor revocation.

        A direct revocation always invalidates the target. An ancestor
        revocation invalidates descendants only when cascades=True.
        """
        target = await session.get(
            AuthorityDB,
            authority_id,
        )

        if target is None:
            raise AuthorityNotFoundError(authority_id)

        current: AuthorityDB | None = target
        is_target = True
        visited: set[str] = set()

        while current is not None:
            if current.authority_id in visited:
                return True

            visited.add(current.authority_id)

            revocations = await RevocationService.direct_revocations(
                session,
                current.authority_id,
            )

            if is_target and revocations:
                return True

            if not is_target and any(revocation.cascades for revocation in revocations):
                return True

            if current.parent_authority_id is None:
                break

            current = await session.get(
                AuthorityDB,
                current.parent_authority_id,
            )
            is_target = False

        return False
