"""Identity management for DDF."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.db.models import Identity


class IdentityService:
    """Create and list registered DDF identities."""

    @staticmethod
    async def create(
        session: AsyncSession,
        *,
        identity_id: str,
        public_key: str | None = None,
        display_name: str | None = None,
    ) -> Identity:
        existing = await session.get(
            Identity,
            identity_id,
        )

        if existing is not None:
            raise ValueError(f"Identity already exists: {identity_id}")

        identity_type = identity_id.split(":", 1)[0] if ":" in identity_id else "unknown"

        identity = Identity(
            id=identity_id,
            identity_type=identity_type,
            display_name=display_name,
            public_key=public_key,
            metadata_json={},
        )

        session.add(identity)
        await session.commit()
        await session.refresh(identity)

        return identity

    @staticmethod
    async def list(
        session: AsyncSession,
    ) -> list[Identity]:
        stmt = select(Identity).order_by(Identity.created_at.asc())

        result = await session.execute(stmt)
        return list(result.scalars().all())
