"""Revocation registry interfaces and assertion-subtree invalidation."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.db.models import CapabilityRevocation, UniversalAssertionRecord
from ddf.provenance.service import ProvenanceService


@dataclass(frozen=True)
class RevocationStatus:
    """CRL/OCSP-style status response for a capability assertion."""

    grant_id: str
    revoked: bool
    checked_at: datetime
    reason: str | None = None
    source: str = "ddf-registry"


class RevocationStatusSource(Protocol):
    """A real-time revocation status provider, such as a CRL or OCSP adapter."""

    async def check_status(self, grant_id: str) -> RevocationStatus: ...


class OpenFGATupleInvalidator(Protocol):
    """The OpenFGA tuple deletion surface needed for revocation propagation."""

    enabled: bool

    async def delete_capability_tuple(
        self,
        *,
        principal: str,
        target_namespace: str,
        target_resource: str,
    ) -> None: ...


class RevocationRegistry(Protocol):
    """Registry API consumed by capability authorization and lifecycle hooks."""

    async def check_status(self, grant_id: str) -> RevocationStatus: ...

    async def revoke_subtree(
        self,
        grant_id: str,
        *,
        actor: str,
        reason: str,
    ) -> Sequence[str]: ...


class DatabaseRevocationRegistry:
    """Persist revocations, consult optional live status sources, and invalidate tuples."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        status_sources: Sequence[RevocationStatusSource] = (),
        openfga: OpenFGATupleInvalidator | None = None,
    ) -> None:
        self._session = session
        self._status_sources = tuple(status_sources)
        self._openfga = openfga

    async def check_status(self, grant_id: str) -> RevocationStatus:
        """Check local state and all configured real-time revocation sources."""
        record = await self._session.get(CapabilityRevocation, grant_id)
        if record is not None:
            return RevocationStatus(
                grant_id=grant_id,
                revoked=True,
                checked_at=datetime.now(UTC),
                reason=record.reason,
            )

        for source in self._status_sources:
            status = await source.check_status(grant_id)
            if status.revoked:
                return status

        return RevocationStatus(
            grant_id=grant_id,
            revoked=False,
            checked_at=datetime.now(UTC),
        )

    async def revoke_subtree(
        self,
        grant_id: str,
        *,
        actor: str,
        reason: str,
    ) -> Sequence[str]:
        """Revoke a grant and every persisted descendant, then invalidate tuples."""
        records = await self._descendants(grant_id)
        if not records:
            raise ValueError(f"universal capability grant not found: {grant_id}")

        now = datetime.now(UTC)
        invalidations: list[tuple[str, str, str]] = []
        revoked_ids: list[str] = []
        for record in records:
            assertion = record.assertion_json
            capability = assertion.get("capability", {})
            subject = assertion.get("subject")
            namespace = capability.get("target_namespace")
            resource = capability.get("target_resource")
            if isinstance(subject, str) and isinstance(namespace, str) and isinstance(resource, str):
                invalidations.append((subject, namespace, resource))

            existing = await self._session.get(CapabilityRevocation, record.grant_id)
            if existing is None:
                self._session.add(
                    CapabilityRevocation(
                        grant_id=record.grant_id,
                        actor=actor,
                        reason=reason,
                        revoked_at=now,
                    )
                )
            revoked_ids.append(record.grant_id)
            await ProvenanceService.record_event(
                self._session,
                event_type="capability_revoked",
                authority_id=record.source_authority_id,
                actor=actor,
                action="revoke",
                resource=resource if isinstance(resource, str) else None,
                details={
                    "grant_id": record.grant_id,
                    "reason": reason,
                    "parent_grant_id": record.parent_grant_id,
                },
            )

        await self._session.commit()

        if self._openfga is not None and self._openfga.enabled:
            for subject, namespace, resource in invalidations:
                await self._openfga.delete_capability_tuple(
                    principal=subject,
                    target_namespace=namespace,
                    target_resource=resource,
                )

        return tuple(revoked_ids)

    async def _descendants(self, grant_id: str) -> list[UniversalAssertionRecord]:
        """Load a persisted subtree breadth-first and guard against corrupted cycles."""
        root = await self._session.get(UniversalAssertionRecord, grant_id)
        if root is None:
            return []

        records = [root]
        seen = {grant_id}
        frontier = [grant_id]
        while frontier:
            result = await self._session.execute(
                select(UniversalAssertionRecord).where(
                    UniversalAssertionRecord.parent_grant_id.in_(frontier)
                )
            )
            children = list(result.scalars().all())
            frontier = []
            for child in children:
                if child.grant_id not in seen:
                    seen.add(child.grant_id)
                    frontier.append(child.grant_id)
                    records.append(child)
        return records
