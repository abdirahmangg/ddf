"""Tamper-evident provenance services for DDF."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.crypto.signing import Ed25519Key
from ddf.db.models import ProvenanceChainHead, ProvenanceEvent

CHAIN_FORMAT = "ddf-provenance/1"


def _canonical_json(value: Any) -> bytes:
    """Serialize a value deterministically for hashing."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


class ProvenanceService:
    """Create and verify append-only hash-linked provenance records."""

    @staticmethod
    def _participates_in_current_chain(
        event: ProvenanceEvent,
    ) -> bool:
        """Return whether an event uses the current chain format."""
        details = event.details_json or {}

        return details.get("_ddf_chain_format") == CHAIN_FORMAT

    @staticmethod
    async def _latest_chained_event(
        session: AsyncSession,
    ) -> ProvenanceEvent | None:
        """Return the most recent current-format provenance event."""
        stmt = select(ProvenanceEvent).order_by(
            ProvenanceEvent.created_at.desc(),
            ProvenanceEvent.event_id.desc(),
        )

        result = await session.execute(stmt)

        for event in result.scalars():
            if ProvenanceService._participates_in_current_chain(event):
                return event

        return None

    @staticmethod
    async def record_event(
        session: AsyncSession,
        *,
        event_type: str,
        authority_id: str | None = None,
        actor: str | None = None,
        sponsor: str | None = None,
        action: str | None = None,
        resource: str | None = None,
        details: dict[str, Any] | None = None,
        signing_key: Ed25519Key | None = None,
    ) -> ProvenanceEvent:
        """Append a tamper-evident provenance event."""
        head = await ProvenanceService._lock_chain_head(session)
        previous_hash = head.latest_hash

        created_at = datetime.now(UTC)
        normalized_created_at = created_at.astimezone(UTC).replace(tzinfo=None)
        business_details = dict(details or {})

        payload = {
            "event_type": event_type,
            "authority_id": authority_id,
            "actor": actor,
            "sponsor": sponsor,
            "action": action,
            "resource": resource,
            "details": business_details,
            "previous_hash": previous_hash,
            "created_at": normalized_created_at.isoformat(),
        }

        content_hash = hashlib.sha256(_canonical_json(payload)).hexdigest()

        metadata: dict[str, Any] = {
            **business_details,
            "_ddf_chain_format": CHAIN_FORMAT,
            "_ddf_previous_hash": previous_hash,
        }

        if signing_key is not None:
            metadata["_ddf_signature"] = signing_key.sign(content_hash.encode("utf-8"))
            metadata["_ddf_signing_key_id"] = signing_key.key_id
            metadata["_ddf_signing_public_key"] = signing_key.verify_key_b64

        event = ProvenanceEvent(
            event_type=event_type,
            authority_id=authority_id,
            actor=actor,
            sponsor=sponsor,
            action=action,
            resource=resource,
            details_json=metadata,
            content_hash=content_hash,
            created_at=created_at,
        )

        session.add(event)
        await session.flush()
        head.latest_hash = content_hash
        head.updated_at = created_at

        return event

    @staticmethod
    async def _lock_chain_head(session: AsyncSession) -> ProvenanceChainHead:
        """Acquire a transaction-scoped lock shared by SQLite and PostgreSQL writers."""
        bind = session.get_bind()
        now = datetime.now(UTC)
        values = {"id": 1, "latest_hash": "", "updated_at": now}
        if bind.dialect.name == "sqlite":
            await session.execute(
                sqlite_insert(ProvenanceChainHead)
                .values(**values)
                .on_conflict_do_nothing(index_elements=[ProvenanceChainHead.id])
            )
        elif bind.dialect.name == "postgresql":
            await session.execute(
                postgresql_insert(ProvenanceChainHead)
                .values(**values)
                .on_conflict_do_nothing(index_elements=[ProvenanceChainHead.id])
            )
        else:
            raise RuntimeError(
                f"provenance chain locking is unsupported for dialect {bind.dialect.name}"
            )
        head = await session.scalar(
            select(ProvenanceChainHead)
            .where(ProvenanceChainHead.id == 1)
            .with_for_update()
        )
        if head is None:
            raise RuntimeError("provenance chain head could not be initialized")
        if not head.latest_hash:
            latest = await ProvenanceService._latest_chained_event(session)
            if latest is not None and latest.content_hash is not None:
                head.latest_hash = latest.content_hash
        return head

    @staticmethod
    def _payload_for_event(
        event: ProvenanceEvent,
    ) -> dict[str, Any]:
        """Reconstruct the canonical payload represented by an event."""
        details = event.details_json or {}

        business_details = {
            key: value for key, value in details.items() if not key.startswith("_ddf_")
        }

        created_at = event.created_at
        if created_at.tzinfo is not None:
            created_at = created_at.astimezone(UTC).replace(tzinfo=None)
        else:
            created_at = created_at.replace(tzinfo=None)

        return {
            "event_type": event.event_type,
            "authority_id": event.authority_id,
            "actor": event.actor,
            "sponsor": event.sponsor,
            "action": event.action,
            "resource": event.resource,
            "details": business_details,
            "previous_hash": details.get(
                "_ddf_previous_hash",
                "",
            ),
            "created_at": created_at.isoformat(),
        }

    @staticmethod
    async def verify_chain(
        session: AsyncSession,
    ) -> tuple[bool, list[str]]:
        """
        Verify the active current-format provenance chain from the latest event
        backward along the embedded previous-hash pointers.

        Legacy provenance rows are retained but are not silently interpreted
        as members of a chain format they were never written with.
        """
        stmt = select(ProvenanceEvent).order_by(
            ProvenanceEvent.created_at.desc(),
            ProvenanceEvent.event_id.desc(),
        )

        result = await session.execute(stmt)
        chained_events = [
            event
            for event in result.scalars().all()
            if ProvenanceService._participates_in_current_chain(event)
        ]

        if not chained_events:
            return True, []

        by_hash = {
            event.content_hash: event
            for event in chained_events
            if event.content_hash is not None
        }
        head = await session.get(ProvenanceChainHead, 1)
        latest_event = (
            by_hash.get(head.latest_hash)
            if head is not None
            else chained_events[0]
        )
        if latest_event is None:
            return False, ["PROVENANCE_CHAIN_HEAD_MISMATCH"]

        seen: set[str] = set()
        chain_events: list[ProvenanceEvent] = []
        current: ProvenanceEvent | None = latest_event

        while current is not None and current.content_hash not in seen:
            chain_events.append(current)
            seen.add(current.content_hash or "")

            previous_hash = (current.details_json or {}).get("_ddf_previous_hash", "")
            if not previous_hash:
                break

            current = by_hash.get(previous_hash)

        violations: list[str] = []
        previous_hash = ""

        for event in reversed(chain_events):
            details = event.details_json or {}

            stored_previous_hash = details.get(
                "_ddf_previous_hash",
                "",
            )

            if stored_previous_hash != previous_hash:
                violations.append(f"PROVENANCE_PREVIOUS_HASH_MISMATCH:{event.event_id}")

            expected_hash = hashlib.sha256(
                _canonical_json(ProvenanceService._payload_for_event(event))
            ).hexdigest()

            if expected_hash != event.content_hash:
                violations.append(f"PROVENANCE_CONTENT_HASH_MISMATCH:{event.event_id}")

            signature = details.get("_ddf_signature")
            public_key = details.get("_ddf_signing_public_key")

            if signature and public_key:
                content_hash = event.content_hash or ""

                try:
                    verify_key = VerifyKey(
                        public_key.encode("ascii"),
                        encoder=Base64Encoder,
                    )

                    verify_key.verify(
                        content_hash.encode("utf-8"),
                        Base64Encoder.decode(signature.encode("ascii")),
                    )

                except (
                    BadSignatureError,
                    ValueError,
                    TypeError,
                ):
                    violations.append(f"PROVENANCE_SIGNATURE_INVALID:{event.event_id}")

            previous_hash = event.content_hash or ""

        return not violations, violations

    @staticmethod
    async def list_events(
        session: AsyncSession,
        *,
        authority_id: str | None = None,
        actor: str | None = None,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[ProvenanceEvent]:
        """List provenance events with optional filters."""
        stmt = select(ProvenanceEvent)

        if authority_id is not None:
            stmt = stmt.where(ProvenanceEvent.authority_id == authority_id)

        if actor is not None:
            stmt = stmt.where(ProvenanceEvent.actor == actor)

        if event_type is not None:
            stmt = stmt.where(ProvenanceEvent.event_type == event_type)

        stmt = stmt.order_by(ProvenanceEvent.created_at.desc()).limit(limit)

        result = await session.execute(stmt)

        return list(result.scalars().all())
