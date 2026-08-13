"""Tamper-evident provenance services for DDF."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.crypto.signing import Ed25519Key
from ddf.db.models import ProvenanceEvent

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
        previous = await ProvenanceService._latest_chained_event(session)

        previous_hash = (
            previous.content_hash
            if previous is not None and previous.content_hash is not None
            else ""
        )

        created_at = datetime.now(UTC)
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
            "created_at": created_at.isoformat(),
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

        return event

    @staticmethod
    def _payload_for_event(
        event: ProvenanceEvent,
    ) -> dict[str, Any]:
        """Reconstruct the canonical payload represented by an event."""
        details = event.details_json or {}

        business_details = {
            key: value for key, value in details.items() if not key.startswith("_ddf_")
        }

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
            "created_at": event.created_at.isoformat(),
        }

    @staticmethod
    async def verify_chain(
        session: AsyncSession,
    ) -> tuple[bool, list[str]]:
        """
        Verify the complete current-format provenance chain.

        Legacy provenance rows are retained but are not silently interpreted
        as members of a chain format they were never written with.
        """
        stmt = select(ProvenanceEvent).order_by(
            ProvenanceEvent.created_at.asc(),
            ProvenanceEvent.event_id.asc(),
        )

        result = await session.execute(stmt)

        chained_events = [
            event
            for event in result.scalars().all()
            if ProvenanceService._participates_in_current_chain(event)
        ]

        violations: list[str] = []
        previous_hash = ""

        for event in chained_events:
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
