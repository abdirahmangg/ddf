"""DDF provenance and audit endpoints."""

from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    Query,
)
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.api.dependencies import get_db_session
from ddf.provenance.service import ProvenanceService

router = APIRouter(
    prefix="/v1/audit",
    tags=["audit"],
)

SessionDep = Annotated[
    AsyncSession,
    Depends(get_db_session),
]

Limit = Annotated[
    int,
    Query(ge=1, le=1000),
]


@router.get("/events")
async def list_events(
    session: SessionDep,
    authority_id: str | None = None,
    actor: str | None = None,
    event_type: str | None = None,
    limit: Limit = 100,
) -> list[dict]:
    """List provenance events."""
    events = await ProvenanceService.list_events(
        session,
        authority_id=authority_id,
        actor=actor,
        event_type=event_type,
        limit=limit,
    )

    return [
        {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "authority_id": event.authority_id,
            "actor": event.actor,
            "sponsor": event.sponsor,
            "action": event.action,
            "resource": event.resource,
            "details": event.details_json,
            "content_hash": event.content_hash,
            "created_at": (event.created_at.isoformat()),
        }
        for event in events
    ]


@router.get("/verify")
async def verify_provenance(
    session: SessionDep,
) -> dict:
    """Verify the current DDF provenance chain."""
    valid, violations = await ProvenanceService.verify_chain(session)

    return {
        "valid": valid,
        "violations": violations,
    }
