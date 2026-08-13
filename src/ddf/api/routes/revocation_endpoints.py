"""DDF authority revocation endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.api.dependencies import get_db_session
from ddf.revocation.service import RevocationService

router = APIRouter(
    prefix="/v1",
    tags=["revocation"],
)

SessionDep = Annotated[
    AsyncSession,
    Depends(get_db_session),
]


class CreateRevocationRequest(BaseModel):
    """Authority revocation request."""

    authority_id: str
    actor: str
    reason: str | None = None
    cascades: bool = True


@router.post("/revocations")
async def create_revocation(
    request: CreateRevocationRequest,
    session: SessionDep,
) -> dict:
    """Revoke an authority."""
    revocation = await RevocationService.revoke(
        session,
        authority_id=request.authority_id,
        actor=request.actor,
        reason=request.reason,
        cascades=request.cascades,
    )

    return {
        "revocation_id": (revocation.revocation_id),
        "authority_id": revocation.authority_id,
        "actor": revocation.actor,
        "reason": revocation.reason,
        "cascades": revocation.cascades,
        "created_at": (revocation.created_at.isoformat()),
    }


@router.get("/revocations/{authority_id}")
async def get_revocation_status(
    authority_id: str,
    session: SessionDep,
) -> dict:
    """Return direct and effective revocation state."""
    direct = await RevocationService.is_revoked(
        session,
        authority_id,
    )

    effective = await RevocationService.is_effectively_revoked(
        session,
        authority_id,
    )

    return {
        "authority_id": authority_id,
        "revoked": direct,
        "effectively_revoked": effective,
    }
