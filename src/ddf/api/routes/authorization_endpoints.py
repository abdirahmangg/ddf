"""Authorization API endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.api.dependencies import get_db_session
from ddf.authority.models import AuthorizationRequest
from ddf.authorization.service import AuthorizationService

router = APIRouter(
    prefix="/v1",
    tags=["authorization"],
)

SessionDep = Annotated[
    AsyncSession,
    Depends(get_db_session),
]


@router.post(
    "/authorize",
    response_model=dict,
    summary="Make an authorization decision",
    description=(
        "Evaluate full-chain delegated authority, revocation, "
        "proof-of-possession, constraints, and optional OpenFGA policy."
    ),
)
async def authorize(
    request: AuthorizationRequest,
    session: SessionDep,
) -> dict:
    """Make a DDF authorization decision."""
    decision = await AuthorizationService.authorize(
        session=session,
        request=request,
    )

    response = decision.model_dump(mode="json")

    return response
