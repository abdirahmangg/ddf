# ruff: noqa: B008, B904
"""API endpoints for authority grants and delegations."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.api.dependencies import get_db_session, get_settings_dep
from ddf.api.errors import AttenuationViolationError
from ddf.api.routes.grants import (
    AuthorityResponse,
    CreateDelegationRequest,
    CreateGrantRequest,
    DelegationResponse,
    GrantResponse,
)
from ddf.delegation.service import DelegationService, GrantService
from ddf.settings import Settings

router = APIRouter(prefix="/v1", tags=["authorities"])


@router.post(
    "/grants",
    response_model=GrantResponse,
    summary="Create a root authority grant",
    description="Grant a root authority from sponsor to actor",
)
async def create_grant(
    request: CreateGrantRequest,
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dep),
) -> GrantResponse:
    """
    Create a root authority grant.

    A grant is a root authority with no parent, issued directly by the sponsor.

    Args:
        request: Grant creation request
        session: Database session
        settings: Application settings

    Returns:
        Created authority

    Raises:
        400: Invalid request
        500: Internal server error
    """
    try:
        authority = await GrantService.create_grant(
            session=session,
            sponsor=settings.api_host,  # For now, use API host as sponsor
            actor=request.actor,
            actions=request.actions,
            resources=request.resources,
            purposes=request.purposes,
            constraints=request.constraints,
            expires_in_hours=request.expires_in_hours,
            reason=request.reason,
            signing_key=None,  # Will be signed by API if needed
        )

        # Convert to response
        auth_dict = authority.model_dump()
        auth_dict["issued_at"] = authority.issued_at.isoformat()
        auth_dict["expires_at"] = authority.expires_at.isoformat()

        return GrantResponse(
            authority=AuthorityResponse(**auth_dict),
            message=f"Authority granted to {request.actor}",
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create grant: {e!s}",
        )


@router.post(
    "/delegations/{authority_id}",
    response_model=DelegationResponse,
    summary="Delegate an authority to another actor",
    description="Create a delegated (child) authority from a parent authority",
)
async def create_delegation(
    authority_id: str,
    request: CreateDelegationRequest,
    session: AsyncSession = Depends(get_db_session),
) -> DelegationResponse:
    """
    Delegate an authority to another actor.

    Creates a child authority attenuated from the parent, ensuring the security
    invariant: Authority(child) ⊆ Authority(parent).

    Args:
        authority_id: Parent authority ID
        request: Delegation request
        session: Database session

    Returns:
        Created child authority and delegation record

    Raises:
        400: Invalid delegation (attenuation violation)
        404: Parent authority not found
        500: Internal server error
    """
    try:
        child_authority, delegation_id = await DelegationService.create_delegation(
            session=session,
            parent_authority_id=authority_id,
            delegated_to=request.delegated_to,
            actions=request.actions,
            resources=request.resources,
            purposes=request.purposes,
            constraints=request.constraints,
            reason=request.reason,
            signing_key=None,
        )

        # Convert to response
        auth_dict = child_authority.model_dump()
        auth_dict["issued_at"] = child_authority.issued_at.isoformat()
        auth_dict["expires_at"] = child_authority.expires_at.isoformat()

        return DelegationResponse(
            authority=AuthorityResponse(**auth_dict),
            delegation_id=delegation_id,
            message=f"Authority delegated to {request.delegated_to}",
        )

    except AttenuationViolationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Delegation violates attenuation: {e!s}",
        )
    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(e),
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create delegation: {e!s}",
        )
