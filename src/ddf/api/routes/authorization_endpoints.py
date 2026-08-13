"""Authorization API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.api.dependencies import get_db_session
from ddf.authority.models import AuthorizationRequest, AuthorizationDecision
from ddf.authorization.service import AuthorizationService
from ddf.api.errors import (
    AuthorityNotFoundError,
    AuthorityExpiredError,
    AuthorizationDeniedError,
)

router = APIRouter(prefix="/v1", tags=["authorization"])


@router.post(
    "/authorize",
    response_model=dict,
    summary="Make an authorization decision",
    description="Check if an actor can perform an action on a resource",
)
async def authorize(
    request: AuthorizationRequest,
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """
    Make an authorization decision.

    Evaluates whether actor can perform action on resource for given purpose
    using specified authority. Returns detailed decision with reasons.

    Args:
        request: Authorization request
        session: Database session

    Returns:
        Authorization decision (ALLOW or DENY) with reasons

    Raises:
        404: Authority not found
        403: Authority expired or authorization denied
        500: Internal server error
    """
    try:
        decision = await AuthorizationService.authorize(
            session=session,
            request=request,
        )

        # Convert decision to response dict
        response_dict = decision.model_dump()
        if decision.issued_at:
            response_dict["issued_at"] = decision.issued_at.isoformat()
        if decision.valid_until:
            response_dict["valid_until"] = decision.valid_until.isoformat()

        return {
            "decision": response_dict["decision"],
            "decision_id": response_dict.get("decision_id"),
            "actor": response_dict.get("actor"),
            "action": response_dict.get("action"),
            "resource": response_dict.get("resource"),
            "purpose": response_dict.get("purpose"),
            "sponsor": response_dict.get("sponsor"),
            "authority_path": response_dict.get("authority_path", []),
            "effective_constraints": response_dict.get("effective_constraints"),
            "valid_until": response_dict.get("valid_until"),
            "reasons": response_dict.get("reasons", []),
            "details": response_dict.get("details", {}),
        }

    except AuthorityNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except AuthorityExpiredError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except AuthorizationDeniedError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authorization check failed: {str(e)}",
        )
