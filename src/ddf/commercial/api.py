"""Commercial trust/control-plane API."""

from __future__ import annotations

import hmac
import os
from collections.abc import Awaitable, Callable
from typing import Annotated

import httpx
from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
)
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from ddf.api.dependencies import get_db_session
from ddf.authority.models import AuthorizationRequest
from ddf.authorization.service import AuthorizationService
from ddf.commercial.auth import (
    authenticate_request,
    require_role,
)
from ddf.commercial.authority import (
    create_delegation,
    create_root_grant,
)
from ddf.commercial.capabilities import (
    consume_capability,
    mint_capability,
)
from ddf.commercial.db import (
    AuthorityTenant,
    EvidenceRecord,
    Tenant,
    TrustedPrincipal,
)
from ddf.commercial.evidence import record_evidence
from ddf.commercial.identity import register_agent
from ddf.commercial.intent import compile_intent
from ddf.commercial.models import (
    AuthenticatedPrincipal,
    BootstrapRequest,
    CommercialDelegationRequest,
    CommercialGrantRequest,
    CompileIntentRequest,
    ConsumeCapabilityRequest,
    MintCapabilityRequest,
    PolicyUpdateRequest,
    ReBACCheckRequest,
    ReBACTupleRequest,
    RegisterAgentRequest,
)
from ddf.commercial.policy import set_policy
from ddf.policy.openfga import OpenFGAPolicy

router = APIRouter(
    prefix="/v1/commercial",
    tags=["commercial-trust-plane"],
)


SessionDep = Annotated[
    AsyncSession,
    Depends(get_db_session),
]


async def principal_dependency(
    request: Request,
    session: SessionDep,
) -> AuthenticatedPrincipal:
    return await authenticate_request(request, session)


PrincipalDep = Annotated[
    AuthenticatedPrincipal,
    Depends(principal_dependency),
]


class LegacyMutationGuard(BaseHTTPMiddleware):
    """Disable insecure v0.1 mutation endpoints in enforced deployments."""

    protected = (
        "/v1/grants",
        "/v1/delegations/",
        "/v1/revocations",
    )

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        enforce = os.getenv("DDF_COMMERCIAL_ENFORCE", "false").lower() in {"1", "true", "yes", "on"}

        if (
            enforce
            and request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
            and any(
                request.url.path == path or request.url.path.startswith(path)
                for path in self.protected
            )
        ):
            raise HTTPException(
                status_code=410,
                detail=("legacy unauthenticated mutation endpoint disabled; use /v1/commercial/*"),
            )

        return await call_next(request)


@router.post("/bootstrap")
async def bootstrap(
    request: BootstrapRequest,
    session: SessionDep,
    bootstrap_token: Annotated[
        str | None,
        Header(alias="X-DDF-Bootstrap-Token"),
    ] = None,
) -> dict:
    configured = os.getenv("DDF_BOOTSTRAP_TOKEN", "")

    if len(configured) < 32:
        raise HTTPException(
            status_code=503,
            detail="DDF_BOOTSTRAP_TOKEN must contain at least 32 characters",
        )

    if not bootstrap_token or not hmac.compare_digest(
        bootstrap_token,
        configured,
    ):
        raise HTTPException(
            status_code=401,
            detail="invalid bootstrap token",
        )

    existing = await session.get(Tenant, request.tenant_id)

    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="tenant already exists",
        )

    tenant = Tenant(
        tenant_id=request.tenant_id,
        display_name=request.tenant_id,
    )

    principal = TrustedPrincipal(
        tenant_id=request.tenant_id,
        subject=request.subject,
        identity_type=request.identity_type,
        key_id=request.key_id,
        public_key=request.public_key,
        roles_json=request.roles,
        active=True,
    )

    session.add(tenant)
    session.add(principal)

    await session.commit()

    return {
        "tenant_id": request.tenant_id,
        "principal": request.subject,
        "roles": request.roles,
    }


@router.post("/agents")
async def create_agent(
    request: RegisterAgentRequest,
    session: SessionDep,
    principal: PrincipalDep,
) -> dict:
    require_role(
        principal,
        "agent_registrar",
        "tenant_admin",
    )

    try:
        card = await register_agent(
            session,
            principal=principal,
            request=request,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    return card.model_dump(mode="json")


@router.post("/grants")
async def issue_grant(
    request: CommercialGrantRequest,
    session: SessionDep,
    principal: PrincipalDep,
) -> dict:
    require_role(
        principal,
        "authority_issuer",
        "tenant_admin",
    )

    require_human = os.getenv("DDF_REQUIRE_HUMAN_ROOT_SPONSOR", "true").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    if require_human and principal.identity_type not in {"human", "user"}:
        raise HTTPException(
            status_code=403,
            detail="root authority requires an authenticated human sponsor",
        )

    try:
        authority = await create_root_grant(
            session,
            principal=principal,
            request=request,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    return authority.model_dump(mode="json")


@router.post("/delegations/{authority_id}")
async def delegate(
    authority_id: str,
    request: CommercialDelegationRequest,
    session: SessionDep,
    principal: PrincipalDep,
) -> dict:
    try:
        authority, delegation_id = await create_delegation(
            session,
            principal=principal,
            parent_authority_id=authority_id,
            request=request,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=403,
            detail=str(exc),
        ) from exc

    return {
        "authority": authority.model_dump(mode="json"),
        "delegation_id": delegation_id,
    }


@router.post("/authorize")
async def authorize(
    request: AuthorizationRequest,
    session: SessionDep,
    principal: PrincipalDep,
) -> dict:
    mapping = await session.get(
        AuthorityTenant,
        request.authority_id,
    )

    if mapping is None or mapping.tenant_id != principal.tenant_id:
        raise HTTPException(
            status_code=404,
            detail="authority not found in tenant",
        )

    if request.actor != principal.subject and not principal.has_role(
        "tenant_admin", "authorize_as"
    ):
        raise HTTPException(
            status_code=403,
            detail="authenticated principal does not match request actor",
        )

    try:
        decision = await AuthorizationService.authorize(
            session=session,
            request=request,
        )
    except Exception:
        raise

    return decision.model_dump(mode="json")


@router.post("/capabilities")
async def mint(
    request: MintCapabilityRequest,
    session: SessionDep,
    principal: PrincipalDep,
) -> dict:
    try:
        capability = await mint_capability(
            session,
            principal=principal,
            request=request,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=403,
            detail=str(exc),
        ) from exc

    return capability.model_dump(mode="json")


@router.post("/capabilities/{capability_id}/consume")
async def consume(
    capability_id: str,
    request: ConsumeCapabilityRequest,
    session: SessionDep,
    principal: PrincipalDep,
) -> dict:
    try:
        return await consume_capability(
            session,
            principal=principal,
            capability_id=capability_id,
            request=request,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=403,
            detail=str(exc),
        ) from exc


@router.post("/intents/compile")
async def intent_compile(
    request: CompileIntentRequest,
    principal: PrincipalDep,
) -> dict:
    del principal

    try:
        proposal = compile_intent(request.text)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    return {
        "proposal": proposal.model_dump(mode="json"),
        "trusted": False,
        "message": (
            "Intent output is an untrusted proposal and must still pass "
            "deterministic DDF authority/policy validation."
        ),
    }


@router.post("/rebac/check")
async def rebac_check(
    request: ReBACCheckRequest,
    principal: PrincipalDep,
) -> dict:
    policy = OpenFGAPolicy.from_env()

    required = os.getenv("DDF_OPENFGA_REQUIRED", "false").lower() in {"1", "true", "yes", "on"}

    if required and not policy.enabled:
        raise HTTPException(
            status_code=503,
            detail="OpenFGA is required but disabled",
        )

    try:
        allowed = await policy.check(
            user=request.user,
            relation=request.relation,
            object=request.object,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="OpenFGA check failed closed",
        ) from exc

    return {
        "allowed": allowed,
        "tenant_id": principal.tenant_id,
    }


@router.post("/rebac/tuples")
async def rebac_write(
    request: ReBACTupleRequest,
    session: SessionDep,
    principal: PrincipalDep,
) -> dict:
    require_role(
        principal,
        "rebac_admin",
        "tenant_admin",
    )

    policy = OpenFGAPolicy.from_env()

    try:
        await policy.write_tuple(
            user=request.user,
            relation=request.relation,
            object=request.object,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="OpenFGA tuple write failed",
        ) from exc

    await record_evidence(
        session,
        tenant_id=principal.tenant_id,
        event_type="openfga_tuple_written",
        principal_id=principal.subject,
        payload=request.model_dump(mode="json"),
    )
    await session.commit()

    return {"written": True}


@router.put("/policies/{policy_key}")
async def update_policy(
    policy_key: str,
    request: PolicyUpdateRequest,
    session: SessionDep,
    principal: PrincipalDep,
) -> dict:
    require_role(
        principal,
        "policy_admin",
        "tenant_admin",
    )

    record = await set_policy(
        session,
        principal=principal,
        key=policy_key,
        value=request.value,
    )

    return {
        "policy_key": record.policy_key,
        "version": record.version,
        "value": record.value_json,
    }


@router.get("/evidence")
async def evidence(
    session: SessionDep,
    principal: PrincipalDep,
    limit: int = 100,
) -> list[dict]:
    require_role(
        principal,
        "auditor",
        "tenant_admin",
    )

    limit = max(1, min(limit, 1000))

    rows = (
        await session.execute(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == principal.tenant_id)
            .order_by(
                EvidenceRecord.created_at.asc(),
                EvidenceRecord.evidence_id.asc(),
            )
            .limit(limit)
        )
    ).scalars()

    return [
        {
            "evidence_id": row.evidence_id,
            "event_type": row.event_type,
            "principal_id": row.principal_id,
            "authority_id": row.authority_id,
            "capability_id": row.capability_id,
            "payload": row.payload_json,
            "previous_hash": row.previous_hash,
            "content_hash": row.content_hash,
            "key_id": row.key_id,
            "public_key": row.public_key,
            "signature": row.signature,
            "created_at": row.created_at.isoformat(),
        }
        for row in rows
    ]


async def readiness(session: AsyncSession) -> dict:
    await session.execute(text("SELECT 1"))

    result = {
        "status": "ready",
        "database": "ready",
        "openfga": "not-required",
    }

    required = os.getenv("DDF_OPENFGA_REQUIRED", "false").lower() in {"1", "true", "yes", "on"}

    if required:
        policy = OpenFGAPolicy.from_env()

        if not policy.enabled:
            raise RuntimeError("OpenFGA is required but disabled")

        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(f"{policy.api_url}/healthz")
            response.raise_for_status()

        result["openfga"] = "ready"

    return result


def install_commercial(app: FastAPI) -> None:
    app.include_router(router)
    app.add_middleware(LegacyMutationGuard)

    @app.get("/ready")
    async def ready(
        session: SessionDep,
    ) -> dict:
        try:
            return await readiness(session)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail=f"not ready: {exc}",
            ) from exc
