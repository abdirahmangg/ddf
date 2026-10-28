"""Strict v0.2 authorization and delegation endpoints."""

import base64
import json
import os
from itertools import pairwise
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.api.dependencies import get_db_session
from ddf.api.errors import SignatureVerificationError
from ddf.authority.capabilities import CapabilityAccessRequest
from ddf.authority.models import (
    CapabilityAssertionProof,
    SignedCapabilityAssertion,
    UniversalDDFCapabilityAssertion,
)
from ddf.authority.revocation import DatabaseRevocationRegistry
from ddf.authority.runtime_posture import EATVerifier
from ddf.authorization.service import AuthorizationService
from ddf.crypto.signing import Verifier
from ddf.db.models import UniversalAssertionRecord
from ddf.policy.openfga import OpenFGAConfigurationError, OpenFGAPolicy

router = APIRouter(prefix="/v2", tags=["universal-capabilities"])


class UniversalAuthorizationRequest(BaseModel):
    """Strict v0.2 capability authorization envelope."""

    grant_id: str
    request: CapabilityAccessRequest

    model_config = ConfigDict(extra="forbid")


class UniversalDelegationRequest(BaseModel):
    """Strict child assertion for attenuation and persistent delegation."""

    child: SignedCapabilityAssertion

    model_config = ConfigDict(extra="forbid")


SessionDep = Annotated[AsyncSession, Depends(get_db_session)]


def _trusted_assertion_keys() -> dict[str, dict[str, str]]:
    configured = os.getenv("DDF_CAPABILITY_TRUSTED_KEYS", "")
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="DDF_CAPABILITY_TRUSTED_KEYS is required for v0.2 assertion verification",
        )
    try:
        keys: Any = json.loads(configured)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="DDF_CAPABILITY_TRUSTED_KEYS must be a JSON object",
        ) from exc
    if not isinstance(keys, dict):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="DDF_CAPABILITY_TRUSTED_KEYS must be a JSON object",
        )
    return keys


def _verify_signed_assertion(signed: SignedCapabilityAssertion) -> None:
    trusted_keys = _trusted_assertion_keys()
    trusted = trusted_keys.get(signed.assertion.issuer)
    if not isinstance(trusted, dict):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="assertion issuer is not trusted",
        )

    key_id = trusted.get("key_id")
    public_key = trusted.get("public_key")
    if (
        not isinstance(key_id, str)
        or not isinstance(public_key, str)
        or signed.proof.key_id != key_id
        or signed.proof.public_key != public_key
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="assertion proof does not match the trusted issuer key",
        )
    try:
        base64.b64decode(public_key, validate=True)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="configured capability issuer key is invalid",
        ) from exc
    try:
        Verifier.verify_assertion(signed.assertion, signed.proof)
    except SignatureVerificationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="assertion signature verification failed",
        ) from exc


def _stored_assertion(record: UniversalAssertionRecord) -> SignedCapabilityAssertion:
    if record.proof_json is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="migrated legacy assertion requires trusted re-issuance",
        )
    return SignedCapabilityAssertion(
        assertion=UniversalDDFCapabilityAssertion.model_validate(record.assertion_json),
        proof=CapabilityAssertionProof.model_validate(record.proof_json),
    )


async def _validated_chain(
    session: AsyncSession,
    record: UniversalAssertionRecord,
) -> list[UniversalDDFCapabilityAssertion]:
    chain: list[UniversalDDFCapabilityAssertion] = []
    seen: set[str] = set()
    current: UniversalAssertionRecord | None = record
    while current is not None:
        if current.grant_id in seen:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="universal capability delegation cycle detected",
            )
        seen.add(current.grant_id)
        revocation = await DatabaseRevocationRegistry(session).check_status(current.grant_id)
        if revocation.revoked:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="universal capability assertion has been revoked",
            )
        signed = _stored_assertion(current)
        _verify_signed_assertion(signed)
        chain.append(signed.assertion)
        current = (
            await session.get(UniversalAssertionRecord, current.parent_grant_id)
            if current.parent_grant_id
            else None
        )
    chain.reverse()
    for parent, child in pairwise(chain):
        if not AuthorizationService.is_capability_attenuated(parent, child).allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="persisted delegation chain violates capability attenuation",
            )
    return chain


@router.post("/grants", summary="Persist a signed universal capability assertion")
async def create_grant(
    request: SignedCapabilityAssertion,
    session: SessionDep,
) -> dict[str, Any]:
    """Persist a root assertion only after validating its trusted issuer proof."""
    _verify_signed_assertion(request)
    if await session.get(UniversalAssertionRecord, request.assertion.grant_id) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="grant identifier already exists",
        )
    session.add(
        UniversalAssertionRecord(
            grant_id=request.assertion.grant_id,
            assertion_json=request.assertion.model_dump(mode="json"),
            proof_json=request.proof.model_dump(mode="json"),
        )
    )
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="grant identifier already exists",
        ) from exc
    return request.model_dump(mode="json")


@router.post("/authorize", summary="Authorize a universal capability assertion")
async def authorize(
    request: UniversalAuthorizationRequest,
    session: SessionDep,
) -> dict[str, Any]:
    """Verify issuer trust and evaluate capability and EAT-bound runtime posture."""
    record = await session.get(UniversalAssertionRecord, request.grant_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="universal capability grant not found",
        )
    chain = await _validated_chain(session, record)
    assertion = chain[-1]
    try:
        runtime_verifier = EATVerifier.from_env()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"invalid runtime posture configuration: {exc}",
        ) from exc
    result = AuthorizationService.authorize_capability(
        assertion,
        request.request,
        runtime_verifier=runtime_verifier,
    )
    openfga = OpenFGAPolicy.from_env()
    if "posture_below_threshold" in result.reasons:
        try:
            await DatabaseRevocationRegistry(session, openfga=openfga).revoke_subtree(
                request.grant_id,
                actor=request.request.subject,
                reason="runtime posture fell below the configured threshold",
            )
        except (httpx.HTTPError, OpenFGAConfigurationError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="low-posture revocation could not be fully propagated",
            ) from exc
    if openfga.enabled and result.allowed:
        try:
            relationship_allowed = await openfga.check_capability(
                principal=request.request.subject,
                target_namespace=request.request.target_namespace,
                target_resource=request.request.target_resource,
            )
        except (httpx.HTTPError, OpenFGAConfigurationError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OpenFGA capability check failed",
            ) from exc
        if not relationship_allowed:
            result = result.model_copy(
                update={
                    "allowed": False,
                    "reasons": [*result.reasons, "openfga_denied"],
                }
            )
    return result.model_dump(mode="json")


@router.post(
    "/delegations/{parent_grant_id}",
    summary="Persist an attenuated universal capability delegation",
)
async def create_delegation(
    parent_grant_id: str,
    request: UniversalDelegationRequest,
    session: SessionDep,
) -> dict[str, Any]:
    """Persist a child assertion after verifying the parent and attenuation chain."""
    parent_record = await session.get(UniversalAssertionRecord, parent_grant_id)
    if parent_record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="parent capability grant not found",
        )
    parent_chain = await _validated_chain(session, parent_record)
    parent = parent_chain[-1]
    _verify_signed_assertion(request.child)
    result = AuthorizationService.is_capability_attenuated(
        parent,
        request.child.assertion,
    )
    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"message": "child capability exceeds parent", "reasons": result.reasons},
        )
    child_id = request.child.assertion.grant_id
    if await session.get(UniversalAssertionRecord, child_id) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="grant identifier already exists",
        )
    session.add(
        UniversalAssertionRecord(
            grant_id=child_id,
            assertion_json=request.child.assertion.model_dump(mode="json"),
            proof_json=request.child.proof.model_dump(mode="json"),
            parent_grant_id=parent_grant_id,
        )
    )
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="grant identifier already exists",
        ) from exc
    return {
        "assertion": request.child.assertion.model_dump(mode="json"),
        "parent_grant_id": parent_grant_id,
    }
