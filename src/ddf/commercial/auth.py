"""Signed-request authentication and replay protection."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, status
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.commercial.crypto import request_message, verify_ed25519
from ddf.commercial.db import ReplayNonce, TrustedPrincipal
from ddf.commercial.models import AuthenticatedPrincipal


def _header(request: Request, name: str) -> str:
    value = request.headers.get(name)
    if not value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"missing required authentication header: {name}",
        )
    return value


async def authenticate_request(
    request: Request,
    session: AsyncSession,
) -> AuthenticatedPrincipal:
    tenant_id = _header(request, "X-DDF-Tenant")
    subject = _header(request, "X-DDF-Principal")
    key_id = _header(request, "X-DDF-Key-Id")
    timestamp_text = _header(request, "X-DDF-Timestamp")
    nonce = _header(request, "X-DDF-Nonce")
    signature = _header(request, "X-DDF-Signature")

    principal = (
        await session.execute(
            select(TrustedPrincipal).where(
                TrustedPrincipal.tenant_id == tenant_id,
                TrustedPrincipal.subject == subject,
                TrustedPrincipal.key_id == key_id,
                TrustedPrincipal.active.is_(True),
            )
        )
    ).scalar_one_or_none()

    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unknown or inactive DDF principal",
        )

    try:
        timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid request timestamp",
        ) from exc

    now = datetime.now(UTC)
    validity = int(os.getenv("DDF_REQUEST_SIGNATURE_VALIDITY_SECONDS", "300"))

    if abs((now - timestamp.astimezone(UTC)).total_seconds()) > validity:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="request signature timestamp outside validity window",
        )

    body = await request.body()
    message = request_message(
        method=request.method,
        path=request.url.path,
        timestamp=timestamp_text,
        nonce=nonce,
        body=body,
    )

    if not verify_ed25519(
        principal.public_key,
        message,
        signature,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid DDF request signature",
        )

    retention = int(os.getenv("DDF_NONCE_RETENTION_SECONDS", "900"))

    await session.execute(delete(ReplayNonce).where(ReplayNonce.expires_at < now))

    session.add(
        ReplayNonce(
            tenant_id=tenant_id,
            nonce=nonce,
            principal_id=subject,
            expires_at=now + timedelta(seconds=retention),
        )
    )

    try:
        # Replay state must survive even if the business request later fails.
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="request nonce has already been used",
        ) from exc

    return AuthenticatedPrincipal.model_validate(
        {
            "tenant_id": tenant_id,
            "subject": subject,
            "identity_type": principal.identity_type,
            "key_id": principal.key_id,
            "public_key": principal.public_key,
            "roles": list(principal.roles_json or []),
        }
    )


def require_role(
    principal: AuthenticatedPrincipal,
    *roles: str,
) -> None:
    if not principal.has_role(*roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"required role: one of {', '.join(roles)}",
        )
