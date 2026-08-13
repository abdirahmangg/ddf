"""HTTP-level integration tests for DDF's public API."""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.api.dependencies import get_db_session, get_settings_dep
from ddf.main import create_app
from ddf.settings import Settings


@asynccontextmanager
async def api_client(
    session: AsyncSession,
    *,
    sponsor: str,
) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Create an HTTP client backed by the test DB session."""
    app: FastAPI = create_app()

    async def override_db() -> AsyncGenerator[AsyncSession, None]:
        yield session

    async def override_settings() -> Settings:
        return Settings(api_host=sponsor)

    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_settings_dep] = override_settings

    transport = httpx.ASGITransport(app=app)

    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://ddf.test",
        ) as client:
            yield client
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_health_endpoint(
    test_db: AsyncSession,
) -> None:
    marker = uuid.uuid4().hex[:8]

    async with api_client(
        test_db,
        sponsor=f"user:health-{marker}@example.com",
    ) as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_missing_authority_returns_structured_error(
    test_db: AsyncSession,
) -> None:
    marker = uuid.uuid4().hex[:8]
    missing_id = f"ddf:authority:{uuid.uuid4().hex[:12]}"

    async with api_client(
        test_db,
        sponsor=f"user:alice-{marker}@example.com",
    ) as client:
        response = await client.post(
            "/v1/authorize",
            json={
                "actor": f"agent:buyer-{marker}",
                "action": "purchase",
                "resource": "vendor/dell/order/missing",
                "purpose": "procurement",
                "authority_id": missing_id,
                "context": {},
            },
        )

    assert response.status_code == 404

    body = response.json()

    assert body["error"]["code"] == "AUTHORITY_NOT_FOUND"
    assert body["error"]["details"]["authority_id"] == missing_id


@pytest.mark.asyncio
async def test_delegation_amount_expansion_rejected(
    test_db: AsyncSession,
) -> None:
    marker = uuid.uuid4().hex[:8]

    sponsor = f"user:alice-{marker}@example.com"
    planner = f"agent:planner-{marker}"
    buyer = f"agent:buyer-{marker}"

    async with api_client(
        test_db,
        sponsor=sponsor,
    ) as client:
        grant = await client.post(
            "/v1/grants",
            json={
                "actor": planner,
                "actions": ["purchase"],
                "resources": ["vendor/*"],
                "purposes": ["procurement"],
                "constraints": {
                    "max_amount": 2000,
                    "currency": "GBP",
                },
                "expires_in_hours": 24,
            },
        )

        assert grant.status_code == 200, grant.text

        parent_id = grant.json()["authority"]["authority_id"]

        response = await client.post(
            f"/v1/delegations/{parent_id}",
            json={
                "delegated_to": buyer,
                "actions": ["purchase"],
                "resources": ["vendor/dell/*"],
                "purposes": ["procurement"],
                "constraints": {
                    "max_amount": 20000,
                    "currency": "GBP",
                },
            },
        )

    assert response.status_code == 400
    assert "ATTENUATION" in str(response.json()).upper()


@pytest.mark.asyncio
async def test_authority_lifecycle_via_http(
    test_db: AsyncSession,
) -> None:
    marker = uuid.uuid4().hex[:8]

    sponsor = f"user:alice-{marker}@example.com"
    planner = f"agent:planner-{marker}"
    buyer = f"agent:buyer-{marker}"

    async with api_client(
        test_db,
        sponsor=sponsor,
    ) as client:
        grant = await client.post(
            "/v1/grants",
            json={
                "actor": planner,
                "actions": ["purchase"],
                "resources": ["vendor/*"],
                "purposes": ["procurement"],
                "constraints": {
                    "max_amount": 10000,
                    "currency": "GBP",
                    "geographies": ["GB"],
                },
                "expires_in_hours": 24,
                "reason": "API integration test",
            },
        )

        assert grant.status_code == 200, grant.text

        parent = grant.json()["authority"]
        parent_id = parent["authority_id"]

        assert parent["actor"] == planner
        assert parent["sponsor"] == sponsor

        delegated = await client.post(
            f"/v1/delegations/{parent_id}",
            json={
                "delegated_to": buyer,
                "actions": ["purchase"],
                "resources": ["vendor/dell/order/*"],
                "purposes": ["procurement"],
                "constraints": {
                    "max_amount": 2000,
                    "currency": "GBP",
                    "geographies": ["GB"],
                },
                "reason": "buyer order authority",
            },
        )

        assert delegated.status_code == 200, delegated.text

        child = delegated.json()["authority"]
        child_id = child["authority_id"]

        assert child["actor"] == buyer
        assert child["parent_authority_id"] == parent_id

        allowed = await client.post(
            "/v1/authorize",
            json={
                "actor": buyer,
                "action": "purchase",
                "resource": "vendor/dell/order/9281",
                "purpose": "procurement",
                "authority_id": child_id,
                "context": {
                    "amount": 1500,
                    "currency": "GBP",
                    "geography": "GB",
                },
            },
        )

        assert allowed.status_code == 200, allowed.text
        assert allowed.json()["decision"] == "ALLOW"

        denied = await client.post(
            "/v1/authorize",
            json={
                "actor": buyer,
                "action": "purchase",
                "resource": "vendor/dell/order/9281",
                "purpose": "procurement",
                "authority_id": child_id,
                "context": {
                    "amount": 20000,
                    "currency": "GBP",
                    "geography": "GB",
                },
            },
        )

        assert denied.status_code == 200, denied.text
        assert denied.json()["decision"] == "DENY"
        assert "AMOUNT_EXCEEDS_EFFECTIVE_AUTHORITY" in denied.json()["reasons"]

        audit = await client.get("/v1/audit/verify")

        assert audit.status_code == 200
        assert audit.json()["valid"] is True
        assert audit.json()["violations"] == []

        revoke = await client.post(
            "/v1/revocations",
            json={
                "authority_id": parent_id,
                "actor": sponsor,
                "reason": "integration test ancestor revoke",
                "cascades": True,
            },
        )

        assert revoke.status_code == 200, revoke.text

        status = await client.get(f"/v1/revocations/{child_id}")

        assert status.status_code == 200
        assert status.json()["revoked"] is False
        assert status.json()["effectively_revoked"] is True

        after_revoke = await client.post(
            "/v1/authorize",
            json={
                "actor": buyer,
                "action": "purchase",
                "resource": "vendor/dell/order/9281",
                "purpose": "procurement",
                "authority_id": child_id,
                "context": {
                    "amount": 1500,
                    "currency": "GBP",
                    "geography": "GB",
                },
            },
        )

        assert after_revoke.status_code == 403
        assert after_revoke.json()["error"]["code"] == "AUTHORITY_REVOKED"
