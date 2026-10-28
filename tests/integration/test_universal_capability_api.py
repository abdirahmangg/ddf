"""HTTP integration tests for signed v0.2 capability workflows."""

import base64
import hashlib
import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from nacl.signing import SigningKey
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ddf.api.dependencies import get_db_session
from ddf.api.routes.universal_capabilities import router
from ddf.authority.models import Capability, UniversalDDFCapabilityAssertion
from ddf.authority.revocation import DatabaseRevocationRegistry
from ddf.crypto.signing import Ed25519Key
from ddf.db.models import Base, CapabilityRevocation, UniversalAssertionRecord
from ddf.policy.openfga import OpenFGAPolicy

EAT_ISSUER = "did:key:eat-issuer"


class MemorySession:
    """Small async-session stand-in for endpoint persistence tests."""

    def __init__(self) -> None:
        self.records: dict[str, UniversalAssertionRecord] = {}

    async def get(self, model: type, key: str) -> UniversalAssertionRecord | None:
        if model is not UniversalAssertionRecord:
            return None
        return self.records.get(key)

    def add(self, record: UniversalAssertionRecord) -> None:
        self.records[record.grant_id] = record

    async def commit(self) -> None:
        return

    async def rollback(self) -> None:
        return


@asynccontextmanager
async def client_for(session: MemorySession) -> AsyncIterator[httpx.AsyncClient]:
    app = FastAPI()
    app.include_router(router)

    async def override_session() -> AsyncIterator[MemorySession]:
        yield session

    app.dependency_overrides[get_db_session] = override_session
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://ddf.test",
    ) as client:
        yield client


def signed_assertion(
    *,
    issuer: str,
    subject: str,
    resource: str,
    operations: list[str],
    constraints: dict[str, Any] | None = None,
) -> tuple[UniversalDDFCapabilityAssertion, Ed25519Key]:
    key = Ed25519Key(SigningKey.generate())
    assertion = UniversalDDFCapabilityAssertion(
        grant_id=str(uuid4()),
        issuer=issuer,
        subject=subject,
        capability=Capability(
            target_namespace="mcp",
            target_resource=resource,
            operations=operations,
            constraints=constraints or {},
        ),
    )
    return assertion, key


def signed_body(
    assertion: UniversalDDFCapabilityAssertion,
    key: Ed25519Key,
) -> dict[str, Any]:
    return {
        "assertion": assertion.model_dump(mode="json"),
        "proof": key.sign_assertion(assertion).model_dump(mode="json"),
    }


def eat_token(
    signing_key: Ed25519PrivateKey,
    runtime_context: dict[str, Any],
    *,
    posture_score: float = 0.95,
) -> str:
    now = int(time.time())
    context_hash = hashlib.sha256(
        json.dumps(
            runtime_context,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    return jwt.encode(
        {
            "iss": EAT_ISSUER,
            "iat": now,
            "exp": now + 300,
            "ueid": "test-enclave",
            "nonce": "request-123",
            "ddf_hardware_enclave": True,
            "ddf_posture_score": posture_score,
            "ddf_runtime_context_hash": context_hash,
        },
        signing_key,
        algorithm="EdDSA",
    )


@pytest.mark.asyncio
async def test_signed_root_grant_delegation_and_eat_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_issuer = "did:key:z6Mksponsor"
    planner = "urn:agent:planner"
    worker = "urn:agent:worker"
    issuer_key = Ed25519Key(SigningKey.generate())
    planner_key = Ed25519Key(SigningKey.generate())
    eat_private_key = Ed25519PrivateKey.generate()
    trusted_capability_keys = {
        root_issuer: {
            "key_id": issuer_key.key_id,
            "public_key": issuer_key.verify_key_b64,
        },
        planner: {
            "key_id": planner_key.key_id,
            "public_key": planner_key.verify_key_b64,
        },
    }
    eat_public_key = eat_private_key.public_key().public_bytes_raw()
    monkeypatch.setenv(
        "DDF_CAPABILITY_TRUSTED_KEYS",
        json.dumps(trusted_capability_keys),
    )
    monkeypatch.setenv(
        "DDF_EAT_TRUSTED_KEYS",
        json.dumps(
            {
                EAT_ISSUER: base64.b64encode(eat_public_key).decode("ascii"),
            }
        ),
    )
    runtime_context = {"enclave": "test-tee", "measurement": "sha256:abc"}
    root, _ = signed_assertion(
        issuer=root_issuer,
        subject=planner,
        resource="urn:mcp:tools/*",
        operations=["execute", "read"],
        constraints={
            "all": [
                {"path": "context.tenant", "op": "eq", "value": "tenant-7"},
            ]
        },
    )
    child, _ = signed_assertion(
        issuer=planner,
        subject=worker,
        resource="urn:mcp:tools/sql_query",
        operations=["execute"],
        constraints={
            "all": [
                {"path": "context.tenant", "op": "eq", "value": "tenant-7"},
                {"path": "context.read_only", "op": "eq", "value": True},
            ]
        },
    )
    root_signed_body = signed_body(root, issuer_key)
    child_signed_body = signed_body(child, planner_key)
    session = MemorySession()

    async with client_for(session) as client:
        created = await client.post("/v2/grants", json=root_signed_body)
        assert created.status_code == 200, created.text

        delegated = await client.post(
            f"/v2/delegations/{root.grant_id}",
            json={"child": child_signed_body},
        )
        assert delegated.status_code == 200, delegated.text

        authorized = await client.post(
            "/v2/authorize",
            json={
                "grant_id": child.grant_id,
                "request": {
                    "subject": worker,
                    "target_namespace": "mcp",
                    "target_resource": "urn:mcp:tools/sql_query",
                    "operation": "execute",
                    "context": {"tenant": "tenant-7", "read_only": True},
                    "runtime_context": runtime_context,
                    "eat_token": eat_token(eat_private_key, runtime_context),
                },
            },
        )

    assert len(session.records) == 2
    assert session.records[child.grant_id].parent_grant_id == root.grant_id
    assert authorized.status_code == 200, authorized.text
    assert authorized.json() == {"allowed": True, "reasons": []}


@pytest.mark.asyncio
async def test_v2_endpoints_reject_legacy_and_unknown_fields() -> None:
    async with client_for(MemorySession()) as client:
        grant = await client.post(
            "/v2/grants",
            json={
                "assertion": {
                    "grant_id": str(uuid4()),
                    "issuer": "did:key:z6Mkissuer",
                    "subject": "urn:agent:worker",
                    "purpose": "procurement",
                    "capability": {
                        "target_namespace": "mcp",
                        "target_resource": "urn:mcp:tools/sql_query",
                        "operations": ["purchase"],
                        "constraints": {},
                    },
                },
                "proof": {},
            },
        )
        authorization = await client.post(
            "/v2/authorize",
            json={
                "grant_id": str(uuid4()),
                "purpose": "procurement",
                "request": {},
            },
        )

    assert grant.status_code == 422
    assert authorization.status_code == 422


@pytest.mark.asyncio
async def test_v1_authorization_is_gone_without_compatibility_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ddf.main import create_app

    monkeypatch.delenv("DDF_V01_COMPATIBILITY_ENABLED", raising=False)
    app = create_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://ddf.test",
    ) as client:
        legacy_requests = [
            (
                "/v1/authorize",
                {
                    "actor": "agent:buyer",
                    "action": "purchase",
                    "resource": "vendor/dell/order/1",
                    "purpose": "procurement",
                    "authority_id": "legacy-authority",
                },
            ),
            ("/v1/grants", {"actor": "agent:buyer", "actions": ["purchase"]}),
            (
                "/v1/delegations/legacy-authority",
                {"delegated_to": "agent:worker", "actions": ["purchase"]},
            ),
        ]
        responses = [await client.post(path, json=body) for path, body in legacy_requests]

    assert [response.status_code for response in responses] == [410, 410, 410]


@pytest.mark.asyncio
async def test_low_posture_revokes_persisted_capability_subtree(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    class RecordingOpenFGA:
        enabled = True

        def __init__(self) -> None:
            self.deleted: list[tuple[str, str, str]] = []

        async def delete_capability_tuple(
            self,
            *,
            principal: str,
            target_namespace: str,
            target_resource: str,
        ) -> None:
            self.deleted.append((principal, target_namespace, target_resource))

    openfga = RecordingOpenFGA()

    def fake_openfga_from_env(cls: type[OpenFGAPolicy]) -> RecordingOpenFGA:
        del cls
        return openfga

    monkeypatch.setattr(
        OpenFGAPolicy,
        "from_env",
        classmethod(fake_openfga_from_env),
    )
    root_issuer = "did:key:z6Mksponsor"
    planner = "urn:agent:posture-planner"
    worker = "urn:agent:posture-worker"
    issuer_key = Ed25519Key(SigningKey.generate())
    planner_key = Ed25519Key(SigningKey.generate())
    eat_private_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "DDF_CAPABILITY_TRUSTED_KEYS",
        json.dumps(
            {
                root_issuer: {
                    "key_id": issuer_key.key_id,
                    "public_key": issuer_key.verify_key_b64,
                },
                planner: {
                    "key_id": planner_key.key_id,
                    "public_key": planner_key.verify_key_b64,
                },
            }
        ),
    )
    monkeypatch.setenv(
        "DDF_EAT_TRUSTED_KEYS",
        json.dumps(
            {
                EAT_ISSUER: base64.b64encode(
                    eat_private_key.public_key().public_bytes_raw()
                ).decode("ascii"),
            }
        ),
    )
    runtime_context = {"enclave": "test-tee", "measurement": "sha256:abc"}
    root, _ = signed_assertion(
        issuer=root_issuer,
        subject=planner,
        resource="urn:mcp:tools/*",
        operations=["execute"],
    )
    child, _ = signed_assertion(
        issuer=planner,
        subject=worker,
        resource="urn:mcp:tools/sql_query",
        operations=["execute"],
    )

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'posture.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    app = FastAPI()
    app.include_router(router)

    async def override_session():
        async with maker() as session:
            yield session

    app.dependency_overrides[get_db_session] = override_session
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://ddf.test",
        ) as client:
            created = await client.post("/v2/grants", json=signed_body(root, issuer_key))
            delegated = await client.post(
                f"/v2/delegations/{root.grant_id}",
                json={"child": signed_body(child, planner_key)},
            )
            assert created.status_code == 200, created.text
            assert delegated.status_code == 200, delegated.text

            denied = await client.post(
                "/v2/authorize",
                json={
                    "grant_id": child.grant_id,
                    "request": {
                        "subject": worker,
                        "target_namespace": "mcp",
                        "target_resource": "urn:mcp:tools:sql_query",
                        "operation": "execute",
                        "runtime_context": runtime_context,
                        "eat_token": eat_token(
                            eat_private_key,
                            runtime_context,
                            posture_score=0.4,
                        ),
                    },
                },
            )
            assert denied.status_code == 200
            assert denied.json()["allowed"] is False
            assert "posture_below_threshold" in denied.json()["reasons"]

            async with maker() as session:
                status_rows = (
                    await session.execute(
                        select(CapabilityRevocation.grant_id).where(
                            CapabilityRevocation.grant_id == child.grant_id
                        )
                    )
                ).scalars().all()
                assert status_rows == [child.grant_id]
                assert not (
                    await DatabaseRevocationRegistry(session).check_status(root.grant_id)
                ).revoked
                assert (await DatabaseRevocationRegistry(session).check_status(child.grant_id)).revoked
            assert openfga.deleted == [
                (worker, "mcp", "urn:mcp:tools/sql_query")
            ]

            denied_again = await client.post(
                "/v2/authorize",
                json={
                    "grant_id": child.grant_id,
                    "request": {
                        "subject": worker,
                        "target_namespace": "mcp",
                        "target_resource": "urn:mcp:tools:sql_query",
                        "operation": "execute",
                        "runtime_context": runtime_context,
                        "eat_token": eat_token(eat_private_key, runtime_context),
                    },
                },
            )
            assert denied_again.status_code == 403
    finally:
        await engine.dispose()
