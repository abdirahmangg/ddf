from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from ddf.commercial.production_readiness import (
    BodyLimitMiddleware,
    authorize_remote_intent,
    build_evidence_bundle,
    capability_caller_allowed,
    validate_production_environment,
    verify_evidence_bundle,
)


def test_production_guard_rejects_unsafe_configuration(
    monkeypatch,
):
    monkeypatch.setenv(
        "DDF_ENVIRONMENT",
        "production",
    )

    monkeypatch.setenv(
        "DDF_REQUIRE_TLS",
        "false",
    )

    monkeypatch.delenv(
        "DDF_REDIS_URL",
        raising=False,
    )

    monkeypatch.setenv(
        "DATABASE_URL",
        "sqlite:///unsafe.db",
    )

    monkeypatch.setenv(
        "DDF_BOOTSTRAP_TOKEN",
        "short",
    )

    with pytest.raises(
        RuntimeError,
        match="unsafe production configuration",
    ):
        validate_production_environment()


def test_capability_broker_is_disabled_by_default(
    monkeypatch,
):
    monkeypatch.delenv(
        "DDF_ENABLE_CAPABILITY_BROKERS",
        raising=False,
    )

    principal = SimpleNamespace(
        subject="broker-a",
        roles=[
            "capability_broker",
        ],
    )

    assert not capability_caller_allowed(
        principal,
        "agent:buyer",
    )


def test_capability_broker_requires_explicit_actor_policy(
    monkeypatch,
):
    monkeypatch.setenv(
        "DDF_ENABLE_CAPABILITY_BROKERS",
        "true",
    )

    monkeypatch.setenv(
        "DDF_CAPABILITY_BROKER_POLICY",
        json.dumps(
            {
                "broker-a": [
                    "agent:procurement-*",
                ]
            }
        ),
    )

    principal = SimpleNamespace(
        subject="broker-a",
        roles=[
            "capability_broker",
        ],
    )

    assert capability_caller_allowed(
        principal,
        "agent:procurement-7",
    )

    assert not capability_caller_allowed(
        principal,
        "agent:finance-7",
    )


def test_actor_can_always_mint_for_self():
    principal = SimpleNamespace(
        subject="agent:buyer",
        roles=[],
    )

    assert capability_caller_allowed(
        principal,
        "agent:buyer",
    )


def test_remote_intent_is_reauthorized_deterministically():
    allowed = authorize_remote_intent(
        {
            "action": "purchase",
            "resource": "vendor/dell/order/9281",
            "purpose": "procurement",
        },
        allowed_actions=[
            "purchase",
        ],
        allowed_resources=[
            "vendor/dell/*",
        ],
        allowed_purposes=[
            "procurement",
        ],
    )

    assert allowed["action"] == "purchase"

    with pytest.raises(
        PermissionError,
    ):
        authorize_remote_intent(
            {
                "action": "delete",
                "resource": "vendor/dell/order/9281",
                "purpose": "procurement",
            },
            allowed_actions=[
                "purchase",
            ],
            allowed_resources=[
                "vendor/dell/*",
            ],
            allowed_purposes=[
                "procurement",
            ],
        )


def test_evidence_bundle_offline_verifier_detects_tamper():
    bundle = build_evidence_bundle(
        tenant_id="tenant-a",
        records=[
            {
                "event": "authority_created",
                "value": 1,
            }
        ],
    )

    assert verify_evidence_bundle(
        bundle
    )

    bundle["records"][0][
        "value"
    ] = 2

    assert not verify_evidence_bundle(
        bundle
    )


@pytest.mark.asyncio
async def test_body_limit_rejects_streamed_oversize_request():
    called = False

    async def app(
        scope,
        receive,
        send,
    ):
        nonlocal called
        called = True

    middleware = BodyLimitMiddleware(
        app,
        max_bytes=5,
    )

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/commercial/test",
        "headers": [],
    }

    queue = [
        {
            "type": "http.request",
            "body": b"123",
            "more_body": True,
        },
        {
            "type": "http.request",
            "body": b"456",
            "more_body": False,
        },
    ]

    sent = []

    async def receive():
        return queue.pop(0)

    async def send(message):
        sent.append(message)

    await middleware(
        scope,
        receive,
        send,
    )

    assert not called

    assert sent[0][
        "status"
    ] == 413
