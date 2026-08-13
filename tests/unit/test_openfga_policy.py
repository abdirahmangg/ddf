"""Tests for OpenFGA relationship checks."""

import json

import httpx
import pytest

from ddf.policy.openfga import OpenFGAPolicy


@pytest.mark.asyncio
async def test_disabled_openfga_allows_without_network():
    policy = OpenFGAPolicy(enabled=False)

    assert await policy.check(
        user="agent:buyer",
        relation="operator",
        object="resource:vendor/dell/order/1",
    )


@pytest.mark.asyncio
async def test_openfga_check_uses_remote_decision():
    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        body = json.loads(request.content)

        assert body["tuple_key"]["relation"] == "operator"

        return httpx.Response(
            200,
            json={"allowed": True},
        )

    transport = httpx.MockTransport(handler)

    policy = OpenFGAPolicy(
        enabled=True,
        api_url="http://openfga.test",
        store_id="store-1",
        authorization_model_id="model-1",
        transport=transport,
    )

    assert await policy.check(
        user="agent:buyer",
        relation="operator",
        object="resource:vendor/dell/order/1",
    )
