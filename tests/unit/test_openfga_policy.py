"""Tests for OpenFGA relationship checks."""

import json
from pathlib import Path

import httpx
import pytest

from ddf.policy.openfga import OpenFGAPolicy


def test_core_openfga_model_uses_a_generic_resource_relation():
    model = json.loads(Path("openfga/model.json").read_text())
    assert any(item["type"] == "principal" for item in model["type_definitions"])
    resource = next(
        definition for definition in model["type_definitions"] if definition["type"] == "resource"
    )

    assert set(resource["relations"]) == {"subject", "member"}
    assert any(
        user_type.get("wildcard") == {}
        for user_type in resource["metadata"]["relations"]["subject"]["directly_related_user_types"]
    )


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


def test_universal_pei_and_resource_namespace_mapping() -> None:
    assert OpenFGAPolicy.principal_object("urn:agent:buyer") == "principal:urn:agent:buyer"
    assert (
        OpenFGAPolicy.resource_object(
            "aws",
            "arn:aws:s3:::example-bucket",
        )
        == "resource:aws:arn:aws:s3:::example-bucket"
    )
    assert OpenFGAPolicy.resource_candidates(
        "mcp",
        "urn:mcp:tools/sql_query",
    ) == [
        "resource:mcp:urn:mcp:tools/sql_query",
        "resource:mcp:urn:mcp:tools/*",
        "resource:mcp:urn:mcp:*",
        "resource:mcp:*",
    ]


@pytest.mark.asyncio
async def test_openfga_capability_check_falls_back_to_namespace_wildcard():
    checked_objects = []

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        checked_objects.append(body["tuple_key"]["object"])
        return httpx.Response(
            200,
            json={"allowed": body["tuple_key"]["object"] == "resource:mcp:*"},
        )

    policy = OpenFGAPolicy(
        enabled=True,
        api_url="http://openfga.test",
        store_id="store-1",
        transport=httpx.MockTransport(handler),
    )

    assert await policy.check_capability(
        principal="urn:agent:buyer",
        target_namespace="mcp",
        target_resource="urn:mcp:tools/sql_query",
    )
    assert checked_objects[-1] == "resource:mcp:*"
