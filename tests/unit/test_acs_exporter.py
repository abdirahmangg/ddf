"""Tests for the ACS Guardian hook event exporter."""

from typing import Any

import pytest

from ddf.provenance.acs_exporter import ACSExporter, ACSHookType


@pytest.mark.parametrize(
    "hook_type",
    [
        "toolCallBefore",
        "toolCallResult",
        "subagentStart",
        "subagentStop",
    ],
)
def test_acs_hook_envelope_preserves_parent_request_correlation(hook_type: ACSHookType) -> None:
    event = ACSExporter.envelope(
        hook_type,
        request_id="child-request",
        request_id_ref="parent-request",
        data={"subject": "urn:agent:child"},
    )

    payload = event.model_dump(mode="json")
    assert payload["jsonrpc"] == "2.0"
    assert payload["method"] == hook_type
    assert payload["params"]["request_id"] == "child-request"
    assert payload["params"]["request_id_ref"] == "parent-request"
    assert payload["params"]["source"] == "ddf"
    assert payload["params"]["schema_version"] == "acs-core/0.2"
    assert isinstance(payload["id"], str)


def test_authorization_event_exports_attenuation_and_posture() -> None:
    event = ACSExporter.authorization_event(
        event_type="toolCallBefore",
        request_id="request-1",
        request_id_ref=None,
        subject="urn:agent:worker",
        target_namespace="mcp",
        target_resource="urn:mcp:tools:sql_query",
        operation="execute",
        allowed=False,
        reasons=["posture_below_threshold"],
        grant_id="grant-1",
        posture_score=0.4,
        attenuation_chain=["grant-0", "grant-1"],
    )

    assert event.params.data["decision"] == "deny"
    assert event.params.data["posture_score"] == 0.4
    assert event.params.data["attenuation_chain"] == ["grant-0", "grant-1"]


def test_subagent_events_bind_to_the_parent_request() -> None:
    event = ACSExporter.subagent_event(
        event_type="subagentStart",
        request_id="child-request",
        request_id_ref="parent-request",
        parent_subject="urn:agent:parent",
        child_subject="urn:agent:child",
        grant_id="grant-child",
        attenuation_chain=["grant-root", "grant-child"],
    )

    assert event.request_id_ref == "parent-request"
    assert event.params.data["parent_subject"] == "urn:agent:parent"
    assert event.params.data["child_subject"] == "urn:agent:child"


def test_tool_result_event_keeps_result_and_posture_data() -> None:
    event = ACSExporter.tool_result_event(
        request_id="request-1",
        request_id_ref="parent-request",
        subject="urn:agent:worker",
        grant_id="grant-1",
        outcome="success",
        result={"rows_returned": 1},
        posture_score=0.93,
    )

    assert event.method == "toolCallResult"
    assert event.request_id_ref == "parent-request"
    assert event.params.data["result"] == {"rows_returned": 1}
    assert event.params.data["posture_score"] == 0.93


@pytest.mark.asyncio
async def test_export_requires_a_configured_sink_and_delivers_envelope() -> None:
    event = ACSExporter.envelope(
        "toolCallResult",
        request_id="request-1",
        data={"decision": "allow"},
    )
    with pytest.raises(RuntimeError, match="sink is not configured"):
        await ACSExporter().export(event)

    observed: list[dict[str, Any]] = []

    async def sink(payload: dict[str, Any]) -> None:
        observed.append(payload)

    payload = await ACSExporter(sink).export(event)
    assert observed == [payload]
