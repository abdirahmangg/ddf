"""Export DDF security events as JSON-RPC 2.0 ACS Guardian calls."""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

ACSHookType = Literal["toolCallBefore", "toolCallResult", "subagentStart", "subagentStop"]
EventSink = Callable[[dict[str, Any]], Awaitable[None]]


class ACSHookParams(BaseModel):
    """ACS metadata and DDF event payload carried by a JSON-RPC call."""

    schema_version: Literal["acs-core/0.2"] = "acs-core/0.2"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: Literal["ddf"] = "ddf"
    request_id: str
    request_id_ref: str | None = None
    data: dict[str, Any]

    model_config = ConfigDict(extra="forbid")


class ACSEventEnvelope(BaseModel):
    """JSON-RPC 2.0 method call envelope for an ACS Guardian hook."""

    jsonrpc: Literal["2.0"] = "2.0"
    id: str = Field(default_factory=lambda: str(uuid4()))
    method: ACSHookType
    params: ACSHookParams

    model_config = ConfigDict(extra="forbid")

    @property
    def event_type(self) -> ACSHookType:
        """Return the ACS hook name represented by the JSON-RPC method."""
        return self.method

    @property
    def request_id(self) -> str:
        """Return the DDF request identifier."""
        return self.params.request_id

    @property
    def request_id_ref(self) -> str | None:
        """Return the parent DDF request identifier, if present."""
        return self.params.request_id_ref

    @property
    def data(self) -> dict[str, Any]:
        """Return the application data carried by the JSON-RPC params."""
        return self.params.data


class ACSExporter:
    """Build and optionally deliver ACS-compatible Guardian hook calls."""

    def __init__(self, sink: EventSink | None = None) -> None:
        self._sink = sink

    @staticmethod
    def envelope(
        event_type: ACSHookType,
        *,
        request_id: str,
        request_id_ref: str | None = None,
        data: dict[str, Any],
    ) -> ACSEventEnvelope:
        """Create a validated JSON-RPC call with explicit parent correlation."""
        if not request_id.strip():
            raise ValueError("request_id cannot be empty")
        if request_id_ref is not None and not request_id_ref.strip():
            raise ValueError("request_id_ref cannot be empty")
        return ACSEventEnvelope(
            method=event_type,
            params=ACSHookParams(
                request_id=request_id,
                request_id_ref=request_id_ref,
                data=data,
            ),
        )

    @classmethod
    def authorization_event(
        cls,
        *,
        event_type: Literal["toolCallBefore", "toolCallResult"],
        request_id: str,
        request_id_ref: str | None,
        subject: str,
        target_namespace: str,
        target_resource: str,
        operation: str,
        allowed: bool,
        reasons: list[str],
        grant_id: str,
        posture_score: float | None = None,
        attenuation_chain: list[str] | None = None,
    ) -> ACSEventEnvelope:
        """Format a DDF capability authorization and posture decision."""
        return cls.envelope(
            event_type,
            request_id=request_id,
            request_id_ref=request_id_ref,
            data={
                "subject": subject,
                "target_namespace": target_namespace,
                "target_resource": target_resource,
                "operation": operation,
                "decision": "allow" if allowed else "deny",
                "reasons": list(reasons),
                "grant_id": grant_id,
                "posture_score": posture_score,
                "attenuation_chain": list(attenuation_chain or []),
            },
        )

    @classmethod
    def tool_result_event(
        cls,
        *,
        request_id: str,
        request_id_ref: str | None,
        subject: str,
        grant_id: str,
        outcome: str,
        result: dict[str, Any] | None = None,
        posture_score: float | None = None,
    ) -> ACSEventEnvelope:
        """Format the result of a tool invocation for the Guardian hook."""
        return cls.envelope(
            "toolCallResult",
            request_id=request_id,
            request_id_ref=request_id_ref,
            data={
                "subject": subject,
                "grant_id": grant_id,
                "outcome": outcome,
                "result": result,
                "posture_score": posture_score,
            },
        )

    @classmethod
    def subagent_event(
        cls,
        *,
        event_type: Literal["subagentStart", "subagentStop"],
        request_id: str,
        request_id_ref: str,
        parent_subject: str,
        child_subject: str,
        grant_id: str,
        attenuation_chain: list[str],
        outcome: str | None = None,
    ) -> ACSEventEnvelope:
        """Format a lifecycle hook linked to the parent request."""
        data: dict[str, Any] = {
            "parent_subject": parent_subject,
            "child_subject": child_subject,
            "grant_id": grant_id,
            "attenuation_chain": list(attenuation_chain),
        }
        if outcome is not None:
            data["outcome"] = outcome
        return cls.envelope(
            event_type,
            request_id=request_id,
            request_id_ref=request_id_ref,
            data=data,
        )

    async def export(self, event: ACSEventEnvelope) -> dict[str, Any]:
        """Deliver an event to the configured sink and return its JSON form."""
        payload = event.model_dump(mode="json")
        if self._sink is None:
            raise RuntimeError("ACS event sink is not configured")
        await self._sink(payload)
        return payload
