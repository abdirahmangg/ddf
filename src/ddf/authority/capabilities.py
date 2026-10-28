"""Evaluation and attenuation algebra for universal DDF capabilities."""

from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ddf.authority.models import CANONICAL_OPERATIONS, UniversalDDFCapabilityAssertion
from ddf.authority.predicates import PredicateEngine, PredicateError
from ddf.authority.resources import ResourceHierarchy
from ddf.authority.runtime_posture import EATVerifier


class CapabilityAccessRequest(BaseModel):
    """A sector-neutral request against a universal capability assertion."""

    subject: str
    target_namespace: str
    target_resource: str
    operation: str
    context: dict[str, Any] = Field(default_factory=dict)
    runtime_context: dict[str, Any] = Field(default_factory=dict)
    eat_token: str | None = None

    @field_validator("subject", "target_resource")
    @classmethod
    def validate_uri_identifiers(cls, value: str) -> str:
        if not urlsplit(value).scheme or any(character.isspace() for character in value):
            raise ValueError("subject and target_resource must be valid URIs")
        return value

    @field_validator("target_namespace")
    @classmethod
    def validate_namespace(cls, value: str) -> str:
        if not value:
            raise ValueError("target_namespace cannot be empty")
        return value

    @field_validator("operation")
    @classmethod
    def validate_operation(cls, value: str) -> str:
        if value not in CANONICAL_OPERATIONS:
            raise ValueError(f"unsupported canonical operation: {value}")
        return value

    model_config = ConfigDict(extra="forbid")


class CapabilityEvaluationResult(BaseModel):
    """Deterministic result of capability evaluation."""

    allowed: bool
    reasons: list[str]

    model_config = ConfigDict(extra="forbid")


class CapabilityEvaluator:
    """Apply universal capability matching and sound predicate attenuation."""

    @staticmethod
    def authorize(
        assertion: UniversalDDFCapabilityAssertion,
        request: CapabilityAccessRequest,
        *,
        runtime_verifier: EATVerifier | None = None,
    ) -> CapabilityEvaluationResult:
        reasons: list[str] = []
        capability = assertion.capability
        posture = (runtime_verifier or EATVerifier.from_env()).verify(
            token=request.eat_token,
            runtime_context=request.runtime_context,
        )
        reasons.extend(posture.reasons)

        if request.subject != assertion.subject:
            reasons.append("subject_mismatch")
        if request.target_namespace != capability.target_namespace:
            reasons.append("namespace_mismatch")
        if request.operation not in capability.operations:
            reasons.append("operation_not_permitted")
        if not ResourceHierarchy.is_narrower_or_equal(
            request.target_resource,
            capability.target_resource,
        ):
            reasons.append("resource_not_permitted")

        if capability.constraints:
            environment = {
                "subject": request.subject,
                "target_namespace": request.target_namespace,
                "target_resource": request.target_resource,
                "operation": request.operation,
                "context": request.context,
                "runtime_context": request.runtime_context,
                "posture_score": posture.posture_score,
            }
            if not PredicateEngine.evaluate(capability.constraints, environment):
                reasons.append("capability_predicate_not_satisfied")

        return CapabilityEvaluationResult(allowed=not reasons, reasons=reasons)

    @staticmethod
    def is_attenuated(
        parent: UniversalDDFCapabilityAssertion,
        child: UniversalDDFCapabilityAssertion,
    ) -> CapabilityEvaluationResult:
        """Check child authority is a provable subset of parent authority."""
        reasons: list[str] = []
        parent_capability = parent.capability
        child_capability = child.capability

        if child.issuer != parent.subject:
            reasons.append("issuer_subject_link_mismatch")
        if child_capability.target_namespace != parent_capability.target_namespace:
            reasons.append("namespace_expansion")
        if not set(child_capability.operations).issubset(parent_capability.operations):
            reasons.append("operation_expansion")
        if not ResourceHierarchy.is_narrower_or_equal(
            child_capability.target_resource,
            parent_capability.target_resource,
        ):
            reasons.append("resource_expansion")
        if not CapabilityEvaluator._constraints_are_attenuated(
            parent_capability.constraints,
            child_capability.constraints,
        ):
            reasons.append("constraint_expansion_or_unprovable")

        return CapabilityEvaluationResult(allowed=not reasons, reasons=reasons)

    @staticmethod
    def attenuation_chain_valid(
        assertions: list[UniversalDDFCapabilityAssertion],
    ) -> CapabilityEvaluationResult:
        """Validate issuer links and attenuation from root assertion to leaf."""
        if not assertions:
            return CapabilityEvaluationResult(allowed=False, reasons=["empty_assertion_chain"])
        for index in range(1, len(assertions)):
            result = CapabilityEvaluator.is_attenuated(assertions[index - 1], assertions[index])
            if not result.allowed:
                return CapabilityEvaluationResult(
                    allowed=False,
                    reasons=[f"delegation_{index}:{reason}" for reason in result.reasons],
                )
        return CapabilityEvaluationResult(allowed=True, reasons=[])

    @staticmethod
    def _constraints_are_attenuated(
        parent: dict[str, Any],
        child: dict[str, Any],
    ) -> bool:
        if not parent:
            return True
        if not child:
            return False
        try:
            return PredicateEngine.is_attenuated(child, parent)
        except PredicateError:
            return False
