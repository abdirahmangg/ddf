"""Tests for declarative capability predicates and attenuation."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from ddf.authority.effective import EffectiveAuthority
from ddf.authority.models import AuthorityConstraints, AuthorizationRequest
from ddf.authority.predicates import PredicateEngine, PredicateError
from ddf.authorization.service import AuthorizationService


def test_predicate_engine_evaluates_nested_context_conditions() -> None:
    expression = {
        "all": [
            {"path": "context.environment", "op": "eq", "value": "staging"},
            {
                "any": [
                    {"path": "context.region", "op": "eq", "value": "us-east-1"},
                    {"path": "context.region", "op": "eq", "value": "us-west-2"},
                ]
            },
            {"not": {"path": "context.revoked", "op": "eq", "value": True}},
        ]
    }

    assert PredicateEngine.evaluate(
        expression,
        {"context": {"environment": "staging", "region": "us-east-1", "revoked": False}},
    )
    assert not PredicateEngine.evaluate(
        expression,
        {"context": {"environment": "production", "region": "us-east-1", "revoked": False}},
    )


def test_predicate_engine_fails_on_invalid_or_incompatible_expressions() -> None:
    with pytest.raises(PredicateError, match="unsupported predicate operator"):
        PredicateEngine.validate({"path": "context.role", "op": "matches", "value": ".*"})

    with pytest.raises(PredicateError, match="incompatible values"):
        PredicateEngine.evaluate(
            {"path": "context.count", "op": "gt", "value": 2},
            {"context": {"count": "many"}},
        )


def test_authority_constraints_prove_parent_conjuncts_and_merge_effective_scope() -> None:
    parent = AuthorityConstraints(
        predicates={
            "all": [{"path": "context.tenant", "op": "eq", "value": "tenant-7"}],
        }
    )
    child = AuthorityConstraints(
        predicates={
            "all": [
                {"path": "context.tenant", "op": "eq", "value": "tenant-7"},
                {"path": "context.read_only", "op": "eq", "value": True},
            ],
        }
    )
    expanded = AuthorityConstraints(
        predicates={
            "all": [{"path": "context.read_only", "op": "eq", "value": True}],
        }
    )

    assert PredicateEngine.is_attenuated(child.predicates, parent.predicates)
    assert not PredicateEngine.is_attenuated(expanded.predicates, parent.predicates)
    effective = PredicateEngine.combine(parent.predicates, child.predicates)
    assert effective == child.predicates


def test_authorization_service_evaluates_dynamic_request_context() -> None:
    effective = EffectiveAuthority(
        actor="urn:agent:worker",
        sponsor="did:key:z6Mksponsor",
        actions=["execute"],
        resources=["urn:mcp:tools:sql_query"],
        purposes=["service"],
        constraints=AuthorityConstraints(
            predicates={
                "all": [
                    {"path": "target_namespace", "op": "eq", "value": "mcp"},
                    {"path": "context.tenant", "op": "eq", "value": "tenant-7"},
                ]
            }
        ),
        authority_path=["did:key:z6Mksponsor", "urn:agent:worker"],
        authority_ids=["grant-1"],
        valid_until=datetime.now(UTC) + timedelta(hours=1),
        holder_public_key="",
    )
    request = AuthorizationRequest(
        actor="urn:agent:worker",
        action="execute",
        resource="urn:mcp:tools:sql_query",
        purpose="service",
        authority_id="grant-1",
        target_namespace="mcp",
        context={"tenant": "tenant-7"},
    )
    reasons: list[str] = []
    details: dict[str, Any] = {}

    AuthorizationService._evaluate_predicates(
        request=request,
        effective=effective,
        reasons=reasons,
        details=details,
    )
    assert reasons == []

    request.context["tenant"] = "tenant-8"
    AuthorizationService._evaluate_predicates(
        request=request,
        effective=effective,
        reasons=reasons,
        details=details,
    )
    assert reasons == ["capability_predicate_not_satisfied"]
