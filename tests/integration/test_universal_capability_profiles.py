"""Sector-profile integration coverage for the universal capability contract."""

import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.signing import SigningKey
from pydantic import ValidationError

from ddf.api.errors import SignatureVerificationError
from ddf.authority.capabilities import CapabilityAccessRequest, CapabilityEvaluator
from ddf.authority.models import Capability, UniversalDDFCapabilityAssertion
from ddf.authority.predicates import PredicateEngine
from ddf.authority.runtime_posture import EATVerifier
from ddf.crypto.signing import Ed25519Key, Verifier

PROFILES = [
    pytest.param(
        "mcp",
        "urn:mcp:tools:sql_query",
        ["execute"],
        {"tenant_id": "tenant-7"},
        {"all": [{"path": "context.tenant_id", "op": "eq", "value": "tenant-7"}]},
        id="mcp-tool-execution",
    ),
    pytest.param(
        "aws",
        "arn:aws:s3:::example-bucket",
        ["read"],
        {"environment": "staging", "region": "us-east-1"},
        {
            "all": [
                {"path": "context.environment", "op": "eq", "value": "staging"},
                {"path": "context.region", "op": "eq", "value": "us-east-1"},
            ]
        },
        id="aws-iam-resource",
    ),
    pytest.param(
        "kubernetes",
        "urn:k8s:namespace:staging/pods/*",
        ["write"],
        {"namespace": "staging", "service_account": "controller"},
        {
            "all": [
                {"path": "context.namespace", "op": "eq", "value": "staging"},
                {"path": "context.service_account", "op": "eq", "value": "controller"},
            ]
        },
        id="kubernetes-pod-management",
    ),
    pytest.param(
        "fhir",
        "urn:fhir:Patient/123/Observation",
        ["read"],
        {"release_basis": "treatment", "minimum_necessary": True},
        {
            "all": [
                {"path": "context.release_basis", "op": "eq", "value": "treatment"},
                {"path": "context.minimum_necessary", "op": "eq", "value": True},
            ]
        },
        id="fhir-hipaa-release",
    ),
    pytest.param(
        "ediscovery",
        "urn:ediscovery:case/123/document/456",
        ["read"],
        {"privilege_status": "non_privileged", "matter": "case-123"},
        {
            "all": [
                {
                    "path": "context.privilege_status",
                    "op": "eq",
                    "value": "non_privileged",
                },
                {"path": "context.matter", "op": "eq", "value": "case-123"},
            ]
        },
        id="ediscovery-privilege-filter",
    ),
]

EAT_ISSUER = "did:key:z6MkEATissuer"


def _runtime_evidence(
    runtime_context: dict[str, Any],
    *,
    posture_score: float = 0.95,
    issued_at: int | None = None,
) -> tuple[str, EATVerifier]:
    private_key = Ed25519PrivateKey.generate()
    issued_at = issued_at or int(time.time())
    context_hash = hashlib.sha256(
        json.dumps(
            runtime_context,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    token = jwt.encode(
        {
            "iss": EAT_ISSUER,
            "iat": issued_at,
            "exp": issued_at + 600,
            "ueid": "test-enclave",
            "nonce": "request-unique-nonce",
            "ddf_hardware_enclave": True,
            "ddf_posture_score": posture_score,
            "ddf_runtime_context_hash": context_hash,
        },
        private_key,
        algorithm="EdDSA",
    )
    public_key = private_key.public_key()
    return token, EATVerifier(trusted_issuers={EAT_ISSUER: public_key})


def test_published_schema_has_the_universal_required_shape() -> None:
    schema_file = Path(__file__).parents[2] / "schemas" / "universal-ddf-capability.schema.json"
    schema = json.loads(schema_file.read_text())
    capability = schema["properties"]["capability"]

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "UniversalDDFCapabilityAssertion"
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["grant_id", "issuer", "subject", "capability"]
    assert capability["required"] == [
        "target_namespace",
        "target_resource",
        "operations",
        "constraints",
    ]
    assert capability["properties"]["constraints"]["additionalProperties"] is True


def test_capability_operations_use_the_canonical_vocabulary() -> None:
    with pytest.raises(ValidationError, match="canonical"):
        Capability(
            target_namespace="mcp",
            target_resource="urn:mcp:tools:sql_query",
            operations=["purchase"],
            constraints={},
        )


@pytest.mark.parametrize(
    ("namespace", "resource", "operations", "context", "constraints"),
    PROFILES,
)
def test_namespace_profile_authorization(
    namespace: str,
    resource: str,
    operations: list[str],
    context: dict[str, Any],
    constraints: dict[str, Any],
) -> None:
    assertion = UniversalDDFCapabilityAssertion(
        grant_id=str(uuid4()),
        issuer="did:key:z6MkhaXgBZDvotDkL5P6QqQ2v5H7C5xjzZK7X5gYz5r6",
        subject="urn:agent:ddf:profile-test",
        capability=Capability(
            target_namespace=namespace,
            target_resource=resource,
            operations=operations,
            constraints=constraints,
        ),
    )

    assert assertion.capability.target_namespace == namespace
    assert assertion.capability.target_resource == resource
    runtime_context = {"enclave": "test-tee", "measurement": "sha256:abc"}
    eat_token, runtime_verifier = _runtime_evidence(runtime_context)
    result = CapabilityEvaluator.authorize(
        assertion,
        CapabilityAccessRequest(
            subject=assertion.subject,
            target_namespace=namespace,
            target_resource=resource.removesuffix("/*") + "/example"
            if resource.endswith("/*")
            else resource,
            operation=operations[0],
            context=context,
            runtime_context=runtime_context,
            eat_token=eat_token,
        ),
        runtime_verifier=runtime_verifier,
    )
    assert result.allowed


def test_runtime_posture_rejects_low_scores_stale_and_unbound_attestations() -> None:
    runtime_context = {"enclave": "test-tee"}
    low_score_token, verifier = _runtime_evidence(runtime_context, posture_score=0.4)
    assertion = UniversalDDFCapabilityAssertion(
        grant_id=str(uuid4()),
        issuer="did:key:z6Mkissuer",
        subject="urn:agent:posture-test",
        capability=Capability(
            target_namespace="mcp",
            target_resource="urn:mcp:tools:sql_query",
            operations=["execute"],
            constraints={},
        ),
    )
    request = CapabilityAccessRequest(
        subject=assertion.subject,
        target_namespace="mcp",
        target_resource="urn:mcp:tools:sql_query",
        operation="execute",
        runtime_context=runtime_context,
        eat_token=low_score_token,
    )

    low_score = CapabilityEvaluator.authorize(assertion, request, runtime_verifier=verifier)
    assert not low_score.allowed
    assert "posture_below_threshold" in low_score.reasons

    stale_token, stale_verifier = _runtime_evidence(
        runtime_context,
        issued_at=int(time.time()) - 600,
    )
    stale = CapabilityEvaluator.authorize(
        assertion,
        request.model_copy(update={"eat_token": stale_token}),
        runtime_verifier=stale_verifier,
    )
    assert not stale.allowed
    assert "attestation_stale" in stale.reasons

    unbound = CapabilityEvaluator.authorize(
        assertion,
        request.model_copy(update={"runtime_context": {"enclave": "other-tee"}}),
        runtime_verifier=verifier,
    )
    assert not unbound.allowed
    assert "runtime_context_unbound" in unbound.reasons


def test_parent_predicates_are_required_in_attenuated_child() -> None:
    parent = {
        "all": [
            {"path": "context.environment", "op": "eq", "value": "staging"},
        ]
    }
    narrowed_child = {
        "all": [
            {"path": "context.environment", "op": "eq", "value": "staging"},
            {"path": "context.region", "op": "eq", "value": "us-east-1"},
        ]
    }
    expanded_child = {
        "all": [
            {"path": "context.region", "op": "eq", "value": "us-east-1"},
        ]
    }

    assert PredicateEngine.is_attenuated(narrowed_child, parent)
    assert not PredicateEngine.is_attenuated(expanded_child, parent)


def test_universal_child_capability_must_narrow_parent() -> None:
    parent = UniversalDDFCapabilityAssertion(
        grant_id=str(uuid4()),
        issuer="did:key:z6Mkissuer",
        subject="urn:agent:planner",
        capability=Capability(
            target_namespace="mcp",
            target_resource="urn:mcp:tools/*",
            operations=["execute", "read"],
            constraints={
                "all": [
                    {"path": "context.tenant", "op": "eq", "value": "tenant-7"},
                ]
            },
        ),
    )
    child = UniversalDDFCapabilityAssertion(
        grant_id=str(uuid4()),
        issuer="urn:agent:planner",
        subject="urn:agent:worker",
        capability=Capability(
            target_namespace="mcp",
            target_resource="urn:mcp:tools/sql_query",
            operations=["execute"],
            constraints={
                "all": [
                    {"path": "context.tenant", "op": "eq", "value": "tenant-7"},
                    {"path": "context.read_only", "op": "eq", "value": True},
                ]
            },
        ),
    )

    assert CapabilityEvaluator.is_attenuated(parent, child).allowed


def test_concurrent_multihop_attenuation_checks_remain_consistent() -> None:
    root = UniversalDDFCapabilityAssertion(
        grant_id=str(uuid4()),
        issuer="did:key:z6Mksponsor",
        subject="urn:agent:planner",
        capability=Capability(
            target_namespace="mcp",
            target_resource="urn:mcp:tools/*",
            operations=["execute", "read"],
            constraints={"all": [{"path": "context.tenant", "op": "eq", "value": "tenant-7"}]},
        ),
    )
    planner = UniversalDDFCapabilityAssertion(
        grant_id=str(uuid4()),
        issuer=root.subject,
        subject="urn:agent:worker",
        capability=Capability(
            target_namespace="mcp",
            target_resource="urn:mcp:tools/sql_query",
            operations=["execute"],
            constraints={
                "all": [
                    {"path": "context.tenant", "op": "eq", "value": "tenant-7"},
                    {"path": "context.read_only", "op": "eq", "value": True},
                ]
            },
        ),
    )
    leaf = UniversalDDFCapabilityAssertion(
        grant_id=str(uuid4()),
        issuer=planner.subject,
        subject="urn:agent:query-runner",
        capability=Capability(
            target_namespace="mcp",
            target_resource="urn:mcp:tools/sql_query",
            operations=["execute"],
            constraints={
                "all": [
                    {"path": "context.tenant", "op": "eq", "value": "tenant-7"},
                    {"path": "context.read_only", "op": "eq", "value": True},
                    {"path": "context.audit", "op": "eq", "value": True},
                ]
            },
        ),
    )

    chain = [root, planner, leaf]
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(lambda _: CapabilityEvaluator.attenuation_chain_valid(chain), range(32))
        )
    assert all(result.allowed for result in results)


def test_universal_assertion_signature_is_deterministic_and_verifiable() -> None:
    signing_key = Ed25519Key(SigningKey.generate())
    assertion = UniversalDDFCapabilityAssertion(
        grant_id=str(uuid4()),
        issuer="arn:aws:iam::123456789012:role/issuer",
        subject="urn:k8s:serviceaccount:ops:controller",
        capability=Capability(
            target_namespace="aws",
            target_resource="arn:aws:s3:::example-bucket",
            operations=["read"],
            constraints={},
        ),
    )
    proof = signing_key.sign_assertion(assertion)

    assert proof.signature == signing_key.sign_assertion(assertion).signature
    assert Verifier.verify_assertion(assertion, proof)
    tampered_assertion = assertion.model_copy(update={"subject": "urn:agent:tampered"})
    with pytest.raises(SignatureVerificationError):
        Verifier.verify_assertion(tampered_assertion, proof)
