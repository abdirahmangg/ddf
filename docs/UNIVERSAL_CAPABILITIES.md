# Universal capability assertions

The canonical assertion contract is
[universal-ddf-capability.schema.json](../schemas/universal-ddf-capability.schema.json).
It contains a UUID grant identifier, URI issuer and subject, and a capability
scoped by namespace, resource URI, operation identifiers, and constraints.
Operations and namespace names are supplied by the integration; the DDF
capability evaluator does not attach business meaning to them.
Capability operations use the canonical set `read`, `write`, `execute`,
`invoke`, `delegate`, and `admin`; the namespace and resource identify where
those operations apply.

The Python types are `Capability` and `UniversalDDFCapabilityAssertion` in
`ddf.authority.models`. Both assertion levels reject undeclared fields and
operations are restricted to the canonical vocabulary. `CapabilityEvaluator`
provides generic request matching and attenuation checks. Ed25519 signatures
use DDF's deterministic JSON serializer through `Ed25519Key.sign_payload` and
`Verifier.verify_payload`; `sign_assertion` and `verify_assertion` produce and
check the detached `CapabilityAssertionProof` envelope. Signature proofs are
detached from the signed assertion payload.

## Constraint predicates

The built-in evaluator accepts JSON expressions with `all`, `any`, `not`, and
atomic path comparisons (`eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `in`, `not_in`,
and `exists`). Paths address the request envelope, including its `context`
object. Predicate values are data, never source code.

Attenuation is intentionally conservative: DDF proves conjunction narrowing
when all atomic parent clauses occur unchanged in the child. It rejects
expansion and predicate forms for which this implementation cannot establish a
subset proof. This makes the enforced relation auditable and avoids treating a
general predicate implication as solved by string comparison.

## Namespace profiles

The runnable integration cases cover MCP tool execution, AWS resource access,
Kubernetes pod management, FHIR/HIPAA release conditions, and e-Discovery
privilege filtering in [examples/README.md](../examples/README.md). These are
integration-owned vocabularies; none is built into the assertion schema.

## OpenFGA

The core model in `openfga/model.json` uses a generic `subject` relation on a
`resource` object and supports wildcard principals and resource-group
membership. `OpenFGAPolicy` maps PEIs to `principal:<PEI>` and resources to
`resource:<namespace>:<resource>`. Capability checks try exact resources,
ancestor wildcard objects, and the namespace wildcard. Applications can
continue defining their own tuple relations and models.

## Runtime posture and v0.2 API

The v0.2 endpoints are `POST /v2/grants`, `POST /v2/delegations/{parent_grant_id}`,
and `POST /v2/authorize`. Grant/delegation requests use strict assertion
objects and detached Ed25519 proofs. Configure `DDF_CAPABILITY_TRUSTED_KEYS` as
a JSON object mapping issuer URIs to `{"key_id": "...", "public_key": "<base64>"}`.
The CLI sends v0.2 grant, delegation, and authorization requests to
`DDF_API_URL` (default `http://127.0.0.1:8000`).
Legacy v0.1 mutation and authorization endpoints return `410 Gone` unless
`DDF_V01_COMPATIBILITY_ENABLED=true` is explicitly set for a migration window.

Authorization requires an EdDSA-signed EAT JWT. The verifier checks the issuer
key, required EAT claims, enclave assertion, freshness, and a SHA-256 binding
between the signed token and the complete `runtime_context`. It then enforces
the posture threshold. Configure `DDF_EAT_TRUSTED_KEYS` as a JSON object
mapping issuer URIs to base64-encoded raw Ed25519 public keys. Defaults are a
minimum score of `0.8` and maximum token age of `300` seconds; override them
with `DDF_MIN_POSTURE_SCORE` and `DDF_ATTESTATION_MAX_AGE_SECONDS`.
The trusted EAT issuer must sign only after validating the enclave evidence
represented by `ueid` and `ddf_hardware_enclave`.

The Alembic revision `2a7f61c4d5e8` backfills legacy authorities into
`ddf_universal_assertions`. It maps `quote` to `read` and `purchase` to
`write`, carries legacy purpose and fixed constraints forward as generic
predicates, and preserves parent links. Migrated rows and their parent chain
have no transferable universal assertion signatures: the chain must be
re-issued by trusted issuers before the v0.2 API will authorize it. Unsupported
legacy action names or unmappable parent/resource links abort the migration
rather than broadening authority silently.
