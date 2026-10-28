# Universal capability profiles

The core capability contract does not assign business meaning to an operation.
An integration supplies a namespace, a resource URI, operation identifiers, and
context predicates for its own policy vocabulary. The examples below are also
covered by `tests/integration/test_universal_capability_profiles.py`.

| Profile | Namespace | Resource example | Operation | Example predicate |
|---|---|---|---|---|
| MCP | `mcp` | `urn:mcp:tools:sql_query` | `execute` | tenant matches request context |
| AWS IAM | `aws` | `arn:aws:s3:::example-bucket` | `read` | staging environment and approved region |
| Kubernetes | `kubernetes` | `urn:k8s:namespace:staging/pods/*` | `write` | namespace and service account match |
| FHIR / HIPAA | `fhir` | `urn:fhir:Patient/123/Observation` | `read` | treatment basis and minimum-necessary flag |
| e-Discovery | `ediscovery` | `urn:ediscovery:case/123/document/456` | `read` | document is non-privileged and in the matter |

Constraints use a deliberately small, non-executable expression language:

```json
{
  "all": [
    {"path": "context.tenant_id", "op": "eq", "value": "tenant-7"},
    {"path": "context.region", "op": "in", "value": ["us-east-1", "us-west-2"]}
  ]
}
```

The predicate evaluator supports `all`, `any`, `not`, `eq`, `ne`, `lt`, `lte`,
`gt`, `gte`, `in`, `not_in`, and `exists`. It never evaluates source code or
loads policy text dynamically. To prove attenuation, every conjunctive parent
predicate must appear unchanged in the child; unsupported forms fail closed
for attenuation rather than relying on an unsound implication guess.

The canonical JSON Schema is [universal-ddf-capability.schema.json](../schemas/universal-ddf-capability.schema.json).
