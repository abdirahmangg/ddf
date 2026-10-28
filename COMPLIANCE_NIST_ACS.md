# DDF NIST and ACS Control Mapping

This document maps implemented DDF controls to the identity, authorization,
and audit concepts requested for NIST Zero Trust and the NCCoE agent identity
lifecycle, and to the ACS-Core Guardian hooks named in the task. It is an
implementation mapping, not a NIST or OWASP certification or attestation.
The repository does not vendor an authoritative ACS-Core v0.2 schema or a
third-party conformance suite; the `acs-core/0.2` envelope identifier and field
mapping here are DDF's adapter contract and must be checked against the
deployment's adopted ACS release before claiming interoperability.

## NIST Zero Trust and Agent Identity Lifecycle

| Area | DDF implementation | Current limitation / operational control |
|---|---|---|
| Identity / provisioning | v0.2 signed capability assertions bind URI/URN issuer and subject identifiers to a UUID grant and capability scope. Ed25519 assertion proof validation uses configured trusted issuer keys. | Identity enrollment, key custody, issuance approval, and identity-proofing are deployment responsibilities; DDF does not establish a real-world identity from a PEI alone. |
| Authorization / execution | Capability evaluation checks subject, namespace, resource, canonical operation, declarative predicates, delegation attenuation, and EAT-bound runtime context. Authorization denies on missing, stale, untrusted, unbound, or below-threshold attestation. | The authorization decision is only as strong as trusted issuer configuration, the request-context producer, and the resource/action enforcement point. |
| Execution attestation | `EATVerifier` validates EdDSA JWT signatures from configured trust keys, checks freshness, hardware-enclave evidence, posture score, and the runtime-context hash binding. | DDF's claim names are a DDF profile; they are not a complete implementation of every EAT claim or a hardware attestation verifier. A deployment must verify the evidence chain and measurements at its trusted boundary. |
| Revocation | Universal assertion revocation is persisted and checked during chain validation. A low-posture authorization result revokes the grant and all persisted descendants, records provenance, and requests exact OpenFGA tuple deletions. The registry accepts pluggable live status sources for CRL/OCSP-style checks. | Live CRL/OCSP retrieval, cache/TTL policy, and status-source trust are pluggable integrations and are not enabled by default. A failed OpenFGA deletion is surfaced; local DDF revocation remains persisted and authorization fails closed. |
| Audit | Provenance events are UTC-normalized, SHA-256 hash-linked, optionally Ed25519-signed, and verified. A transactional chain-head row serializes concurrent writers across supported SQLite/PostgreSQL persistence. | Audit immutability beyond the database trust boundary (e.g. WORM storage, independent timestamping, SIEM retention) is an operational integration. |

This mapping follows the lifecycle categories in the task: provisioning,
execution attestation, revocation, and audit. It does not claim that a
particular NIST NCCoE paper or draft has certified DDF. Operators should map
these controls to the current publication and their system-specific
authorization policies during assessment.

## ACS-Core Guardian Hook Mapping

`src/ddf/provenance/acs_exporter.py` emits JSON-RPC 2.0 method-call objects:
`jsonrpc` is `"2.0"`, `id` is the event identifier, `method` is the Guardian
hook type, and `params` contains the ACS version label, UTC timestamp, DDF
source, request correlation, and event data. The supported hook method values
are:

| Guardian hook | DDF event data |
|---|---|
| `toolCallBefore` | Subject, target namespace/resource, operation, grant, attenuation chain, posture score, and allow/deny reasons before execution. |
| `toolCallResult` | The same request binding plus the execution result/outcome supplied by the caller. |
| `subagentStart` | Parent and child subjects, grant identifier, attenuation chain, and the parent request in `request_id_ref`. |
| `subagentStop` | Parent and child subjects, grant identifier, attenuation chain, outcome, and the parent request in `request_id_ref`. |

The exporter validates envelope shape and correlation fields and requires an
explicit asynchronous sink for delivery; a missing sink is an error, not a
successful no-op. DDF leaves event transport, retries, authentication,
retention, and receiver-side schema validation to the configured integration.

## Verification Evidence

The repository tests cover hook values and parent-child correlation, posture
failure revocation and descendant tuple invalidation, and concurrent,
pool-constrained provenance persistence. SQLite runs by default. PostgreSQL
coverage runs when `DDF_TEST_POSTGRES_URL` points to a dedicated test database.
Passing these tests demonstrates the tested implementation behavior only; it
is not external standards conformance evidence.
