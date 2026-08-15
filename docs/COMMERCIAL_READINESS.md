# Commercial Readiness

## Software controls

The commercial production-readiness layer provides:

- maximum request-body enforcement
- production TLS enforcement
- Redis-backed distributed rate limiting
- PostgreSQL-backed mutation idempotency
- explicit capability broker policy disabled by default
- identity key rotation/revocation
- controlled identity-key discovery
- did:web resolution
- pinned OIDC issuer/audience/JWKS verification
- explicit SPIFFE-to-DDF subject mapping
- OpenFGA health/check/write/delete support
- DDF-authority requirement for ReBAC mutation helpers
- remote intent parser adapter whose output must pass deterministic scope checks
- evidence bundle export with offline integrity/signature verification
- `/livez`, `/ready/dependencies` and `/metrics`
- structured JSON logging
- non-root/read-only production deployment examples

## Important boundary

These controls do not constitute a security certification, legal opinion,
compliance attestation or production-readiness certification.

Stable `v1.0.0` remains blocked until the external evidence gate passes.
