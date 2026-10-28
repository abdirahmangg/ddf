# DDF — Dynamic Delegation Fabric

**Open-source authorization infrastructure for delegated AI-agent authority.**

The sector-neutral assertion format, predicate semantics, and namespace
integration cases are documented in [Universal capabilities](docs/UNIVERSAL_CAPABILITIES.md).
The implementation mapping for NIST lifecycle and ACS Guardian hooks is in
[COMPLIANCE_NIST_ACS.md](COMPLIANCE_NIST_ACS.md).
The strict `/v2` API uses universal capability assertions. Legacy `/v1`
authority and authorization endpoints are disabled by default; set
`DDF_V01_COMPATIBILITY_ENABLED=true` only during an explicitly managed
migration window.

DDF answers the fundamental authorization question:

> **Which principal can perform which operation on which resource, under what constraints, and through which delegation path?**

## The Problem

AI agents need delegated authority to act on behalf of humans—but delegation introduces risk.

- How do you grant an agent permission to purchase equipment without giving it unlimited spending power?
- How do you ensure a chain of delegations never accidentally expands privileges?
- How do you prove which agent did what, when, and under whose authority?
- How do you revoke authority safely, without breaking downstream systems?

DDF solves this through a **cryptographically-verified, auditable delegation model** inspired by capability-based security and IETF standards.

## How It Works

Imagine a principal delegates resource access:

```
Alice
  │ execute on urn:mcp:tools/*
  │
  ▼
Planner Agent
  │ execute on urn:mcp:tools/database_query
  │
  ▼
Worker Agent
  │
  ▼
MCP Tool ← "Can I execute? YES"
```

Each step is:
1. **Cryptographically signed** (Ed25519)
2. **Bound to the recipient** (proof of possession)
3. **Attenuated** (child cannot increase parent's permissions)
4. **Runtime-bound** (fresh, signed EAT posture evidence)
5. **Auditable** (every decision is logged)

Legacy purpose and monetary limits are retained only as generic predicates
during migration; they are not v0.2 assertion fields.

## Core Invariant

The **foundational security property** of DDF:

```
Authority(child) ⊆ Authority(parent)
```

A delegated authority can only **narrow**, never **expand**.

- Child constraints ⊆ Parent constraints ✓
- Child resources ⊆ Parent resources ✓
- Child operations ⊆ Parent operations ✓

This invariant is **enforced by code** on every delegation.

## Key Dimensions

Every DDF authority tracks:

1. **Issuer and subject** — the delegating and delegated principal URIs
2. **Namespace and resource** — the universal resource scope
3. **Operations** — canonical operations such as `read`, `write`, and `execute`
4. **Constraints** — generic, declarative predicates
5. **Proof** — detached Ed25519 signature
6. **Runtime posture** — fresh EAT signed by a trusted attestation issuer

## Why DDF?

**For Teams:**
- Audit every delegation and authorization decision
- Revoke authority instantly (cascades to descendants)
- Explain any denial reason automatically
- Never accidentally grant unlimited authority

**For Builders:**
- Standard authorization model for AI agents
- Works locally—zero cloud/SaaS requirement
- Open source—no vendor lock-in
- Production-grade security (Ed25519, deterministic signing)

**For Enterprises:**
- Foundation for future MAAP (Multi-Agent Authorization Platform)
- Scales from dev to compliance-heavy deployments
- Integrates with OpenFGA (Zanzibar-like relationships)
- Ready for HSM/KMS and federation (post-v0.1)

## Quick Start

### 1. Start Services

```bash
make install-dev
make up
```

### 2. Create an Agent Identity

```bash
ddf identity create buyer-agent
```

### 3. Create a Grant

```bash
ddf grant --assertion-json '<signed universal assertion JSON>'
```

### 4. Delegate

```bash
ddf delegate --parent <grant-uuid> --assertion-json '<signed child assertion JSON>'
```

### 5. Authorize

```bash
ddf authorize \
  --grant <grant-uuid> \
  --request-json '<strict access request with EAT token and runtime_context>'
```

Configure `DDF_API_URL`, `DDF_CAPABILITY_TRUSTED_KEYS`, and
`DDF_EAT_TRUSTED_KEYS` before using v0.2 commands. Request fields and required
trust configuration are described in [Universal capabilities](docs/UNIVERSAL_CAPABILITIES.md).

## Technology Stack

- **Python 3.12+** — modern, type-safe
- **FastAPI** — production HTTP API
- **Pydantic** — typed data models
- **PostgreSQL** — persistent storage
- **OpenFGA** — relationship-based entitlements
- **Ed25519** (PyNaCl) — cryptographic signing
- **Pytest + Hypothesis** — comprehensive testing

Everything runs locally for **$0** (no cloud required).

## Architecture

```
DDF Core
├── Authority Model         (Pydantic, versioned)
├── Attenuation Engine      (verify child ⊆ parent)
├── Delegation Service      (create & validate)
├── Cryptography            (Ed25519 signing)
├── Authorization Evaluator (combine all constraints)
├── Provenance & Audit      (tamper-evident logging)
└── Revocation Engine       (cascade invalidation)

↓

FastAPI Routes
├── POST /v2/grants         (create root assertion)
├── POST /v2/delegations    (delegate assertion)
├── POST /v2/authorize      (check capability and runtime posture)
├── GET  /v1/decisions/{id} (explain decision)
└── POST /v1/revocations    (revoke authority)

↓

PostgreSQL + OpenFGA
```

## Documentation

- [Authority Model](docs/authority-model.md) — Deep dive on the data model
- [Attenuation Engine](docs/attenuation.md) — How constraint narrowing works
- [Cryptography & Signing](docs/crypto.md) — Ed25519 and proof-of-possession
- [Threat Model](docs/threat-model.md) — What DDF protects against
- [API Protocol](docs/protocol.md) — Full HTTP API reference
- [Security](SECURITY.md) — Security considerations and disclosure

## Testing

```bash
# Unit tests
make test

# Full coverage report
make test-coverage

# Security-specific tests
pytest tests/security/ -v

# Property-based tests (Hypothesis)
pytest tests/property/ -v

# Check code quality
make lint
make type-check
```

## The MAAP Commercial Product

DDF is the **open-source foundation**. 

Later, Arkstride will release **MAAP** (Multi-Agent Authorization Platform):
- Hosted control plane
- Multi-tenancy & federation
- Enterprise identity (SAML, SCIM)
- Global revocation
- Analytics & anomaly detection
- SLA & support

The relationship: **DDF → MAAP** (like Git → GitHub)

DDF works completely independently. MAAP is optional.

## Status: v0.1 (Alpha)

This is the initial reference implementation. It is production-ready for:
- Local and single-region deployments
- Delegated agent authority
- Auditable decision-making

Post-v0.1 roadmap:
- Federation & cross-company trust
- Advanced policy engines
- MCP integration
- HSM/KMS support

See [GOVERNANCE.md](GOVERNANCE.md) for full roadmap.

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

- Report bugs via GitHub issues
- Propose features via discussions
- Send security reports to open@arkstride.com
- Follow our [Code of Conduct](CODE_OF_CONDUCT.md)

## License

Apache License 2.0

DDF is open source. The "Arkstride" and "MAAP" names are trademarks of Arkstride.

See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.

## Getting Help

- **Issues**: Bug reports and feature requests
- **Discussions**: Questions and ideas
- **Docs**: [docs/](docs/) folder
- **Email**: open@arkstride.com (security issues only)

---

**Built with ❤️ by Arkstride**

*Open-source authorization for the era of delegated AI.*
