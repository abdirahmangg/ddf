# DDF — Dynamic Delegation Fabric

**Open-source authorization infrastructure for delegated AI-agent authority.**

DDF answers the fundamental authorization question:

> **Which actor can perform which action, on which resource, through which authority path, for what purpose, under whose sponsorship—and until when?**

## The Problem

AI agents need delegated authority to act on behalf of humans—but delegation introduces risk.

- How do you grant an agent permission to purchase equipment without giving it unlimited spending power?
- How do you ensure a chain of delegations never accidentally expands privileges?
- How do you prove which agent did what, when, and under whose authority?
- How do you revoke authority safely, without breaking downstream systems?

DDF solves this through a **cryptographically-verified, auditable delegation model** inspired by capability-based security and IETF standards.

## How It Works

Imagine Alice delegates purchase authority:

```
Alice
  │ "purchase anything from vendors"
  │ "up to £10,000"
  │ "delegation depth = 3"
  │
  ▼
Planner Agent
  │ "purchase from Dell only"
  │ "up to £5,000"
  │ "delegation depth = 2"
  │
  ▼
Procurement Agent
  │ "purchase from Dell"
  │ "up to £2,000"
  │ "delegation depth = 1"
  │
  ▼
Buyer Agent
  │
  ▼
Vendor API ← "Can I purchase? YES"
```

Each step is:
1. **Cryptographically signed** (Ed25519)
2. **Bound to the recipient** (proof of possession)
3. **Attenuated** (child cannot increase parent's permissions)
4. **Time-limited** (explicit expiration)
5. **Purpose-bound** (only for "procurement", not marketing)
6. **Auditable** (every decision is logged)

If Buyer Agent tries to purchase **£20,000**, DDF returns:

```
✗ DENY
reason: AUTHORITY_AMOUNT_EXPANSION
parent_maximum: £2,000
requested: £20,000
```

## Core Invariant

The **foundational security property** of DDF:

```
Authority(child) ⊆ Authority(parent)
```

A delegated authority can only **narrow**, never **expand**.

- Child max_amount ≤ Parent max_amount ✓
- Child resources ⊆ Parent resources ✓
- Child purposes ⊆ Parent purposes ✓
- Child expiration ≤ Parent expiration ✓

This invariant is **enforced by code** on every delegation.

## Key Dimensions

Every DDF authority tracks:

1. **Actor** — who is authorized (`agent:buyer`)
2. **Action** — what they can do (`purchase`, `quote`, `review`)
3. **Resource** — what they can access (`vendor/dell/order/*`)
4. **Authority Path** — full delegation chain (`[Alice, Planner, Procurement, Buyer]`)
5. **Purpose** — why they can do it (`procurement`)
6. **Sponsor** — who ultimately authorized them (`user:alice@example.com`)
7. **Constraints** — boundaries (max amount, geography, audience, expiration)
8. **Proof** — cryptographic signature

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

### 3. Grant Authority

```bash
ddf grant \
  --sponsor "user:alice@example.com" \
  --actor "agent:buyer-agent" \
  --action "purchase" \
  --resource "vendor/*" \
  --purpose "procurement" \
  --max-amount 10000 \
  --currency GBP
```

### 4. Delegate

```bash
ddf delegate \
  --parent-authority-id ddf:authority:... \
  --actor "agent:procurement-agent" \
  --max-amount 5000
```

### 5. Authorize

```bash
ddf authorize \
  --actor "agent:procurement-agent" \
  --action "purchase" \
  --resource "vendor/dell/order/9281" \
  --purpose "procurement" \
  --authority-id ddf:authority:... \
  --context '{"amount": 4200, "currency": "GBP", "geography": "GB"}'
```

Response:

```
✓ ALLOW

Actor       agent:procurement-agent
Action      purchase
Resource    vendor/dell/order/9281
Purpose     procurement
Sponsor     user:alice@example.com
Path        Alice → Planner → Procurement → Buyer
Maximum     GBP 5,000
Requested   GBP 4,200
Expires     2026-08-13 15:00 UTC
```

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
├── POST /v1/grants         (create root authority)
├── POST /v1/delegations    (delegate authority)
├── POST /v1/authorize      (check authorization)
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
