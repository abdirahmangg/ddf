# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in DDF, please email open@arkstride.com instead of using the issue tracker.

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide an estimated timeline for a fix.

## Security Principles

DDF is designed with security as a first-class concern:

1. **Open Source Security**: All code is publicly reviewable
2. **No Custom Crypto**: We use PyNaCl (libsodium) for Ed25519, a well-vetted library
3. **Deterministic Serialization**: Authority documents use canonical JSON for signing
4. **Proof of Possession**: All delegated authorities are bound to holder's public key
5. **Attenuation Invariant**: Child authority ⊆ Parent authority, enforced by code
6. **Audit Trail**: All authorization decisions are logged with provenance
7. **No Secrets in Logs**: Private keys are never logged or printed

## Known Limitations (v0.1)

- Local revocation only (no distributed revocation infrastructure)
- Single-region deployment (no federation)
- No HSM/KMS integration
- Request-proof timestamp validation uses system clock (vulnerable to clock skew)
- No advanced threat detection

See [docs/threat-model.md](docs/threat-model.md) for detailed threat analysis.

## Security Testing

DDF includes automated security tests:

- **Privilege Escalation Test**: Child authority cannot expand parent constraints
- **Stolen Authority Test**: Authority cannot be used without holder's private key
- **Authority Laundering Test**: Cannot skip intermediate delegations
- **Property-based Testing**: Hypothesis-based invariant testing

Run security tests:

```bash
pytest tests/security/ -v
```

## Dependency Security

- Dependencies are pinned to specific versions in `pyproject.toml`
- Regular security audits via `safety check`
- CI runs `bandit` security scanning on every commit
- Direct dependencies only where possible

## Cryptographic Details

- **Algorithm**: Ed25519 (via PyNaCl/libsodium)
- **Key IDs**: Format `ddf:key:<identifier>`
- **Signatures**: Base64-encoded Ed25519 signature over canonical JSON
- **Hashing**: SHA-256 for provenance chain
- **Randomness**: System `os.urandom()` for UUIDs and nonces

## Proof of Possession

Every delegated authority must be verified with the actor's private key:

1. Actor creates canonical request proof (actor, authority_id, method, path, body hash, timestamp, nonce)
2. Actor signs proof with Ed25519 private key
3. Server verifies signature matches authority holder's public key
4. Request is allowed only if signature is valid

## Future Security Improvements (Post-v0.1)

- HSM/KMS integration
- Distributed revocation (CRLs or OCSP-like)
- DPoP-like sender-constrained tokens
- Rate limiting and anomaly detection
- Advanced logging and SIEM integration
