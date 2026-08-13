# Governance

## Overview

DDF is an open-source project led by Arkstride. This document describes the governance structure and decision-making process.

## Project Leadership

**Arkstride** maintains the DDF project and determines the technical direction.

Current maintainers:
- Arkstride Engineering Team

## Decision Making

### Feature Decisions

1. **Small features** (bug fixes, documentation, minor improvements): Maintainers can merge directly or after brief review
2. **Medium features** (new endpoints, significant refactoring): Discussion in issues/PR, consensus among maintainers
3. **Large features** (new subsystems, major architecture changes): RFC (Request for Comments) process

### RFC Process

For major changes, create a discussion or RFC document:

1. Open an issue with label `rfc` describing the proposal
2. Community feedback and discussion (at least 1 week)
3. Maintainers discuss and decide
4. Decision is documented in the issue

### Breaking Changes

Breaking changes require a minor or major version bump and advance notice.

## Versioning

DDF uses [Semantic Versioning](https://semver.org/):

- **v0.1.0**: Initial release
- **v0.x**: Pre-1.0 (may include breaking changes)
- **v1.0+**: Stable API guarantees

## Release Process

1. Create a release branch from `main`
2. Update version in `pyproject.toml`
3. Update `CHANGELOG.md` (if created)
4. Create GitHub release with tag `vX.Y.Z`
5. Publish to PyPI

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## Community

- **Issues**: For bugs, feature requests, and discussions
- **Discussions**: For broader questions about DDF
- **Pull Requests**: For code contributions
- **Email**: open@arkstride.com for security issues

## Trademark

"Arkstride" and the Arkstride logo are trademarks of Arkstride. Use is governed by the [Apache License 2.0](LICENSE).

The DDF code is freely available under Apache 2.0.
The MAAP commercial product may be built on DDF, but is separate.

## Code of Conduct

All participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Roadmap

DDF v0.1 focuses on:
- Core authority model
- Delegation and attenuation
- Basic authorization
- Cryptographic signing
- Provenance and revocation
- CLI and examples

Post-v0.1 roadmap:
- Federation and cross-company trust
- Advanced policy engines
- MCP integration
- A2A adapters
- HSM/KMS support
- Analytics and anomaly detection (in MAAP)

See GitHub issues for detailed feature tracking.
