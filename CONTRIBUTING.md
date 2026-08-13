# Contributing to DDF

Thank you for your interest in contributing to DDF (Dynamic Delegation Fabric)!

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a feature branch: `git checkout -b feat/your-feature`
4. Set up development environment: `make install-dev && make up`
5. Make your changes
6. Write tests for your changes
7. Run tests: `make test`
8. Run linting and type checks: `make lint && make type-check`
9. Commit with conventional commits: `git commit -m "feat: description"`
10. Push to your fork
11. Submit a pull request

## Development Setup

```bash
# Install dependencies
make install-dev

# Start PostgreSQL and OpenFGA
make up

# Run tests
make test

# Check code quality
make lint
make type-check

# Format code
make format
```

## Conventional Commits

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` A new feature
- `fix:` A bug fix
- `docs:` Documentation only changes
- `test:` Adding tests
- `refactor:` Code change that neither fixes a bug nor adds a feature
- `security:` Security-related fixes
- `chore:` Changes to build process, dependencies, or tooling
- `ci:` Changes to CI configuration

Example: `feat: implement authority attenuation engine`

## Code Style

- Python 3.12+
- Type hints required for all production code
- 100 character line length (ruff)
- Format with `make format`
- Pass `make lint` and `make type-check`

## Testing Requirements

- Minimum 90% coverage for core authorization logic
- Property-based tests using Hypothesis for invariants
- All security paths should approach complete branch coverage
- Tests should be located in `tests/` matching the source structure

## Security Considerations

- Review [SECURITY.md](SECURITY.md) before working on security features
- Do not implement custom cryptography (use PyNaCl/Ed25519)
- All authorization logic must be testable and explainable
- Never commit private keys or sensitive test data

## Architecture

- Keep authorization logic in pure functions where possible
- Database models in `src/ddf/db/`
- Business logic in service modules (e.g., `src/ddf/delegation/service.py`)
- API routes in `src/ddf/api/routes/`
- Tests mirror source structure: `tests/unit/`, `tests/integration/`, `tests/property/`, `tests/security/`

## Pull Request Process

1. Update README.md if needed
2. Ensure tests pass: `make test`
3. Ensure coverage ≥ 90% for new code
4. Ensure code quality: `make lint && make type-check`
5. Provide clear PR description
6. Link related issues

## Questions?

Open an issue on GitHub or start a discussion. We welcome questions and feedback!

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
