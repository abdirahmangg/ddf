# DDF Operations

## Required production configuration

Set at minimum:

- `DDF_ENVIRONMENT=production`
- `DDF_REQUIRE_TLS=true`
- `DDF_REDIS_URL`
- PostgreSQL `DATABASE_URL`
- `DDF_BOOTSTRAP_TOKEN` with at least 32 characters
- OpenFGA URL/store/model configuration where ReBAC is required

Recommended:

- `DDF_MAX_REQUEST_BYTES=1048576`
- `DDF_RATE_LIMIT_PER_MINUTE=120`
- `DDF_REQUIRE_IDEMPOTENCY=true`
- `DDF_DB_POOL_MIN=2`
- `DDF_DB_POOL_MAX=20`
- `DDF_JSON_LOGGING=true`

Capability brokers remain disabled unless
`DDF_ENABLE_CAPABILITY_BROKERS=true` and an explicit
`DDF_CAPABILITY_BROKER_POLICY` JSON mapping exists.

## Failure behavior

Production startup fails for unsafe core configuration.

Redis failure causes rate limiting to fail closed.

PostgreSQL failure causes durable idempotency to fail closed.

OpenFGA checks return denial when the dependency cannot provide a valid allow.
