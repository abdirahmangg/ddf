# 01 — Attack Surface

All items below are from static source review. None were exercised at
runtime. "Gated" means an authentication/authorization dependency is present
on the FastAPI route; "ungated" means it is not.

## HTTP routes — legacy plane (`ddf.main`, mounted unconditionally)

| Route | Method | Gated? | Notes |
|---|---|---|---|
| `/health` | GET | No (by design) | Returns version + debug flag |
| `/v1/grants` | POST | **Only if `DDF_COMMERCIAL_ENFORCE=true`** (default `false`) | `delegation_endpoints.py` → `GrantService.create_grant`; no `signing_key` passed → unsigned, unkeyed authority (see Finding F23/F24) |
| `/v1/delegations/{authority_id}` | POST | **Only if `DDF_COMMERCIAL_ENFORCE=true`**, and only if path matches `/v1/delegations/` with trailing slash | `DelegationService.create_delegation`; no caller-identity parameter exists at all (F27) |
| `/v1/authorize` | POST | **Never** — not in `LegacyMutationGuard.protected` under any configuration | `AuthorizationService.authorize`; evaluates whatever authority_id is supplied |
| `/v1/revocations` | POST | Only if enforced | `RevocationService.revoke`; `actor` is a free-text field, no auth tie-in |
| `/v1/revocations/{authority_id}` | GET | Not covered by guard (GET not in method set) | Reveals revocation status — minor enumeration surface |
| `/v1/audit/events` | GET | **Never** | Global, tenant-less `provenance_events` table — see F28 |
| `/v1/audit/verify` | GET | **Never** | Runs chain verification over the same global table |

## HTTP routes — commercial plane (`/v1/commercial/*`, `ddf.commercial.api`)

All routes except `/bootstrap` require `authenticate_request` (signed-request
PoP auth via `X-DDF-*` headers). `/bootstrap` requires a separate bearer
token (`X-DDF-Bootstrap-Token`) checked with `hmac.compare_digest`.

| Route | Method | Role required | Notes |
|---|---|---|---|
| `/v1/commercial/bootstrap` | POST | Bootstrap token only | Creates first tenant + principal |
| `/v1/commercial/agents` | POST | `agent_registrar` or `tenant_admin` | |
| `/v1/commercial/grants` | POST | `authority_issuer` or `tenant_admin` | `DDF_REQUIRE_HUMAN_ROOT_SPONSOR` (default true) restricts to human/user identity_type |
| `/v1/commercial/delegations/{authority_id}` | POST | implicit: immediate holder or `tenant_admin` | |
| `/v1/commercial/authorize` | POST | caller must match `actor` unless `tenant_admin`/`authorize_as` | tenant-scoped via `AuthorityTenant` lookup |
| `/v1/commercial/capabilities` | POST (mint) | `capability_caller_allowed` | |
| `/v1/commercial/capabilities/{id}/consume` | POST | caller must be capability holder | never re-checks authority revocation (F2) |
| `/v1/commercial/intents/compile` | POST | any authenticated principal | explicitly marked untrusted output |
| `/v1/commercial/rebac/check` | POST | any authenticated principal | caller supplies user/relation/object freely (F5a) |
| `/v1/commercial/rebac/tuples` | POST | `rebac_admin` or `tenant_admin` | not tenant-namespaced in OpenFGA object space |
| `/v1/commercial/policies/{key}` | PUT | `policy_admin` or `tenant_admin` | |
| `/v1/commercial/evidence` | GET | `auditor` or `tenant_admin` | tenant-scoped correctly |

## Operational routes (`production_readiness.install_production_readiness`)

| Route | Gated? | Notes |
|---|---|---|
| `/ready` (legacy) | No | Leaks raw exception text in 503 body |
| `/livez` | No (by design) | |
| `/ready/dependencies` | No (by design) | Reports DB/Redis/OpenFGA booleans |
| `/metrics` | No | Labels include raw request path (F16) |

## Middleware chain (production readiness layer)

Order as registered in `install_production_readiness`: Metrics →
DurableIdempotency → DistributedRateLimit → TLSRequired → BodyLimit (Starlette
applies these in reverse of registration order around the inner app — see
F13/F14/F15 for behavior details). All of this is **additively mounted**;
none of it replaces or gates the legacy, ungated routes above.

## Trust boundaries identified

1. **Unauthenticated internet → legacy `/v1/*` routes.** No identity is
   established. This is the most significant boundary in the system because
   `/v1/authorize` sits on the far side of it with no gate at all.
2. **Authenticated tenant principal → commercial `/v1/commercial/*` routes.**
   Identity via Ed25519 signed-request PoP, tenant-scoped.
3. **DDF service → PostgreSQL.** Single shared database; legacy and
   commercial planes share tables (`authorities`, `provenance_events`) with
   different trust assumptions.
4. **DDF service → OpenFGA.** Optional, env-toggled, not tenant-namespaced
   in the object/tuple space as implemented.
5. **DDF service → Redis.** Rate limiting and (per docs) nonce/caching;
   fails closed only when `DDF_ENVIRONMENT=production`.
6. **DDF service → outbound HTTP.** `resolve_did_web`, `verify_oidc_token`,
   `RemoteIntentAdapter`, `RemoteSigningProvider` all make outbound calls;
   none are wired into any route observed, so reachability is unconfirmed.

## Network surface (docker-compose.yml, dev stack)

| Service | Published ports | Notes |
|---|---|---|
| postgres:16-alpine | 5432 | Default dev credentials (`ddf`/`ddf_password`), bound on all host interfaces |
| openfga/openfga:latest | 8080, 8081, 3000 | Mutable tag; no datastore engine or auth configured; playground port published |
| DDF API (Makefile `make serve`) | 8000 | `--reload --host 0.0.0.0` dev settings |

## Config knobs of security relevance

`DDF_COMMERCIAL_ENFORCE`, `DDF_ENVIRONMENT`, `DDF_REQUIRE_TLS`,
`DDF_REDIS_URL`, `DDF_BOOTSTRAP_TOKEN`, `DDF_MAX_REQUEST_BYTES`,
`DDF_RATE_LIMIT_PER_MINUTE`, `DDF_REQUIRE_IDEMPOTENCY`,
`DDF_OPENFGA_ENABLED`/`DDF_OPENFGA_REQUIRED`, `DDF_ENABLE_CAPABILITY_BROKERS`
+ `DDF_CAPABILITY_BROKER_POLICY`, `DDF_SYSTEM_SIGNING_PROVIDER` +
`DDF_SYSTEM_SIGNING_PRIVATE_KEY`, `DDF_DEVELOPMENT_MODE`,
`DDF_REQUIRE_HUMAN_ROOT_SPONSOR`, `REQUEST_SIGNATURE_VALIDITY_SECONDS` /
`DDF_REQUEST_SIGNATURE_VALIDITY_SECONDS` (two different env var names appear
across `settings.py` and `auth.py` for what looks like the same concept —
unresolved naming inconsistency, see F21).
