# 05 — Findings Register

**No finding has been independently executed by this assessment.** However,
one exception changes the confidence picture materially: the project's own
test suite (`tests/test_api_routes.py::test_authority_lifecycle_via_http`,
reviewed in a later batch) contains a passing test that performs the exact
headline attack chain below — unauthenticated grant, unauthenticated
authorize — and asserts `decision == "ALLOW"` as the correct, intended
result. That is the maintainers' own regression test demonstrating this
exact behavior, which is about as strong as evidence gets without this
assessment independently running pytest itself. That finding is labeled
**CONFIRMED-BY-EXISTING-TEST** below, a tier between CONFIRMED-BY-READING
and full independent execution. Everything else remains CONFIRMED-BY-READING
(every function in the path read, deterministic, no remaining ambiguity),
HIGH-CONFIDENCE (strong textual evidence, one or two unread dependencies),
or HYPOTHESIS (plausible, meaningfully dependent on unread code).

## Summary table

| ID | Severity (provisional) | Title | Confidence | Component |
|---|---|---|---|---|
| F1 | Critical (as part of chain below) | Legacy `/v1/authorize` is never gated under any configuration; `/v1/grants`, `/v1/delegations/`, `/v1/revocations` gated only if `DDF_COMMERCIAL_ENFORCE=true` (default false) | CONFIRMED-BY-READING | main.py, commercial/api.py |
| F23 | Critical (chain) | Legacy-issued authorities have `holder_public_key=""` and `proof=None` — no PoP, no signature | CONFIRMED-BY-READING | delegation/service.py, authority/models.py |
| F24 | High (chain) | Legacy grant route hardcodes `sponsor=settings.api_host`; sponsor-integrity invariant not enforced on this path | CONFIRMED-BY-READING | api/routes/delegation_endpoints.py |
| F27 | Critical (chain) | Legacy delegation service has no caller-identity parameter at all — anyone can delegate from any known authority_id | CONFIRMED-BY-READING | delegation/service.py |
| **Chain F1+F23+F24+F27+F33** | **Critical** | **Unauthenticated end-to-end authority mint → delegate → authorize, with no cryptographic proof anywhere in the path** | **CONFIRMED-BY-TEST (EXECUTED).** `pytest tests/integration/test_api_routes.py::test_authority_lifecycle_via_http -v` run live against commit `c96b5bf5d1a30604ab9c2e24775477113fae5354` with Postgres+OpenFGA up: **PASSED**. The unauthenticated `ALLOW` is real, observed behavior, not merely a reading of the test. | see 05a below |
| F28 | High | Legacy audit tables (`provenance_events`, `authorization_logs`, and all other legacy tables) have no `tenant_id` column at all — confirmed in the actual ORM class definitions, not just the migration; `/v1/audit/events` and `/v1/audit/verify` are unauthenticated and return all tenants' data globally; the same test suite calls `GET /v1/audit/verify` with no auth headers and gets 200 | CONFIRMED-BY-READING (schema: db/models.py) + CONFIRMED-BY-EXISTING-TEST (route reachability) | db/models.py, provenance_endpoints.py |
| F6 | High | `revoke_identity_key`/`ddf_identity_keys` never consulted by `authenticate_request` (only reads `ddf_trusted_principals`) — key revocation has no effect on authentication | **REMEDIATED, CONFIRMED-BY-TEST.** Fixed in commit `344fc86` ("fix: disable revoked identity keys for authentication"), branch `fix/revocation-and-production-readiness`. Regression test `test_revoked_identity_key_cannot_authenticate` PASSED against the fix (full literal `pytest tests/ -v` output reviewed: 147 passed, 0 failed). | production_readiness.py, commercial/auth.py |
| F2 | Medium–High | `consume_capability` never rechecks authority revocation/expiry/chain validity after mint | **REMEDIATED, CONFIRMED-BY-TEST.** Fixed in commit `c25d589` ("fix: reject capabilities for revoked authorities"). Regression test `test_capability_cannot_be_consumed_after_authority_revocation` PASSED. | commercial/capabilities.py |
| F3 | High | Constraint checks (amount/currency/geography/audience) skipped when context field omitted; NaN amount bypasses numeric comparison | **REMEDIATED, CONFIRMED-BY-TEST (adversarially verified).** Confirmed exploitable before the fix: all 6 cases (missing/NaN/negative × authorize/mint) returned `ALLOW` — literal failing output reviewed. Fixed in commit `0b4a0d6` ("fix: validate constrained request amounts") with a shared validator in `authority/constraints.py` used by both call sites. All 6 cases now DENY/raise; full suite 158 passed. | commercial/capabilities.py, authorization/service.py, authority/constraints.py |
| F4 | High (if reachable) | Authority signature verified against `proof.public_key` embedded in the document itself, not a pinned system key; unsigned authorities accepted by design ("v0.1 compatibility") | HIGH-CONFIDENCE | authorization/service.py |
| F5a | High (if OpenFGA enabled) | `openfga_user`/`relation`/`object` taken from caller-supplied `request.context` in authorize | CONFIRMED-BY-READING | authorization/service.py |
| F5b | Low–Medium (design, not a bug) | OpenFGA fails *open* (allowed) when disabled — confirmed as deliberate, tested design via `test_openfga_policy.py::test_disabled_openfga_allows_without_network`, not an accidental gap. Operationally relevant: a deployment that intends OpenFGA as a mandatory extra control, but leaves it disabled or misconfigured, will silently allow requests rather than deny them. | CONFIRMED-BY-READING + CONFIRMED-BY-EXISTING-TEST | policy/openfga.py, commercial/api.py |
| F5c | Medium | OpenFGA objects/tuples not tenant-namespaced | HIGH-CONFIDENCE | commercial/api.py |
| R1 | Medium–High | A non-cascading revocation recorded first causes a later cascading revocation request to be silently ignored (returns the existing row) | **REMEDIATED, CONFIRMED-BY-TEST.** Fixed in commit `04bebed` ("fix: allow revocation cascade escalation"). Regression test `test_cascade_upgrade_is_not_shadowed` PASSED. | revocation/service.py |
| R2–R8 | Low–Medium | See "Revocation service" detail below | mixed | revocation/service.py |
| F7 | Medium | Evidence chain ordering race: `now` read before advisory lock acquired, ordering by `created_at` under contention can fork the chain | HIGH-CONFIDENCE | commercial/evidence.py |
| F8 | Medium | Legacy provenance chain unsigned by default; anyone with DB write access can recompute every link; chain-format marker allows silent exclusion from verification; no lock → concurrent writes can fork | HIGH-CONFIDENCE | provenance/service.py |
| F9 | Low–Medium | Legacy PoP envelope has no tenant/key_id/query/host/content-type binding or domain separation | HIGH-CONFIDENCE (design) | crypto/canonical.py |
| F10 | Medium | Delegation issues: `tenant_admin` delegation misattributes actor in `DelegationDB`; no chain-depth cap enforced by default; empty actions list inherits everything | HYPOTHESIS/HIGH-CONFIDENCE mixed | commercial/authority.py |
| F11 | Low | `/ready` leaks exception text; `/health` exposes debug flag; DB URL (with credentials) printed at startup; mismatched env var names between settings.py and auth.py | HIGH-CONFIDENCE | main.py, settings.py, commercial/auth.py |
| F12 | Low | Availability: no body-size limit before auth on legacy routes; global nonce-cleanup DELETE on every authenticated request; duplicate task_id/agent_id can 500 | HYPOTHESIS | commercial/auth.py, identity.py |
| F13 | Medium | `@app.on_event("startup")` handlers registered by `install_production_readiness` likely never run because `main.py` uses `lifespan=` — production startup guard and DB/Redis ping may be silently skipped | **REMEDIATED, CONFIRMED-BY-TEST.** Fixed in commit `918e9a8` ("fix: run production checks in app lifespan") — moved `validate_production_environment()` and related checks into `main.py`'s actual `lifespan()` context manager, removed `on_event` registration. Regression test `test_unsafe_production_config_is_caught_at_startup` PASSED against the fix. | production_readiness.py, main.py |
| F14 | Medium–High | `DurableIdempotencyMiddleware` runs before authentication, keyed only on `(tenant header, idempotency key)` with no principal — can replay a cached authenticated response to an unauthenticated caller | HIGH-CONFIDENCE (schema-confirmed: PK is `(tenant_id, idempotency_key)` only) | production_readiness.py, alembic c42e9b9a4f21 |
| F15 | Medium | Rate limiter runs before auth, keyed on client-supplied `X-DDF-Tenant`/`X-DDF-Principal` headers — trivially bypassed or used to burn a victim's quota | HIGH-CONFIDENCE | production_readiness.py |
| F16 | Medium | `/metrics` unauthenticated, labels include raw request path (IDs), unbounded cardinality possible | HIGH-CONFIDENCE | production_readiness.py |
| F17 | Medium–High | `verify_evidence_bundle` returns True for unsigned bundles; trusts the public key embedded in the bundle itself for signed ones; no per-record verification | HIGH-CONFIDENCE | production_readiness.py |
| F18/F25 | Medium–High (reachability dependent) | Three independent resource matchers (authorize, capabilities, remote-intent) disagree in implementation; none normalize `..`/`//`/encoding; `vendor/dell/../admin` textually satisfies a `vendor/dell/*` prefix check | CONFIRMED-BY-READING (inconsistency); HYPOTHESIS (exploitability, depends on downstream consumer) | authorization/service.py, commercial/capabilities.py, authority/resources.py, production_readiness.py |
| F19 | Medium (reachability unconfirmed) | `resolve_did_web` has no allowlist, no loopback/private-range/link-local blocking; nothing observed calls it | HIGH-CONFIDENCE (controls missing); HYPOTHESIS (reachable) | production_readiness.py |
| F20 | Medium | `DDF_ENVIRONMENT` defaults to `development`, disabling all fail-closed controls; `DDF_DEVELOPMENT_MODE=true` not rejected in production, generates ephemeral signing key | HIGH-CONFIDENCE | production_readiness.py, commercial/crypto.py |
| F40 | Low (but concretely reproducible) | `Makefile`'s `install-dev` target installs `.[dev,openfga]` only — not `production` — yet `main.py` unconditionally imports `production_readiness.py`, which imports `redis`/`jwt`/`prometheus_client` at module load. The README's own documented quick-start (`make install-dev && make up` then run the server) would fail with `ImportError` on startup exactly as written, sharpening F21. | CONFIRMED-BY-READING | Makefile, pyproject.toml, main.py |
| F21 | Low–Medium | Base install imports production-only deps (`jwt`, `redis`, `prometheus_client`) at module load — base install cannot start; `DATABASE_URL` vs `DDF_DATABASE_URL` naming split risks two different DB pools | HIGH-CONFIDENCE | main.py, pyproject.toml, production_readiness.py, settings.py |
| F22 | Medium | Legacy authorize PoP message has no nonce/timestamp/tenant — replayable; skipped entirely when authority has no holder key (ties to F23) | HIGH-CONFIDENCE (design) | authorization/service.py |
| F30 | Low (process) | CI security job (`bandit`, `safety check`) both run with `|| true` — cannot ever fail the pipeline regardless of findings | CONFIRMED-BY-READING | ci.yml |
| F32 | Medium | Kubernetes `NetworkPolicy` egress rule is `- {}` (allow all egress to any destination); provides zero containment if the did:web/OIDC/remote-intent SSRF surface (F19) is ever reachable | CONFIRMED-BY-READING | ddf-production.yaml |
| F33 | Critical (same root cause as headline chain, independent attack surface) | CLI `grant`/`delegate` commands (`ddf/cli/main.py`) call `GrantService.create_grant`/`DelegationService.create_delegation` with no `signing_key`, producing the same unsigned, unkeyed authority as the HTTP legacy routes; `identity create` generates a real keypair that is never connected to grant/delegate at all | CONFIRMED-BY-READING | cli/main.py |
| F34 | Medium (release-integrity) | SBOM (`ddf_spdx.json`, titled "stable-release candidate SBOM") lists `ddf` at version `1.0.0rc3`, contradicting `pyproject.toml`'s `1.0.0rc5` — which the project's own `test_release_identity.py` pins as the expected value. **Now confirmed by commit comparison:** the SBOM's embedded `documentNamespace` commit hash (`f70e637b989b9ebcaa2ff434be242a62595cc9e1`) does not match the actual repository `HEAD` (`c96b5bf5d1a30604ab9c2e24775477113fae5354`, confirmed via `git rev-parse HEAD`). The SBOM was generated against an entirely different commit than the one under assessment, compounding the version mismatch. | CONFIRMED-BY-READING | ddf_spdx.json, git history |
| F41 | **Medium (demonstrated, upgraded from Low)** | A `poetry.lock` exists and resolves `pyproject.toml`'s exact declared extras cleanly — but it is **untracked by git**, never committed, and none of the project's install paths (`Makefile`, `Dockerfile`, `ci.yml`) reference it. **CONFIRMED BY EXECUTION:** the live environment has `urllib3` installed at `2.7.0` (3 known CVEs per `pip-audit`: PYSEC-2026-4175/4176/4177), while `poetry.lock` pins the fixed `2.8.0`. The unused lockfile's absence from the real install path directly let a vulnerable version of an actual DDF dependency into the environment. | CONFIRMED-BY-TEST (EXECUTED) | poetry.lock, Makefile, Dockerfile, ci.yml; live `pip-audit` output |
| F42 (new) | **High — REMEDIATED, CONFIRMED-BY-TEST (adversarially discovered and verified).** `consume_capability`'s `SELECT ... FOR UPDATE` on the capability row and `RevocationService.is_effectively_revoked`'s check on the authority/revocations tables were not serialized against each other. Under a genuinely concurrent interleaving (two async tasks, separate DB sessions, revocation's commit landing after the consume's revocation check but before the consume's own commit), consumption completed successfully (`decision: ALLOW`, `status: consumed`) against an authority that had, by that point, been revoked. Discovered only during the second adversarial pass (A4 in the retest plan), not the original static review — this is a genuine TOCTOU race distinct from F2 (which covers the simpler non-concurrent case and was already fixed). Fixed in commit `737bfba` ("fix: serialize capability use with revocation") using a Postgres advisory transaction lock (`pg_advisory_xact_lock`, keyed on `authority_id`) taken by both `consume_capability` (after its row lock) and `RevocationService.revoke` (before reading/writing revocation state) — the same pattern already used in `commercial/evidence.py`. Verified with a real concurrent regression test run 20 times (20/20 pass), not a sequential approximation. | commercial/capabilities.py, revocation/service.py |
| F35 | Medium (supply-chain process) | The SBOM contains `debugpy`, `GitPython`, `gitdb`, `ipykernel`, `jupyterlab`, `nbclient`, `nbconvert`, `nbformat` — none declared anywhere in `pyproject.toml` or the `Dockerfile` — strongly indicating it was generated from a development/notebook environment rather than the actual production dependency closure. **CONFIRMED BY EXECUTION:** a live `pip-audit` run in the execution-phase Codespace found `jupyterlab` and `tornado` actually installed in that environment, neither a DDF dependency anywhere in `pyproject.toml`/`poetry.lock` — the exact same contamination signature, directly observed rather than inferred. | CONFIRMED-BY-TEST (EXECUTED) | ddf_spdx.json; live `pip-audit` output |
| F36 | Low–Medium (supply-chain accuracy) | `prometheus-client` — required by the `production` extra and imported at module load by `production_readiness.py` — is absent from the SBOM entirely, consistent with F35 (wrong environment captured) | CONFIRMED-BY-READING | ddf_spdx.json |
| F38 | Low–Medium (process) | `external_evidence.py`'s gate verifier checks structure/format only (reviewer non-empty, commit is 40 hex chars, artifact SHA-256 matches) — never authenticates the reviewer's identity or independently confirms `commit` against actual repo HEAD; a filesystem-write-capable party could fabricate a passing gate file | CONFIRMED-BY-READING | scripts/external_evidence.py |
| F39 | Medium | Helm chart (`values.yaml`) defaults `image.tag: latest` — a mutable tag — undermining the reproducibility the release-evidence tooling otherwise assumes (SBOM pinned to a git SHA, gate verifier requires a 40-char commit); inconsistent with the raw k8s manifest's `:VERSION` placeholder approach. **Confirmed reaching production:** `deploy/terraform/main.tf`'s `helm_release` resource supplies no `values`/`set` override, so `terraform apply` deploys the chart's unpinned `latest` default as-is. | CONFIRMED-BY-READING | deploy/helm/ddf/values.yaml, deploy/terraform/main.tf |
| F6-drill | **High** (escalates F6) | The project's own `key_compromise_drill.py` — meant to produce release evidence that key-compromise response works — only checks that `revoke_identity_key()` returns `True` (a DB row was updated in `ddf_identity_keys`); it never attempts an authenticated request with the "revoked" key to confirm rejection. Since `authenticate_request` never reads `ddf_identity_keys` (only `ddf_trusted_principals`, per F6), this drill can report success and write a clean passing artifact while the revoked key still fully authenticates against the real API. | CONFIRMED-BY-READING | scripts/key_compromise_drill.py |

## 05a — Headline finding detail: unauthenticated end-to-end authorization bypass

**Severity: Critical. Confidence: CONFIRMED-BY-EXISTING-TEST.**

The project's own `tests/test_api_routes.py::test_authority_lifecycle_via_http`
builds a real `httpx.AsyncClient` against `ddf.main.create_app()` (the actual
production app factory, with only the DB session and `api_host` setting
overridden for test isolation) and executes:

```python
grant = await client.post("/v1/grants", json={...})           # no auth headers
...
delegated = await client.post(f"/v1/delegations/{parent_id}", json={...})  # no auth headers
...
allowed = await client.post("/v1/authorize", json={
    "actor": buyer, "action": "purchase", "authority_id": child_id,
    "context": {"amount": 1500, "currency": "GBP", "geography": "GB"},
})
assert allowed.status_code == 200
assert allowed.json()["decision"] == "ALLOW"
```

No signature, no `X-DDF-*` header, no bootstrap token — anywhere in this
sequence — and the test asserts `ALLOW` as the correct outcome. This is the
maintainers' own passing regression test performing the identical attack
chain this assessment identified from reading `delegation/service.py` and
`authorization/service.py` independently. This is the strongest form of
evidence available short of this assessment running pytest itself.

A supporting detail: the test's `api_client()` helper overrides
`get_settings_dep` with `Settings(api_host=sponsor)` specifically so that
`settings.api_host` — which `delegation_endpoints.create_grant` uses
directly as the authority's `sponsor` field (F24) — produces a
human-readable identity string for test assertions. This is a workaround
for F24, not a fix, and its presence suggests the author was aware
`sponsor=settings.api_host` is not a real identity binding.

A related, separate observation: `LegacyMutationGuard`'s own docstring
states it exists to "Disable **insecure** v0.1 mutation endpoints in
enforced deployments" — the maintainers already know this surface needs
disabling. The defect is that the guard's protected list
(`/v1/grants`, `/v1/delegations/`, `/v1/revocations`) omits `/v1/authorize`
and `/v1/audit/*` entirely, leaving the one endpoint that actually grants
access, and the one that leaks cross-tenant audit data, outside the
mitigation built specifically for this class of problem.

**Attack path (attacker model A — fully unauthenticated):**

1. `POST /v1/grants` with any `actor`/`actions`/`resources`/`purposes` →
   `delegation_endpoints.create_grant` → `GrantService.create_grant(...,
   signing_key=None)` → persists an `AuthorityDB` row with
   `holder_public_key=""`, `proof_json={}`. No authentication dependency is
   present on this route, and the guard that could disable it
   (`LegacyMutationGuard`) only activates when `DDF_COMMERCIAL_ENFORCE=true`,
   which is not the default.
2. (Optional, not required for the chain, but available) `GET
   /v1/audit/events` — unauthenticated, unscoped — returns every
   `authority_id` in the system if the attacker needs to discover one rather
   than using their own (F28).
3. `POST /v1/delegations/{authority_id}` → `DelegationService.create_delegation`,
   which has **no caller-identity parameter at all** — it loads the parent
   purely by ID and produces a child that inherits the parent's
   actions/resources/purposes/constraints by default (F27). Again
   `holder_public_key=""`, no proof.
4. `POST /v1/authorize` with the resulting `authority_id` →
   `AuthorizationService.authorize`. `verify_authority_signature` returns
   immediately because `authority.proof is None`.
   `verify_proof_of_possession` returns immediately because
   `authority.holder_public_key` is falsy. The request is evaluated purely
   on action/resource/purpose/constraint matching and returns `ALLOW`.

**Root cause, confirmed across every call site reviewed:** `GrantService`
and `DelegationService`'s `signing_key` parameter is optional and defaults
to producing an unsigned, unkeyed authority (`holder_public_key=""`,
`proof=None`). This is not limited to the HTTP legacy routes:

- The CLI (`ddf/cli/main.py`, `grant`/`delegate` commands, F33) has the
  identical gap — never supplies a `signing_key` either, and its
  `identity create` command generates a real Ed25519 keypair that is never
  connected to `grant`/`delegate` at all.
- The project's own unit test suite (`test_authorization_service.py`,
  `test_delegation_service.py`, `test_effective_authority.py`,
  `test_revocation_service.py` — independent of the HTTP integration test
  cited above) universally creates authorities this way and treats
  successful, unsigned, unkeyed authorization as the single normal, correct
  usage pattern throughout.
- The **only** call site in the entire codebase reviewed that constructs a
  real `Ed25519Key` and passes it as `signing_key` is `demo/procurement.py`,
  a demonstration script, not a production entry point.

In other words, `signing_key` is a vestigial parameter: the capability to
produce a properly signed, PoP-bound authority exists in the service layer,
but no real entry point (HTTP, CLI) and no test ever exercises it. This
elevates the finding from "a gap in one route's wiring" to "the
authenticated-issuance code path was built but never connected to anything
a real caller uses."

**Impact if confirmed by execution:** complete bypass of DDF's stated
proof-of-possession invariant. An attacker can mint, delegate, and exercise
authority of any shape (actions, resources, purpose, amount up to whatever
they request) with no cryptographic material whatsoever, so long as the
legacy routes are reachable and `DDF_COMMERCIAL_ENFORCE` is not set to true.

**What would need to be true for this NOT to be exploitable in a real
deployment:** the operator has set `DDF_COMMERCIAL_ENFORCE=true` AND the
legacy `/v1/authorize` and `/v1/audit/*` routes are additionally blocked at
a layer outside this codebase (e.g. a reverse proxy denylist), since
`LegacyMutationGuard` does not cover them regardless of the flag.

**Reproducer:** `regression-tests/test_legacy_authorize_unauthenticated.py`

## Revocation service detail (R1–R8)

From `revocation/service.py`, read in isolation:

- **R1 (HIGH-CONFIDENCE):** `revoke()` returns any existing revocation row
  for the authority rather than creating a new one. If a non-cascading
  revocation is recorded first, a subsequent cascading revocation request
  silently returns the old, non-cascading row — descendants are never
  invalidated. Reproducer: `regression-tests/test_revocation_cascade_override.py`.
- **R2 (HYPOTHESIS, needs route-layer auth):** no authorization check is
  visible on who may call `revoke()` — `actor` is caller-supplied and used
  only for the audit trail.
- **R3 (HYPOTHESIS):** R1+R2 combined would let a delegate revoke its own
  authority non-cascading to pre-empt and neutralize a sponsor's later
  cascading revoke.
- **R4 (HYPOTHESIS):** `session.get(AuthorityDB, authority_id)` has no
  tenant predicate in the revocation service itself (tenant scoping, where
  present, lives in the commercial route layer, not here).
- **R5 (HYPOTHESIS):** check-then-insert in `revoke()` has no lock;
  concurrent calls could produce duplicate revocation rows.
- **R6 (HYPOTHESIS, partially addressed by schema):** `authorities.parent_authority_id`
  has a real FK with default `ON DELETE` behavior (no explicit `ondelete`),
  which prevents hard-deleting a parent while children exist — but this
  does not address soft-revocation dangling-reference scenarios.
- **R7 (HYPOTHESIS):** TOCTOU window between the revocation check and the
  protected action, since they are separate queries with no shared lock.
- **R8 (LOW/INFORMATIONAL):** comma-joined resources in the audit payload
  are ambiguous if a resource string itself contains a comma; a 404 vs.
  normal response on revocation-status lookup allows ID enumeration.

## Defenses verified by reading (not yet by execution)

- `load_authority_chain` re-derives the full chain from stored
  `parent_authority_id` links (never trusts a client-supplied path), rejects
  cycles, and validates every `authority_path` segment — the strongest
  control in the codebase, and it runs independently at authorize, mint,
  and delegate time on the commercial path.
- `calculate_effective_constraints` correctly re-inherits a parent's
  constraint value whenever the child's own value is unset, closing what
  would otherwise look like a constraint-dropping gap in
  `ConstraintValidator.is_narrower_or_equal`.
- Commercial-path nonce reuse is blocked atomically via a `(tenant_id,
  nonce)` primary key, inserted only after signature verification succeeds.
- Bootstrap token comparison is constant-time (`hmac.compare_digest`) with a
  32-character minimum.
- `ddf_capabilities` has `UniqueConstraint(tenant_id, task_id)`, giving
  atomic single-issuance per task.
- Capability consumption uses `SELECT ... FOR UPDATE`, serializing
  concurrent consumers of the same capability row.
- Redis-backed rate limiting and distributed idempotency both fail closed
  specifically when `DDF_ENVIRONMENT=production` (though see F20 for the
  default-environment caveat).
- OIDC verification (`verify_oidc_token`) checks an algorithm allowlist,
  requires a uniquely-pinned `kid`, and requires `exp`/`iat`/`sub` plus
  issuer/audience — well-formed, though not observed to be wired into any
  authentication path.
- did:web, OIDC, and remote-intent HTTP clients all disable redirect
  following.

## poetry.lock refutes the "same-project, messier environment" theory for F35

The genuine `poetry.lock` for this project (matching `pyproject.toml`'s
`dev`/`openfga`/`production` extras exactly) is completely clean — no
`debugpy`, no Jupyter stack, no `GitPython`. This rules out the possibility
that the SBOM's contamination came from a slightly dirtier resolution of
*this project's own* dependencies; a correct resolution looks nothing like
it. The contamination in `ddf_spdx.json` necessarily came from a broader,
unrelated environment, strengthening F35 from "plausible" to "the only
remaining explanation." Combined with the commit mismatch above (F34), the
SBOM should be treated as unreliable evidence for the gate it's meant to
satisfy and regenerated from a clean checkout at the correct commit before
`release_signing_sbom` can legitimately be marked passed.

With a correct lockfile now available, a full `pip-audit` or `safety check`
run against the exact pinned versions (`fastapi` 0.142.2, `sqlalchemy`
2.1.2, `pynacl` 1.6.2, `cryptography` 50.0.2, `pyjwt` 2.15.1, `redis` 5.3.1,
and the rest) would be straightforward to add to the execution phase — this
sandbox has no network access to run it here.

## Remediation round 2 — confirmed by test (commit range `e60b23e..f227ad1`)

A second remediation pass, on branch `fix/revocation-and-production-readiness`
(branched from the first remediation commit `e60b23e`, not from `main`),
addressed R1, F2, F6, F13, and a previously-noted minor gap in one commit
each, verified with literal full-suite output at each step:

| Commit | Finding | Regression test |
|---|---|---|
| `04bebed` | R1 (cascade shadowing) | `test_cascade_upgrade_is_not_shadowed` |
| `2bb8470` | Legacy GET `/v1/revocations/{id}` gap + retirement of dead legacy route handlers | `test_legacy_authorize_route_is_retired`, `test_legacy_revocation_status_route_is_retired` |
| `918e9a8` | F13 (startup guard) | `test_unsafe_production_config_is_caught_at_startup` |
| `344fc86` | F6 (revoked key still authenticates) | `test_revoked_identity_key_cannot_authenticate` |
| `c25d589` | F2 (capability survives revocation) | `test_capability_cannot_be_consumed_after_authority_revocation` |
| `f227ad1` | lint cleanup only | — |

**Full suite after all fixes:** `pytest tests/ -v` → **147 passed, 1 warning,
0 failed** (literal output reviewed). `ruff check src tests` → all checks
passed. `mypy src/ddf` → no issues in 52 source files. `git status --short`
clean, correct branch (`fix/revocation-and-production-readiness`), `git tag
--points-at` empty for both the new HEAD and the base commit `e60b23e` —
release-tag integrity preserved across both remediation rounds.

**Approach confirmed for the legacy-GET gap:** rather than extending
`LegacyMutationGuard` again, `delegation_endpoints.py` (-159 lines),
`authorization_endpoints.py` (-44 lines), and `revocation_endpoints.py`
(-76 lines) were deleted outright, since their functionality is fully
covered by the authenticated `/v1/commercial/*` equivalents. This is a
cleaner fix than patching the guard a third time.

**Minor residual item, not a security finding:** coverage data shows
`src/ddf/api/routes/grants.py` now at 0% (39/39 lines uncovered) — it held
Pydantic schemas for the now-deleted `delegation_endpoints.py` and appears
orphaned. Harmless dead code; worth a future cleanup commit.

## Execution results (batch 15 — live stack, commit `c96b5bf5d1a30604ab9c2e24775477113fae5354`)

**What ran:** `docker compose up -d` (Postgres + OpenFGA), `alembic upgrade head`,
`pytest tests/integration/test_api_routes.py::test_authority_lifecycle_via_http -v`,
`pytest tests/ -v` (full suite), `pip-audit`. All output shown was literal
command output, not summarized.

**Results:**
- Headline chain: **PASSED**, confirming F1+F23+F24+F27+F33 by execution (see
  updated table entry above).
- Full suite: **135 passed, 0 failed.** No regressions found anywhere in the
  project's own test suite against this commit.
- `pip-audit`: 9 CVEs across 3 packages — `jupyterlab` (3, environment
  contamination, F35), `tornado` (3, same contamination, pulled in as a
  `jupyterlab` dependency), `urllib3` (3, a real DDF dependency installed
  below its locked-safe version, F41). Zero CVEs reported against DDF's own
  core dependencies (`fastapi`, `pydantic`, `sqlalchemy`, `pynacl`,
  `cryptography`, etc.) at the versions actually installed.
- `docker compose ps` showed `ddf-openfga` as `Running` but
  **`(unhealthy)`** — its own healthcheck (`curl http://localhost:8080/healthz`)
  was failing. All 135 tests passed regardless, consistent with OpenFGA
  being disabled by default (`DDF_OPENFGA_ENABLED` unset) — no test in the
  existing suite depends on a genuinely healthy OpenFGA. Flagged as an
  operational note, not a new security finding, and not chased further.
- Coverage data from the full-suite run shows `commercial/production_readiness.py`
  at only 34.40% line coverage — confirming by measurement, not just
  inference, that most of the HYPOTHESIS-level findings in that file (F6's
  drill behavior, F13 startup guard, F14 idempotency, F15 rate limiting,
  F16 metrics, F17 evidence bundles, F19 did:web, F20 environment
  defaults) are **not exercised by the project's own test suite at all** —
  the gap these findings describe is real, not a misreading of tests that
  already cover it.

**What has not yet run:** the `regression-tests/` and `reproducers/` files
written during this assessment (8 files, targeting R1, F2, F3, F6, F13,
F17, F28) were not copied into `tests/` and executed in this batch. These
remain the next concrete step — the only way to move F2, F3, F6, F13, F17,
F28, and R1 from HIGH-CONFIDENCE/HYPOTHESIS to CONFIRMED-BY-TEST or refuted.

## Commit SHA and working-tree status: confirmed

The commit SHA and working-tree status were initially reported via prose
without literal command output shown (flagged and held at INFERRED pending
verification). Literal output was then provided:
`git rev-parse HEAD` → `c96b5bf5d1a30604ab9c2e24775477113fae5354`;
`git status --short` → `?? poetry.lock` (git's exact porcelain syntax for a
single untracked file). Both are now OBSERVED. The SHA is consistent with
what was reported earlier, and the mismatch with the SBOM's embedded commit
hash (`f70e637b989b9ebcaa2ff434be242a62595cc9e1`, see F34) stands confirmed.

## F35, confirmed at its root cause by the generator script

`generate_spdx_sbom.py` builds the SBOM via `importlib.metadata.distributions()`,
enumerating every package installed in whatever Python environment the
script happens to run in — no virtualenv isolation, no diff against
`pyproject.toml`'s declared dependencies, no distinction between "what the
production container ships" and "what's installed locally." This confirms
the dev/notebook-tooling contamination found earlier (`debugpy`, `jupyter`,
`GitPython`, etc.) isn't a one-off mistake in a single artifact — the tool
itself has no mechanism to prevent this, and will reproduce the same
problem on every future regeneration unless it's explicitly run inside a
clean, production-only environment (e.g., inside the actual Docker build,
or against a locked production-only virtualenv).

## Release identity: new evidence

`generate_spdx_sbom.py` embeds `git_sha()`'s live output directly into the
SBOM's `documentNamespace`. The SBOM reviewed earlier had
`documentNamespace: ".../spdx/f70e637b989b9ebcaa2ff434be242a62595cc9e1"` —
this is very likely the actual commit this assessment has been conducted
against, though unverified (no independent confirmation this is still HEAD,
or that nothing changed after that SBOM was generated). Record this as a
candidate commit SHA in `00-target-identity.md`, not a confirmed one.

Separately, `Chart.yaml`'s `appVersion: "1.0.0rc3"` is a fourth
independent version data point. The tally is now 3-to-1 for `1.0.0rc3`
(`src/ddf/__init__.py`, the SBOM, the Helm chart) versus `1.0.0rc5`
(`pyproject.toml` alone, backed only by `test_release_identity.py`'s pin).
This reframes the earlier observation: it now looks more likely that
`1.0.0rc3` is the actually-intended/shipped version, and `pyproject.toml`
plus its dedicated test are the artifacts that drifted from it — not the
reverse.

`release_gate.py` also reveals the expected production file layout
(`deploy/production/Dockerfile`, `deploy/k8s/ddf-production.yaml`,
`deploy/helm/ddf/Chart.yaml`, `deploy/terraform/main.tf`,
`deploy/alerts/ddf-prometheus-rules.yaml`, `docs/COMMERCIAL_READINESS.md`,
`docs/OPERATIONS.md`, `docs/INCIDENT_RESPONSE.md`) — confirming
`deploy/terraform/main.tf` exists and has not been reviewed in this
assessment.

## F17, refined by the project's own test

`test_production_readiness.py::test_evidence_bundle_offline_verifier_detects_tamper`
builds an **unsigned** bundle (no `DDF_EVIDENCE_BUNDLE_SIGNING_KEY_B64` set)
and asserts `verify_evidence_bundle(bundle)` is `True` for it, then tampers
a record and confirms verification then fails. This confirms the earlier
reading: "verification" here means only that the records are internally
consistent with the stated hash, never that the bundle came from a trusted
party. This is evidently the intended design, not an oversight — but it is
a materially weaker guarantee than `COMMERCIAL_READINESS.md`'s phrase
"offline integrity/**signature** verification" suggests to a reader relying
on it for compliance evidence. Recommend either requiring a signature for
any bundle used as compliance evidence, or rewording the documentation to
make clear that unsigned bundles offer only tamper-detection of the export
itself, not authenticity of its source.

## Test-suite coverage gap directly underlying the headline finding

`test_stolen_authority_v01.py` is a genuinely good test — it proves PoP
correctly rejects a signature from the wrong private key — but it only ever
constructs authorities with a real, non-empty `holder_public_key`. No test
in the files reviewed exercises `verify_proof_of_possession` or
`verify_authority_signature` against an authority with
`holder_public_key=""` and `proof=None` — which is exactly the state
`GrantService.create_grant` and `DelegationService.create_delegation`
produce by default, and exactly the state the legacy routes always use.
The suite thoroughly tests "wrong key"; it has no test for "no key at all."

## F37 (new) — alerting covers availability only, not the security events the runbook names

`ddf-prometheus-rules.yaml` defines two alerts (5xx-rate, p99-latency), both
built on `MetricsMiddleware`'s HTTP counters. `INCIDENT_RESPONSE.md` names
"replay-detection surge," "unexplained capability consumption,"
"evidence-chain integrity failure," "OpenFGA policy drift," and
"tenant-isolation or IDOR report" as security events requiring immediate
action — none has a corresponding alert rule. There is no automated signal
for a spike in 401/403 responses, for `/v1/audit/verify` returning
`valid: false`, for `/ready/dependencies` degrading, or for rate-limit/
idempotency-conflict volume. The incident-response process assumes
detection the monitoring configuration doesn't provide.

## Release-evidence directory (release-evidence/*)

All nine gate files referenced by `release-gates.json`
(`backup-restore.json`, `compliance.json`, `incident-owner.json`,
`key-compromise.json`, `legal-review.json`, `load-ha-chaos.json`,
`pentest.json`, `release-signing-sbom.json`, `slo-observation.json`) are
empty template stubs — `status: "pending"`, blank `reviewer`,
`approved_at`, `commit`, `summary`, and `artifacts` — all created within the
same minute (`2026-08-15T00:22:0X`), evidently scaffolding generated
together rather than real records. `release-evidence/README.md` defines
sound validity criteria for a gate (status `passed`, SHA-256 match in the
gate manifest, populated reviewer, not expired, stable-release verifier
acceptance) and states explicitly: "No DDF script may self-declare an
independent pentest, legal approval, or compliance certification." This
assessment does not and should not be used to mark `pentest.json` as
passed — consistent with `PENTEST_SCOPE.md`'s own statement to the same
effect, reviewed earlier.

The one substantive gate artifact actually supplied, `ddf_spdx.json`
(meant to satisfy `release_signing_sbom`), is itself incorrect per F34–F36
above — so even once the governance process around it is followed, the
underlying document needs to be regenerated correctly first.

## Infrastructure observations (Dockerfile, ddf-production.yaml, model.json)

- **Dockerfile:** runs as non-root UID 10001, matching the k8s manifest's
  `runAsUser: 10001`; installs `.[production,openfga]`, so the actual
  deployed container image always has the dependencies `main.py` imports at
  module load — this resolves part of F21 for this specific deployment path
  (a bare `pip install ddf` as a library elsewhere would still hit it).
- **ddf-production.yaml**, strong points: `runAsNonRoot`, `readOnlyRootFilesystem`,
  all capabilities dropped, no privilege escalation, `automountServiceAccountToken: false`,
  seccomp `RuntimeDefault`, a `PodDisruptionBudget`, and readiness/liveness
  probes correctly pointed at the newer `/ready/dependencies` and `/livez`
  endpoints rather than the legacy, info-leaking `/ready` (F11) — the legacy
  route remains mounted and reachable regardless, but isn't used for health
  checks here.
- **F32 (new):** the `NetworkPolicy`'s egress rule is `- {}`, which in
  Kubernetes semantics allows all outbound traffic to any destination. This
  provides zero containment if the did:web/OIDC/remote-intent surface (F19)
  is ever wired to a reachable route — recommend scoping egress explicitly
  to Postgres, OpenFGA, Redis, and any configured OIDC/KMS endpoints.
- Minor: `image: ghcr.io/arkstride/ddf:VERSION` is an unresolved template
  placeholder — fine if substituted by CI/CD (not reviewed), otherwise not
  deployable as-is.
- **model.json** (OpenFGA authorization model): defines `user`/`agent`/
  `organization`/`resource` types with viewer/editor/operator relations and
  **no tenant-scoping concept anywhere in the type model itself** — this
  confirms F5c (OpenFGA objects not tenant-namespaced) at the schema design
  level, not merely in how the API calls it.

## Minor new observations

- `tests/conftest.py`'s `test_db` fixture opens a real session against
  whatever `DATABASE_URL`/`settings.database_url` is configured, with no
  transaction rollback or per-test isolation — tests accumulate real rows
  in whatever database is configured (dev convenience, not a security
  finding, but worth fixing before scaling the test suite).
- `test_release_identity.py` pins `pyproject.toml`'s version to
  `1.0.0rc5`, resolving which of the two disagreeing version strings is
  authoritative — but it does not check `src/ddf/__init__.py`'s
  `1.0.0rc3` against the same value, so that drift is not caught by CI.
- `test_kubernetes_shutdown_contract.py` references
  `deploy/k8s/ddf-production.yaml` (not reviewed in this assessment) and
  confirms the project has at least considered graceful-shutdown behavior
  (rolling update, termination grace period, preStop hook) — operational
  hygiene, not a security finding.

## Secrets review

No live secrets observed. Dev-default credentials
(`ddf`/`ddf_password`) appear in `docker-compose.yml` and `.env.example`
and are clearly placeholders, not reproduced here beyond that description.
If any of these defaults have been reused in a real environment, rotate
them per standard practice.
