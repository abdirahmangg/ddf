# 00 — Target Identity

Status legend: OBSERVED / DEMONSTRATED / INFERRED / NOT TESTED

## Delivery method (important caveat)

This assessment is **source-assisted from pasted/uploaded files across many
chat turns, from an assessment environment with no network or Docker
access**, not from a live checkout the assessor controlled directly. File
coverage reached the full tracked tree (confirmed against a complete
`git ls-files` inventory), and the commit SHA below was independently
confirmed via literal terminal output relayed from a separate GitHub
Codespace session. **No finding in this register has been confirmed by this
assessment's own execution** — everything is from reading source, except
one Critical finding chain confirmed via the project's own existing,
unexecuted-by-us test (`tests/integration/test_api_routes.py`, see
`05-findings-register.md` §05a). Execution against a live stack is the
necessary next phase; see the Action Needed section below.

## Identity facts

| Item | Value | Status |
|---|---|---|
| Project | DDF (Dynamic Delegation Fabric); MAAP is a planned separate commercial product | OBSERVED |
| Repository | github.com/abdirahmangg/ddf, branch `main`, public, 26 commits (as of first contact) | OBSERVED (web fetch, not git) |
| Owning org | Arkstride | OBSERVED |
| Package version (pyproject.toml) | `1.0.0rc5` | OBSERVED |
| Package version (src/ddf/__init__.py) | `1.0.0rc3` | OBSERVED — **inconsistent with pyproject.toml** |
| README badge | "v0.1 (Alpha)" | OBSERVED — inconsistent with both rc versions above |
| Target stable release | `v1.0.0` (release-gates.json) | OBSERVED |
| Python | >=3.12 | OBSERVED |
| License | Apache-2.0 | OBSERVED |
| Commit SHA | **Confirmed.** `git rev-parse HEAD` → `c96b5bf5d1a30604ab9c2e24775477113fae5354`, shown as literal command output and consistent with what was reported earlier. Does **not** match the SBOM's embedded commit (`f70e637b989b9ebcaa2ff434be242a62595cc9e1`) — see F34. | OBSERVED |
| Working tree status | **Confirmed.** `git status --short` → `?? poetry.lock` (git's porcelain syntax for one untracked file, no other changes). | OBSERVED |
| `poetry.lock` content | **Confirmed.** The file's specificity (151+ packages, exact hashes, versions matching `pyproject.toml`'s `dev`/`openfga`/`production` extras precisely) is treated as genuine content. | OBSERVED |
| Container image IDs | NOT AVAILABLE — nothing built from this assessment; a devnet build is planned as the next phase | NOT TESTED |
| Dependency lock state | No lockfile supplied; `pyproject.toml` uses `>=` floors throughout, with the single pinned exception `openfga-sdk==0.4.1` | OBSERVED |

**Process finding (not a security vulnerability):** four disagreeing version
identifiers are live simultaneously, and the split is 3-to-1:
`src/ddf/__init__.py`, the generated SBOM, and the Helm chart's `appVersion`
all say `1.0.0rc3`; only `pyproject.toml` says `1.0.0rc5`, backed solely by
`tests/test_release_identity.py`'s pin (which checks `pyproject.toml` only,
not the other three). This majority suggests `1.0.0rc3` is more likely the
actually-intended version, and `pyproject.toml`/its test are the drifted
outlier — but this is an inference, not a confirmed fact. Resolve all four
strings to one source of truth, confirm the candidate commit SHA above
against a real `git` checkout, and record both before any release decision
is made from this register.

## Material reviewed

A complete `git ls-files` inventory (130 tracked files, obtained via a
GitHub Codespace, batch 13) was cross-referenced against everything
reviewed across all upload batches. Coverage is now effectively complete:

- **`src/ddf/**` — 100% reviewed.** Every one of the ~55 tracked files under
  the application source tree, including `db/models.py` (the actual ORM
  classes), `cli/main.py`, and every module under `api/`, `authority/`,
  `authorization/`, `commercial/`, `crypto/`, `db/`, `delegation/`, `demo/`,
  `identity/`, `policy/`, `provenance/`, `revocation/`.
- **`scripts/**` — 100% reviewed** (8 files: the SBOM generator, release
  gate verifier, external evidence validator, and all four drill/load
  scripts).
- **`deploy/**` — 100% reviewed** (Prometheus alert rules, Helm chart,
  Kubernetes manifest, the production Dockerfile at its correct path
  `deploy/production/Dockerfile`, and `deploy/terraform/main.tf`).
- **`docs/**` — 100% reviewed**, including the `docs/release-assurance/`
  subfolder (`COMPLIANCE_EVIDENCE.md`, `LEGAL_REVIEW.md`,
  `PENTEST_SCOPE.md`, `SLO_POLICY.md`) and `docs/COMMERCIAL_READINESS.md`,
  `OPERATIONS.md`, `INCIDENT_RESPONSE.md` at their correct paths (not repo
  root, as earlier notes assumed — content was identical, only the path
  was wrong).
- **`examples/**` — 100% reviewed** (`__init__.py`,
  `procurement/__init__.py`, `procurement/README.md`, `procurement/demo.py`).
- **`release-evidence/**` and `release-gates.json` — 100% reviewed** (all 9
  gate stub files plus the directory README and the SBOM).
- **`openfga/model.json`** — reviewed.
- **`tests/**` — all but one file reviewed**: `tests/conftest.py`,
  `tests/integration/test_api_routes.py`, `tests/property/test_invariants.py`,
  every file under `tests/security/` (10 files), and every file under
  `tests/unit/` except `test_attenuation.py`.
- Top-level docs: `README.md`, `SECURITY.md`, `GOVERNANCE.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `pyproject.toml`,
  `docker-compose.yml`, `.env.example`, `alembic.ini`,
  `.github/workflows/ci.yml`, and all three `alembic/versions/*.py`
  migrations plus `alembic/env.py`.

## NOT reviewed (complete, final list — zeroed out against `git ls-files`)

| File | Priority | Note |
|---|---|---|
| `tests/unit/test_attenuation.py` (13,416 bytes) | **The one substantive gap** | A dedicated unit-test file for the core attenuation invariant, distinct from `tests/property/test_invariants.py` and `tests/security/test_privilege_escalation_v01.py` (both already reviewed) |
| `Makefile` | Minor | Uploaded twice but content never actually shown; defines the `make up`/`make serve`/`make test`/etc. targets referenced throughout the other docs |
| `.gitignore` | Trivial | Only a line count (218) confirmed, never content |
| `LICENSE` | Trivial | Presumed stock Apache-2.0; never shown to confirm it's unmodified |
| `NOTICE` | Trivial | Presumed to match the trademark notice already quoted in `GOVERNANCE.md` |
| `alembic/README`, `alembic/script.py.mako` | Negligible | Standard Alembic scaffold boilerplate (58 and 704 bytes) |

`ddf-main.zip` was uploaded once at the start but never opened — opening
archives is outside this environment's policy.

## Status: static review complete. Next phase: execution

Target identity, file coverage, and the findings register are complete as
of commit `c96b5bf5d1a30604ab9c2e24775477113fae5354`. The remaining work is
execution, not more source:

1. **Devnet reserved as the live stack for the execution phase** (per
   decision at the close of this assessment). Provision it per
   `docker-compose.yml` (Postgres + OpenFGA) plus Redis (required by
   `production_readiness.py`'s rate-limiting/idempotency paths, not present
   in the dev compose file — add it separately or via
   `DDF_REDIS_URL` pointed at a devnet Redis instance).
2. Install from `poetry.lock` if reproducing the exact locked dependency
   set is wanted (it is currently untracked by git and unused by the
   project's own `Makefile`/`Dockerfile`/`ci.yml`, which install from
   `pyproject.toml`'s floating bounds — see F41); otherwise follow
   `make install-dev && make up` as documented, noting F40 (`install-dev`
   omits the `production` extra that `main.py` unconditionally imports).
3. Run every reproducer in `regression-tests/` and `reproducers/` against
   the devnet stack and record actual results in `06-retest-report.md`.
   Priority order: `test_legacy_authorize_unauthenticated.py` (the
   headline chain, currently CONFIRMED-BY-EXISTING-TEST and one execution
   away from CONFIRMED-BY-TEST), then `test_audit_events_unauthenticated.py`
   (F28), `test_revoked_key_still_authenticates.py` (F6), then the rest.
4. Optionally close the last trivial file-coverage gaps
   (`alembic/README`, `alembic/script.py.mako` — boilerplate, negligible
   priority) and `tests/unit/test_attenuation.py` was received in batch 14
   and is reflected in the register; no outstanding file gaps remain that
   are expected to matter.
5. Run `pip-audit` or `safety check` against `poetry.lock`'s pinned
   versions on the devnet stack (network access available there, unlike
   this assessment environment) to close out the dependency-CVE question
   left open throughout this review.
