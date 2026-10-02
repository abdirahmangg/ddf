# 06 — Retest Report

Status: **execution started.** First live-stack run completed against
commit `c96b5bf5d1a30604ab9c2e24775477113fae5354` in a GitHub Codespace
with Docker available. No remediation has been applied yet — this is a
baseline execution run, not a post-fix retest.

## Environment

- Commit: `c96b5bf5d1a30604ab9c2e24775477113fae5354`
- Python: 3.14.2 (note: `pyproject.toml` requires `>=3.12`; `ci.yml` pins
  3.12 specifically — this run used a newer interpreter than CI. All tests
  passed regardless, but this is not an exact replica of the CI
  environment.)
- Docker: client/server 29.8.0-1
- Services: `ddf-postgres` (healthy), `ddf-openfga` (running, but reported
  `unhealthy` by its own healthcheck — not chased down further)
- Install: `pip install -e ".[dev,openfga,production]"`, `alembic upgrade head`

## Run 1 — headline finding

Result: **PASSED.**

This confirms, by execution, the Critical chain F1+F23+F24+F27+F33: an
unauthenticated `POST /v1/grants`, `POST /v1/delegations/{id}`, and
`POST /v1/authorize` sequence produces a real `ALLOW` decision with no
signature anywhere in the path. Status upgraded from
CONFIRMED-BY-EXISTING-TEST to CONFIRMED-BY-TEST (EXECUTED).

## Run 2 — full project test suite

Result: **135 passed, 0 failed, 2 deprecation warnings** (both about
`@app.on_event` being deprecated in favor of lifespan handlers — this is
the exact mechanism F13 questions, but no test in the existing suite
actually exercises whether `validate_production_environment()` fires at
real app startup; `test_production_guard_rejects_unsafe_configuration`
calls the function directly, not via the app lifecycle).

No regressions anywhere in the existing suite at this commit.

## Run 3 — dependency audit

Result: 9 known vulnerabilities across 3 packages:

| Package | Installed | Vulnerabilities | Fixed in | Relevance |
|---|---|---|---|---|
| `jupyterlab` | 4.6.3 | PYSEC-2026-4055/4056/4057 | 4.5.11, 4.6.4 | Not a DDF dependency — environment contamination (CONFIRMS F35) |
| `tornado` | 6.5.8 | GHSA-chx6-46f5-w4vp, GHSA-c2m8-h5v5-343r, GHSA-3hv7-mjh2-fv65 | 6.5.9 | Not a DDF dependency — pulled in by `jupyterlab` |
| `urllib3` | 2.7.0 | PYSEC-2026-4175/4176/4177 | 2.8.0 | A real DDF dependency, installed below the version `poetry.lock` already pins (2.8.0) — directly demonstrates F41 |

`ddf` itself was skipped ("not found on PyPI," expected for an unpublished
local package). No CVEs reported against any of DDF's own core, declared
dependencies at the versions actually installed.

## Outstanding — not yet run

The 8 reproducer/regression files written during the static-review phase
have **not** been copied into `tests/` or executed:

- `regression-tests/test_legacy_authorize_unauthenticated.py` — superseded
  in practice by the headline test's real pass above, but still useful as
  an over-the-wire HTTP check distinct from the in-process ASGI test.
- `regression-tests/test_revocation_cascade_override.py` (R1)
- `regression-tests/test_capability_survives_revocation.py` (F2)
- `regression-tests/test_startup_guard_runs.py` (F13 — the one test that
  would actually settle whether the on_event/lifespan interaction matters)
- `regression-tests/test_evidence_bundle_forgery.py` (F17)
- `reproducers/test_audit_events_unauthenticated.py` (F28)
- `reproducers/test_revoked_key_still_authenticates.py` (F6)
- `reproducers/test_nan_amount_bypass.py` (F3)

These need fixture adaptation to the project's actual `conftest.py` in
several cases (noted in each file's docstring) before they'll run cleanly.
This is the next concrete step.

## Run 4 — remediation round 1 (commit `e60b23e`, branch `fix/unauthenticated-authority-bypass`)

Fixed F1+F23+F24+F27+F33 (unauthenticated authority issuance and
authorize) and the `urllib3` CVE (F41). Verified via literal `git log`/
`git diff --stat`/full diff review and a passing manual unauthenticated
HTTP replay (`POST /v1/grants`, `/v1/delegations/{id}`, `/v1/authorize` all
→ 410). Base commit's tag (`v1.0.0rc5` → `c96b5bf5d1a30604ab9c2e24775477113fae5354`)
confirmed untouched. Full diff reviewed line by line; two unplanned
additions were found riding along in the same commit (`commercial/evidence.py`
new `verify_evidence_chain()`, `commercial/models.py` new
`CommercialRevocationRequest`) — legitimate, necessary consequences of the
fix (a revocation route had to exist once the legacy one was gated), but a
process note that this wasn't a fully scoped, single-purpose commit.

## Run 5 — remediation round 2 (commits `04bebed`..`f227ad1`, branch `fix/revocation-and-production-readiness`)

Fixed R1, F2, F6, F13, and the legacy `GET /v1/revocations/{authority_id}`
gap — six atomic commits, one per finding (plus one lint-only commit),
branched correctly from the round-1 fix rather than from `main`. Full
literal `pytest tests/ -v` output reviewed: **147 passed, 0 failed, 1
warning.** `ruff check` and `mypy` both clean. `git tag --points-at` empty
for both the new HEAD and the round-1 base commit — no tag touched across
either remediation round.

**Findings now closed, confirmed by test (not merely by reading):**

| Finding | Status |
|---|---|
| F1 + F23 + F24 + F27 + F33 (headline chain) | REMEDIATED |
| F28 (unauthenticated audit read) | REMEDIATED (via the same guard extension) |
| F41 (vulnerable urllib3 in environment) | REMEDIATED |
| R1 (cascade shadowing) | REMEDIATED |
| F2 (capability survives revocation) | REMEDIATED |
| F6 (revoked key still authenticates) | REMEDIATED |
| F13 (startup guard not wired to lifespan) | REMEDIATED |
| Legacy `GET /v1/revocations/{id}` enumeration gap | REMEDIATED (route deleted) |

## Run 6 — adversarial bypass attempts against the six round-2 fixes (branch `fix/revocation-and-production-readiness`, no files changed)

Closed the gap noted after run 5: attempted to defeat each of the six
already-fixed findings rather than just re-running their own regression
tests. Result: **all six fixes held** — no bypass found for the headline
chain, the legacy route retirements, R1's cascade-escalation ordering,
F6's key-rotation edge cases, or F13's safe/unsafe startup boundary. Two
genuine new bypasses were found, outside the six already-fixed items:

- **F3** (amount constraint bypass) — confirmed exploitable: 6/6 adversarial
  cases (missing/NaN/negative amount × authorize/mint) returned `ALLOW`
  where they should `DENY`/raise.
- **F42** (new) — a capability-consumption-vs-revocation race (A4):
  confirmed exploitable via genuine concurrent execution (not a sequential
  approximation) — a capability was consumed successfully after a
  concurrent revocation had committed.

No files were changed in this run — confirmation only, per instruction, to
scope the fix as separate follow-up work.

## Run 7 — fixes for F3 and F42 (branch `fix/constraint-and-consumption-race`, branched from the run-5 HEAD)

**F3:** red confirmed first — 6 failing regression tests
(`test_authorize_rejects_invalid_amount_with_max_amount[missing|nan|negative]`,
`test_mint_capability_rejects_invalid_amount_with_max_amount[missing|nan|negative]`)
reproduced the exact bypasses found in Run 6. Fixed in `0b4a0d6` via a
shared validator in `authority/constraints.py`, used by both
`authorization/service.py` and `commercial/capabilities.py` rather than
duplicated logic. All 6 now pass. A companion commit `0ccdfbf` updated one
pre-existing test that relied on the old lenient behavior (supplied a
valid amount instead of omitting it, since a `max_amount`-constrained
authority now correctly requires one).

**F42:** red confirmed first — a real concurrent regression test (separate
asyncio tasks, separate DB sessions, explicit synchronization so the
revoke's commit lands inside the consume's check-to-commit window)
reproduced the race: `decision: ALLOW` on a since-revoked authority. Fixed
in `737bfba` via `pg_advisory_xact_lock` keyed on `authority_id`, taken by
both `consume_capability` and `RevocationService.revoke`, matching the
pattern already established in `commercial/evidence.py`. Re-run 20 times:
**20/20 pass** — the race no longer reproduces under repeated runs.

**Final verification after both fixes:**
- Full suite: `pytest tests/ -v` → **158 passed, 0 failed, 1 warning.**
- `ruff check src tests` → all checks passed.
- `mypy src/ddf` → no issues in 52 source files.
- A second, independent adversarial pass re-attempted all of the original
  bypasses (amount cases + 20x concurrency loop) directly against the fix,
  not just the regression tests the fix shipped with — all held.
- `git status --short` clean, branch `fix/constraint-and-consumption-race`,
  no tag points at HEAD.

A fourth commit, `fc0f584` ("fix: preserve exact constrained amount
comparisons"), was not part of the original remediation prompt. Reviewed
line by line: `cast(float, amount)` is a typing-only annotation (a no-op
at runtime, not an actual conversion), so the negative/exceeds-max
comparisons still operate on the original un-converted value in both the
before and after versions. The only real behavior change is for integer
amounts large enough to overflow Python's `float()` conversion (beyond
~1.8×10³⁰⁸): previously misclassified as `AMOUNT_NOT_FINITE` via a caught
`OverflowError` from `isfinite()`; now correctly falls through to an exact
integer comparison against `max_amount` and is rejected as
`AMOUNT_EXCEEDS_EFFECTIVE_AUTHORITY` instead. Both versions always reject
such values — this is a precision/correctness refinement for an extreme
edge case, not a reopening of F3 and not unrelated scope. Cleared.

**Round 2/3 remediation is now fully closed: ten findings remediated and
confirmed by test** — F1+F23+F24+F27+F33, F28, F41, R1, F2, F6, F13, the
legacy-GET gap, F3, and F42 — with adversarial bypass attempts against all
of them holding.

## Not yet addressed

- F4, F5a–c, F7–F12, F14–F22, F32, F34–F40 remain as documented in
  `05-findings-register.md` — none were in scope for any remediation round
  so far.
- `src/ddf/api/routes/grants.py` is now orphaned dead code (0% coverage,
  per round-2 coverage data) — cosmetic cleanup, not a security item.
