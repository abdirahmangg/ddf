# 07 — Final Report

**This assessment is not a substitute for the independent pentest release gate.** DDF's
own `release-gates.json` and `PENTEST_SCOPE.md` state that DDF automation/internal
review cannot mark that gate passed, and this review — done by Claude, source-assisted,
without code execution — is exactly that kind of internal review. Treat everything below
as input to the external assessor's scope, not as a replacement for it.

## Shipping status (final)

Across three remediation rounds plus adversarial bypass attempts, **ten findings are
remediated and confirmed by test**, including the original Critical chain:

1. F1+F23+F24+F27+F33 — unauthenticated authority mint/delegate/authorize

2. F28 — unauthenticated cross-tenant audit read

3. F41 — vulnerable `urllib3` from an unused lockfile

4. R1 — revocation cascade shadowed by an earlier non-cascading revoke

5. F2 — capability usable after its authority's revocation (simple case)

6. F6 — revoked identity key still authenticates

7. F13 — production startup guard not wired to the real app lifespan

8. Legacy `GET /v1/revocations/{id}` unauthenticated enumeration

9. F3 — missing/NaN/negative amount bypasses the `max_amount` constraint

10. F42 — capability consumption racing a concurrent revocation (found only during adversarial retesting, not the original static review)

Every one of the ten has: a regression test that failed before the fix and passed after,
a fix landed in its own commit, a full-suite run with literal pass/fail output reviewed,
and — for all ten — a dedicated adversarial bypass attempt against the shipped fix, not
just its own regression test. Two of those attempts (F3, F42) found real additional
gaps, which were then fixed and re-verified the same way.
**Everything else in the register (F4, F5a-c, F7–F12, F14–F22, F32, F34–F40) remains
open, undisturbed, and out of scope for what's shipping now.** None were claimed fixed;
none should be treated as such.

## Status note on wording

Per the engagement rules, this report avoids "secure," "fully secure," or "no
vulnerabilities" because neither is supportable from what was done here. The honest
statement is: **one Critical-severity finding chain (unauthenticated authority mint,
delegate, and authorize) is CONFIRMED-BY-TEST (EXECUTED)** — run live against a
Postgres+OpenFGA stack at commit `c96b5bf5d1a30604ab9c2e24775477113fae5354`, in a GitHub
Codespace, with literal command output verified: `pytest
tests/integration/test_api_routes.py::test_authority_lifecycle_via_http -v` →
**PASSED**. This is the strongest confidence tier this assessment uses. The full project
test suite also ran clean (135 passed, 0 failed), and a live `pip-audit` run both
confirmed F35 (environment contamination) and F41 (an actual vulnerable dependency
version, `urllib3` 2.7.0, installed in place of the lockfile's pinned 2.8.0) by direct
observation rather than inference. See `06-retest-report.md` for full execution detail.

## A. Executive technical summary

DDF implements a real, carefully-designed authority-attenuation and delegation-chain
model on its commercial (`/v1/commercial/*`) API surface, with the strongest control in
the codebase being `load_authority_chain`'s full re-derivation and re-validation of the
delegation chain from the database on every authorize/mint/delegate call. However, a
separate, older "legacy" API surface (`/v1/grants`, `/v1/delegations/{id}`,
`/v1/authorize`, `/v1/revocations`, `/v1/audit/*`) remains mounted unconditionally and
is either entirely ungated (`/v1/authorize`, `/v1/audit/*`) or gated only when an
operator explicitly sets `DDF_COMMERCIAL_ENFORCE=true`, which is not the default.
Combined with the legacy grant/delegation services defaulting to no holder key and no
signature when called without one — which the legacy routes always do — this produces an
unauthenticated, unsigned, end-to-end authority mint → delegate → authorize chain. This
is not merely inferred from reading: the project's own test suite
(`test_api_routes.py::test_authority_lifecycle_via_http`) performs this exact sequence
against the real application factory with no authentication headers at all and asserts
the resulting `ALLOW` decision as correct, expected behavior.
Subsequent review of the project's own test suite showed this is not an isolated routing
oversight: `GrantService` and `DelegationService`'s `signing_key` parameter — the
mechanism that would bind an authority to a real holder key and signature — is optional,
defaults to producing an unsigned, unkeyed authority, and is supplied by **no real entry
point** anywhere in the codebase reviewed: not the HTTP routes, not the CLI
(`ddf/cli/main.py`, same gap independently, see F33), and not the unit test suite, which
universally exercises authorities this way and treats the resulting unsigned `ALLOW` as
the correct, canonical outcome across `test_authorization_service.py`,
`test_delegation_service.py`, and `test_effective_authority.py`. The only place a real
signing key is ever constructed is a demonstration script. This is strong evidence the
authenticated-issuance code path exists in the service layer but was never wired to
anything a real caller actually uses.
A second high-severity issue, independent of the first, is that the legacy audit tables
(`provenance_events`, `authorization_logs`, and in fact every legacy table) have no
tenant column at all — confirmed in the actual ORM class definitions (`db/models.py`),
not just the migration — and the routes that read them require no authentication, giving
any caller visibility into every tenant's authorization history.
A third notable issue is that an identity-key revocation subsystem exists
(`ddf_identity_keys`, `revoke_identity_key`) but is entirely disconnected from the
actual authentication path, which reads only `ddf_trusted_principals` — revoking a key
via the documented mechanism has no effect on whether that key can still authenticate.
A fourth, lower-severity but systemic observation: the Kubernetes deployment manifest is
otherwise well-hardened (non-root, read-only root filesystem, all capabilities dropped,
seccomp) but its `NetworkPolicy` permits unrestricted egress to any destination, which
would provide no containment if the never-gated did:web/OIDC/remote-intent SSRF surface
(F19) is ever made reachable.

## B. Exact target identity

See `00-target-identity.md`. **Commit SHA confirmed:**
`c96b5bf5d1a30604ab9c2e24775477113fae5354` (`git rev-parse HEAD`, literal output
verified). Working tree clean except one untracked `poetry.lock`. Package version is
inconsistently recorded as `1.0.0rc3` (3 sources: `src/ddf/__init__.py`, the SBOM, the
Helm chart `appVersion`) vs `1.0.0rc5` (1 source: `pyproject.toml`, backed only by
`test_release_identity.py`'s pin) across the same tree at this commit — resolve before
any release decision.

## C. Scope

Source-assisted static review of the DDF repository (`abdirahmangg/ddf`) at commit
`c96b5bf5d1a30604ab9c2e24775477113fae5354`, as supplied via chat upload across 14
batches plus a confirmed `git ls-files` inventory and confirmed `git rev-parse
HEAD`/`git status --short` output from a GitHub Codespace. No runtime testing, no
network access, no Docker in the assessment environment itself. See
`00-target-identity.md` for exactly which files were and were not reviewed.

## D. Methodology

Read every supplied file for the trust boundaries, invariants, and attack models
specified in the engagement brief (authority attenuation, tenant isolation, capability
replay/concurrency, PoP/signing, identity/key lifecycle, revocation, provenance
integrity, OpenFGA integration, OIDC/did:web/SPIFFE, business logic, supply chain). Each
finding is labeled with a confidence level (CONFIRMED-BY-READING, HIGH-CONFIDENCE,
HYPOTHESIS) reflecting how much of the relevant call path was actually read versus
inferred, per the distinction required by the engagement brief between OBSERVED,
DEMONSTRATED, INFERRED, and NOT TESTED. No finding reached DEMONSTRATED
(execution-confirmed) status in this environment.
*(NOTE for this handoff: this section describes the methodology of the original
static-review phase; the subsequent execution phase, described in the Shipping Status
section above and in `06-retest-report.md`, did reach execution-confirmed status for ten
findings.)*

## E. Architecture / security model observed

Two parallel API surfaces exist: a "legacy" v0.1-style unauthenticated surface and a
newer, tenant-scoped, signed-request "commercial" surface intended to supersede it
(`LegacyMutationGuard` exists specifically to retire the legacy mutation routes, but is
incomplete — see F1). Authority documents form a delegation chain validated end-to-end
on every use via `load_authority_chain`, with attenuation enforced by
`AttenuationEngine` + `ConstraintValidator` + `ResourceHierarchy`. Revocation is a
separate, ancestor-walking soft-invalidation mechanism. Provenance is a SHA-256
hash-chained append-only log, with an entirely separate, cryptographically stronger
"evidence envelope" mechanism on the commercial plane. A substantial "production
readiness" layer (TLS enforcement, distributed rate limiting, durable idempotency,
OpenFGA integration, OIDC/did:web/SPIFFE support, evidence bundle export) exists but
several of its controls were found to have wiring gaps (F13, F14, F6).

## F. Attack surface

See `01-attack-surface.md` for the full route-by-route and
trust-boundary-by-trust-boundary breakdown.

## G. Confirmed findings

**One finding chain is CONFIRMED-BY-TEST (EXECUTED):** F1+F23+F24+F27+F33, the headline
unauthenticated mint/delegate/authorize bypass — run live and observed to PASS against a
real Postgres+OpenFGA stack (05a and the Execution Results section in
`05-findings-register.md`).
**Two more findings are now confirmed by execution:** F35 (environment contamination —
`jupyterlab`/`tornado` directly observed installed, not a DDF dependency) and F41 (a
real DDF dependency, `urllib3`, installed below its locked-safe version due to the
unused lockfile).
The remaining findings reaching CONFIRMED-BY-READING — every function in the path read,
logic deterministic, no remaining ambiguity — are: F28 (also confirmed at the schema's
primary source, `db/models.py`), F6 (schema- confirmed, pending its own execution via
`reproducers/test_revoked_key_still_authenticates.py`), F5a, F18/F25 (the matcher
inconsistency itself), and F30. Full detail, severities, and reasoning are in
`05-findings-register.md`.
*(NOTE for this handoff: F6, R1, F2, F13, F3, F42, and the legacy-GET gap have since
been remediated and confirmed by test — see the Shipping Status section at the top of
this file and `06-retest-report.md`.)*

## H. Failed attack attempts / controls verified

See "Defenses verified by reading" in `05-findings-register.md`. Nothing in this
assessment constitutes a failed *execution* attempt, since no execution occurred — these
are controls observed to be correctly implemented on reading, which is a materially
weaker form of verification than an actual failed exploit attempt against a running
system.
*(NOTE for this handoff: this has since changed for the ten remediated findings — each
had a genuine adversarial bypass attempt made against its fix, with results logged in
`06-retest-report.md` Runs 6–7.)*

## I. Concurrency results

**Not tested.** No runtime was available. R5 (revocation check-then-insert race) and the
capability double-consumption property test specified in the engagement brief's test
plan (`03-test-plan.md`, P3) both require a live database and were not executed.
*(NOTE for this handoff: the capability double-consumption-under-revocation race (F42)
was subsequently found and fixed via real concurrent testing — see `06-retest-report.md`
Run 6/7. R5 itself remains untested.)*

## J. Supply-chain observations

`pyproject.toml` uses `>=` floors throughout except for one pinned dependency; no
lockfile was supplied. `ci.yml`'s security job runs `bandit` and `safety check` both
suffixed with `|| true`, so neither can ever fail the pipeline (F30). Base install
imports production-only dependencies at module load time in `main.py` (F21), meaning a
bare `pip install ddf` without the `production` extra cannot start the application —
this is a packaging defect independent of security, but worth fixing before `v1.0.0`.

## K. Remediation/retest results

*(Original text: "None." This is now stale — see `06-retest-report.md` for seven
execution/remediation runs and the Shipping Status section above.)*

## L. Residual risk

Given the headline finding (F1+F23+F24+F27, now also F33 for the CLI) is
CONFIRMED-BY-EXISTING-TEST and pervasive across HTTP, CLI, and the entire unit test
suite, **this codebase should not be treated as production-ready until it is fixed and
independently retested.** The minimal fix has three parts: (1) extend
`LegacyMutationGuard` to cover `/v1/authorize` and `/v1/audit/*` under all
configurations, or retire the legacy routes outright now that the commercial plane
exists; (2) make `GrantService.create_grant` and `DelegationService.create_delegation`
refuse to produce an authority with an empty `holder_public_key` or missing proof,
rather than defaulting silently to an unsigned, unkeyed one, across every caller
including the CLI; and (3) update every existing test that currently asserts an unsigned
authority's `ALLOW` as correct behavior, since fixing (1) and (2) alone will make a
large fraction of the current test suite fail in the expected direction — those tests
need to be corrected to supply real signing keys, not merely have their assertions
loosened.
*(NOTE for this handoff: all three parts of this recommendation have since been
implemented and verified — see Shipping Status above.)*

## M. Testing limitations

- **No code was executed by this assessment itself**, anywhere, at any
point. Every finding is from static reading, except the headline chain,
which is CONFIRMED-BY-EXISTING-TEST — a real, unexecuted-by-us test in
the project's own suite performs it. - File coverage is complete against a confirmed
`git ls-files` inventory at
commit `c96b5bf5d1a30604ab9c2e24775477113fae5354`: all of `src/ddf/**`
(including `db/models.py` and `cli/*`), `scripts/**`, `deploy/**`,
`docs/**`, `examples/**`, `release-evidence/**`, `openfga/model.json`, and
all of `tests/**` were reviewed. Only trivial, non-security-relevant
boilerplate remains unseen: `alembic/README` (58 bytes) and
`alembic/script.py.mako` (704 bytes), both stock Alembic scaffold files. -
`ddf-main.zip` was uploaded once at the start but never opened, per this
environment's policy against opening archives; every other file was
supplied as individual pasted/uploaded source instead, or via a full
`git ls-files` inventory and confirmed `git rev-parse HEAD`/
`git status --short` output from a separate GitHub Codespace session. - An anomaly was
encountered early on and is logged in `04-test-log.md`:
stale versions of these same assessment files were found pre-existing in
the working directory before this session had written anything to it.
They were inspected, found to be an earlier, now-superseded state of this
same analysis (not evidence of external tampering), and were deliberately
replaced rather than trusted or merged. - A provenance caveat applied partway through:
the commit SHA and
working-tree status were initially relayed via prose from the Codespace
session rather than shown as literal command output, and were
provisionally held at a lower confidence tier until literal
`git rev-parse HEAD` / `git status --short` output was provided and
confirmed consistent. Both are now OBSERVED. - No part of this assessment ran
`pip-audit`, `safety check`, or any other
dependency-CVE scan — this environment has no network access.
`poetry.lock` (confirmed genuine, untracked by git — see F41) makes this
straightforward to run on a devnet stack with network access.
*(NOTE for this handoff: `pip-audit` has since been run, three times, in the execution
phase — see `06-retest-report.md` Runs 3 and 7.)*

## Release-decision questions (per engagement brief §32)

1. Confirmed Critical findings? **Yes, as of the execution phase** — the

headline chain F1+F23+F24+F27+F33 is CONFIRMED-BY-TEST (EXECUTED) and
has since been remediated and adversarially retested. (Original text at
time of static review: "No finding is CONFIRMED by this assessment's own
execution... pending independent execution to reach full CONFIRMED-BY-TEST
status" — superseded.)

2. Confirmed High findings? F28 and F6 reached CONFIRMED-BY-READING/

CONFIRMED-BY-TEST and are now remediated; F2 and F3 were confirmed
exploitable by execution/adversarial test and are now remediated. F4,
F5a-c, and the rest remain HIGH-CONFIDENCE/HYPOTHESIS, unexecuted,
unremediated.

3. Unresolved Critical/High? Ten specific findings are resolved and

verified (see Shipping Status). Everything else in the register remains
unresolved.

4. Tenant isolation adversarially tested? Partially — F28's unauthenticated

cross-tenant audit read was confirmed and fixed. Broader tenant-isolation
adversarial testing (cross-tenant ID substitution across every resource
type) was not performed.

5. Delegation attenuation adversarially tested? Not beyond what the

project's own existing test suite already covers (which is substantial —
see `test_attenuation.py`, `test_invariants.py`). No new adversarial
attenuation testing was added in this assessment.

6. Multi-hop authority escalation tested? Not beyond the existing

`demo/procurement.py`-style 3-hop legitimate chain exercised by the
existing test suite.

7. Capability replay tested? Not directly; capability single-use is

enforced via `SELECT ... FOR UPDATE` plus the newly-added advisory lock
(F42 fix) and was verified under genuine concurrency (20/20 runs).

8. Concurrent capability double-consumption tested? **Yes** — this is F42,

confirmed exploitable via genuine concurrent execution and fixed.

9. Revocation cascade tested? **Yes** — this is R1, confirmed and fixed.

10. PoP/signature substitution tested? Not beyond what the existing

`test_stolen_authority_v01.py` covers (wrong-key case). The "no key at
all" case (F23/F24) was confirmed and fixed as part of the headline
chain. 11. Key rotation/revocation tested? **Yes** — F6, confirmed and fixed,
including adversarial rotation-scenario checks (two keys, revoke one,
confirm the other still works; revoke-then-rotate confirms the old key
stays rejected). 12. Provenance tampering tested? No — F7/F8 remain
unexecuted/unremediated. 13. OpenFGA failure behavior tested? No — F5a/F5b/F5c remain
unexecuted/unremediated (F5b was confirmed as intentional design via
an existing test, not fixed, since it isn't a bug). 14. Identity-discovery/SSRF
boundaries tested locally? No — F19 remains
unexecuted; no caller of `resolve_did_web` was found in the files
reviewed, so reachability is still unconfirmed. 15. Authorization-sensitive database
races tested? One race (F42) was
found and fixed; others (R5, the evidence-chain ordering race F7) were
not specifically tested. 16. Dependencies checked for known vulnerabilities? **Yes,
three times**
(`pip-audit` in Runs 3 and 7) — found and fixed the `urllib3` CVEs
(F41); `jupyterlab`/`tornado` CVEs are environment contamination
(F35), not a repo issue. 17. Significant findings retested after remediation? **Yes** —
all ten
remediated findings were retested, including a dedicated adversarial
bypass-attempt pass distinct from their own regression tests. 18. Important areas
remaining untested: F4 (signature pinning), F5a/F5c
(OpenFGA scoping), F7–F12, F14–F22 (production-readiness controls,
confirmed by coverage data to be largely unexercised by the existing
suite), F32 (network egress), F34/F36/F38/F39 (release-process/SBOM
issues). See `05-findings-register.md` for the complete current state
of every item, and the "now what" discussion in this conversation for
proposed next-round remediation scope.

## N. Execution handoff

*(Original next-step plan, now completed — retained for the historical record of what
was planned versus what actually happened, which matched closely.)*
Static review is complete as of commit `c96b5bf5d1a30604ab9c2e24775477113fae5354`. A
live-stack sandbox (network-enabled, Docker-capable) has been reserved for the execution
phase. When available, run in this order:

1. `docker-compose up` (Postgres + OpenFGA), `alembic upgrade head`.

2. `pytest tests/integration/test_api_routes.py::test_authority_lifecycle_via_http -v`

— this is the single highest-priority run, since it is the existing test
that already demonstrates the headline Critical chain (F1+F23+F24+F27+F33).
A pass with `ALLOW` confirms the finding by execution; a failure means the
codebase has already changed since this review and the register needs
re-validation against the new commit.

3. Copy `regression-tests/*.py` and `reproducers/*.py` from this directory

into the real `tests/` tree (or run standalone per each file's docstring)
and execute them, recording pass/fail into `06-retest-report.md`.

4. `pip install pip-audit && pip-audit` (or `safety check`) against

`poetry.lock` — the first real dependency-CVE scan possible in this
assessment, per F41.

5. Update `05-findings-register.md`'s confidence column from

CONFIRMED-BY-READING/HIGH-CONFIDENCE to CONFIRMED-BY-TEST (or mark
refuted) as each item is actually run, and update this report's §G and
the release-decision answers above accordingly.
Every command and file needed for step 2 and 3 already exists in this directory; no
further source review is required before execution begins.
