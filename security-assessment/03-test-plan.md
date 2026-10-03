# 03 — Test Plan

This environment has no network and no Docker, so nothing below was
executed. This plan is for the repo owner or a Claude Code session with
access to the real checkout and a running Postgres + OpenFGA + Redis stack.

| Priority | Test group | Targets | Reproducer |
|---|---|---|---|
| P0 | Unauthenticated authority mint + authorize | F1, F23, F24, F27 | `regression-tests/test_legacy_authorize_unauthenticated.py` |
| P0 | Global unauthenticated audit read | F28 | `reproducers/test_audit_events_unauthenticated.py` |
| P0 | Key revocation has no effect on authentication | F6 | `reproducers/test_revoked_key_still_authenticates.py` |
| P0 | Capability survives authority revocation | F2 | `regression-tests/test_capability_survives_revocation.py` |
| P0 | Cascading revoke shadowed by earlier non-cascading revoke | R1 | `regression-tests/test_revocation_cascade_override.py` |
| P1 | Constraint bypass via omitted/NaN amount | F3 | `reproducers/test_nan_amount_bypass.py` |
| P1 | OpenFGA actor-controlled relation/object/user in authorize | F5a | manual: craft `context.openfga_*` fields |
| P1 | Idempotency replay without authentication | F14 | manual: two-request sequence described in finding |
| P1 | Production startup guard not actually wired (lifespan vs on_event) | F13 | `regression-tests/test_startup_guard_runs.py` |
| P1 | Evidence bundle forgery/downgrade | F17 | `regression-tests/test_evidence_bundle_forgery.py` |
| P2 | Resource matcher inconsistency across 3 call sites | F18, F25 | manual: compare `vendor/dell/*` matches across authorize/capabilities/remote-intent |
| P2 | Rate-limit bypass via spoofed tenant/principal headers | F15 | manual |
| P2 | did:web SSRF surface (loopback/private range) — reachability unconfirmed | F19 | manual, **local mock target only** per engagement rules |
| P3 | Supply chain: ruff/mypy/bandit/pip-audit, actually enforced? | F30 | re-run `ci.yml` jobs and inspect exit codes directly, not `|| true` wrapped |
| P3 | Multi-hop attenuation chain ROOT→A→B→C with per-hop boundary values | I1, I2 | property-style test sweeping amount/resource/purpose/expiry/depth at each hop |
| P3 | Concurrent one-use capability consumption (N-way) | — | launch N parallel `consume` calls against one capability_id, assert exactly 1 succeeds |

Reproducer standard used throughout: smallest pytest or localhost HTTP script
that is deterministic and independently re-runnable; failed attack attempts
are recorded as negative results, not omitted.
