# 04 — Test Log

No code was executed anywhere in this assessment. No exploit was attempted
against a running system. Everything below is static source review.

| # | Action | Result |
|---|---|---|
| 1 | Checked sandbox for an existing repo/worktree | None present; no network, no Docker available in this environment |
| 2 | Fetched github.com/abdirahmangg/ddf landing page (web_fetch) | OK — README, file tree listing, 26 commits, no visible tags/releases |
| 3 | Attempted to fetch `src/ddf` tree via web_fetch | Refused by GitHub robots.txt (ROBOTS_DISALLOWED) — not circumvented |
| 4 | Attempted to fetch `docs/threat-model.md` via web_fetch | HTTP 404 |
| 5 | User uploaded `ddf-main.zip` | Not opened — archive-opening is outside this environment's policy; user was asked to upload extracted files individually |
| 6 | Static read of top-level config/docs (batch 1) | See 00/01 |
| 7 | Static read of `revocation/service.py` + related config (batch 2) | Logic review only — findings R1–R8 folded into 05 |
| 8 | Static read of commercial-plane files: api, auth, authority, capabilities, crypto, db, evidence, identity, intent, models, policy (batch 3) | F1–F12 derived |
| 9 | Static read of `production_readiness.py` (read directly from disk — it had been uploaded earlier but not included in model context), `authorization/service.py`, `policy/openfga.py`, `db/database.py` (batch 4) | F13–F22 derived; F1/F4/F5/F6 upgraded |
| 10 | Static read of API route files, `attenuation.py`, `constraints.py`, `resources.py`, `effective.py`, Alembic `env.py`/`alembic.ini` (batch 5) | F1 confirmed as never gating `/v1/authorize`; F23–F27 identified (hypotheses pending `delegation/service.py`) |
| 11 | Static read of 3 Alembic migration files + `ci.yml` (batch 6) | F28 (no tenant_id on legacy audit tables), F30 (CI scanners always exit 0), F6 upgraded to near-confirmed via schema |
| 12 | Static read of `delegation/service.py`, `identity/service.py`, `demo/procurement.py`, governance docs (batch 7) | F23, F24, F27 upgraded to CONFIRMED-BY-READING; full unauthenticated bypass chain established |
| 13 | Created `/home/claude/security-assessment/` scratch workspace | See anomaly note below |
| 14 | Wrote 00–05 and this log | batch 7 |
| 15 | Static read of `test_api_routes.py`, `test_invariants.py`, `test_authority_laundering_v01.py`, `test_capability_mint_caller_binding.py`, `test_commercial_authority_signature_json.py`, `test_commercial_trust_plane.py`, `test_crypto.py`, `test_kubernetes_shutdown_contract.py`, `test_openfga_health_readiness.py`, `test_privilege_escalation_v01.py`, `test_production_readiness.py`, `test_release_identity.py`, `test_stolen_authority_v01.py`, `db/models.py`, `conftest.py` (batch 8) | F1+F23+F24+F27 upgraded to CONFIRMED-BY-EXISTING-TEST via `test_authority_lifecycle_via_http`; F28 confirmed at schema's primary source; F17 refined; test-suite PoP coverage gap identified |
| 16 | Static read of `Dockerfile` (read directly from disk — uploaded but not in model context), `ddf-production.yaml`, `model.json`, `cli/main.py`, `cli/__init__.py`, and the remaining unit test files (`test_authorization_service.py`, `test_cli_v01.py`, `test_constraints.py`, `test_db_models.py`, `test_delegation_service.py`, `test_effective_authority.py`, `test_models.py`, `test_openfga_policy.py`, `test_provenance_service.py`, `test_resources.py`, `test_revocation_service.py`) (batch 9) | F33 identified (CLI has the same unsigned-authority gap as HTTP); headline finding confirmed pervasive across the entire unit test suite, not just one HTTP integration test; F32 identified (NetworkPolicy egress fully open); F5b reframed as intentional/tested design rather than an oversight; F5c reinforced at the OpenFGA type-model level |
| 17 | Static read of `ddf_spdx.json` (read directly from disk — uploaded but not in model context; parsed programmatically with a local Python script to check for the `ddf` package version and cross-reference against `pyproject.toml`) and the nine `release-evidence/*.json` gate stub files, `release-evidence/README.md`, and re-uploaded governance `.md` files (batch 10) | F34, F35, F36 identified (SBOM version mismatch, dev-environment contamination, missing production dependency); release-evidence stubs confirmed to be empty scaffolding, consistent with `release-gates.json` |

## Anomaly encountered and how it was handled

When creating this workspace, files already existed at
`/home/claude/security-assessment/00-target-identity.md` through
`07-final-report.md`, dated earlier in this session (14:58) — before any
`create_file`/`bash_tool` call in this conversation had written to that
directory. Their content matched an early, now-superseded state of this
analysis (before the delegation/revocation/commercial-plane files had been
reviewed) and concluded "NO CONFIRMED VULNERABILITIES," which is materially
stale and would understate severity if left in place or silently merged.

Rather than trust, merge, or silently overwrite this content, it was
inspected in full, found to be internally consistent with (not contradictory
to) this session's own earlier analysis — i.e. not an indication of
externally injected or adversarial content — and then deliberately deleted
and replaced with the current register. This is noted here per the
assessment's own rule against silently weakening or rewriting test state.
