# 02 — Threat Model and Security Invariants

Invariants are drawn from README.md and SECURITY.md, then checked against
the source actually reviewed. "Verified" here means "observed to be enforced
in the code path reviewed," not "tested at runtime."

| # | Invariant (claimed) | Source | Verified in code? |
|---|---|---|---|
| I1 | Authority(child) ⊆ Authority(parent): amount, resources, purposes, expiry | README | **Partially.** `AttenuationEngine` + `ConstraintValidator` + `ResourceHierarchy` enforce this on the commercial delegation path and are re-verified across the whole chain by `load_authority_chain`. Resource matching uses plain string-prefix comparison with no path normalization (F25) — a `../` resource string can satisfy the subset check textually without being a true subset semantically. |
| I2 | Delegation depth is bounded and decremented per hop | README example | `delegation_depth_remaining` exists in `AuthorityConstraints` and is checked for strict decrease in `ConstraintValidator`, but it is optional (`None` by default) and neither legacy nor commercial delegation routes set it automatically — depth is unbounded unless a caller opts in. |
| I3 | Delegated authority bound to holder public key (PoP) | SECURITY.md | **Violated on the legacy path.** `GrantService.create_grant` and `DelegationService.create_delegation` both default `holder_public_key` to `""` when no `signing_key` is supplied, and the legacy routes never supply one. `verify_proof_of_possession` and `verify_authority_signature` both no-op when the key/proof is empty/`None`. See F23/F24/F27 in 05. |
| I4 | Proof signs actor, authority_id, method, path, body hash, timestamp, nonce | SECURITY.md | Matches `CanonicalSerializer.serialize_request_proof` exactly for that one envelope. The *separate* commercial request-auth envelope (`request_message` in `commercial/crypto.py`) signs method, path, timestamp, nonce, body hash only — no actor/authority_id/tenant binding — a different, narrower envelope than the one SECURITY.md describes. The two are easy to conflate when reasoning about "is PoP in place." |
| I5 | Revocation cascades to descendants | README | Implemented in `RevocationService.is_effectively_revoked` via ancestor walk; see R1 in revocation findings for a scenario where a later cascading revoke can be shadowed by an earlier non-cascading one. |
| I6 | Every decision logged with tamper-evident provenance | README | Hash-chained (`ProvenanceService`), but unsigned by default, globally shared with no tenant scoping (F28), and the chain-format marker makes it possible to silently exit a record from verification by stripping one field. |
| I7 | Authority path cannot skip intermediate delegations ("laundering") | SECURITY.md | **Verified** — `load_authority_chain` re-derives the chain from stored `parent_authority_id` links (never trusts a client-supplied path), checks for cycles, and validates every `authority_path` segment matches the expected `[...,actor]` append at each hop. This is the strongest control found in the codebase. |
| I8 | Purpose is mandatory and attenuated | README | Enforced as a set-subset check in both `AttenuationEngine` and `AuthorizationService`; mandatory via Pydantic `min_length=1` on `purposes`. |

## Attacker models most relevant to current findings

- **A — unauthenticated attacker:** has a direct, confirmed-by-reading path
  to full authority issuance, delegation, and authorization (F1+F23+F24+F27),
  and to reading every tenant's authorization history (F28).
- **C — valid agent with a legitimate key:** can mint capabilities that
  survive authority revocation for up to their TTL (F2).
- **E — malicious delegate expanding authority:** blocked by I1/I7 on the
  commercial path; **not blocked at all** on the legacy path, since the
  legacy delegation route has no caller-identity check (F27) — any caller
  can delegate from any `authority_id` they can discover.
- **F — tenant A attacking tenant B:** OpenFGA state and tuples are not
  tenant-namespaced (F5c); the legacy audit log has no tenant column at all
  (F28), which is a stronger result than ordinary cross-tenant leakage since
  there is no tenant boundary to cross in that table.
- **H — holder of a revoked key:** confirmed unaffected — `ddf_identity_keys`
  (used by `revoke_identity_key`) is never consulted by `authenticate_request`,
  which only reads `ddf_trusted_principals` (F6).
- **M/N — concurrent/replay:** nonce replay is blocked atomically at the DB
  level for the commercial auth envelope (defense verified); the legacy
  PoP envelope (`CanonicalSerializer.serialize_request_proof`) has no
  observed nonce-storage mechanism wired to it in the files reviewed.

## Gaps between documented claims and what the code does

- SECURITY.md's "No Secrets in Logs" is contradicted by `main.py` printing
  `settings.database_url` (credentials included) at every startup.
- SECURITY.md's "Dependencies are pinned" is contradicted by `pyproject.toml`
  using `>=` floors throughout.
- SECURITY.md describes one PoP envelope; two different, non-equivalent
  envelopes actually exist (legacy vs. commercial), as noted at I4.
- The project's own `release-gates.json` and governance docs
  (`PENTEST_SCOPE.md` etc.) state plainly that no internal review — including
  this one — can mark the independent-pentest gate as passed. This
  assessment should be read as input to that external process, not a
  replacement for it.
