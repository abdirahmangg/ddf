"""Backfill legacy authorities into universal capability assertions.

Revision ID: 2a7f61c4d5e8
Revises: c42e9b9a4f21
"""

from collections.abc import Sequence
from typing import Any
from urllib.parse import quote, urlsplit
from uuid import NAMESPACE_URL, uuid5

import sqlalchemy as sa

from alembic import op

revision: str = "2a7f61c4d5e8"
down_revision: str | Sequence[str] | None = "c42e9b9a4f21"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OPERATIONS = {
    "read": "read",
    "view": "read",
    "list": "read",
    "get": "read",
    "quote": "read",
    "write": "write",
    "create": "write",
    "update": "write",
    "delete": "write",
    "purchase": "write",
    "execute": "execute",
    "run": "execute",
    "invoke": "invoke",
    "call": "invoke",
    "delegate": "delegate",
    "admin": "admin",
}


def _principal_uri(value: str) -> str:
    if urlsplit(value).scheme:
        return value
    return f"urn:ddf:legacy:principal:{quote(value, safe='')}"


def _resource_uri(value: str) -> str:
    if urlsplit(value).scheme:
        return value
    return f"urn:ddf:legacy:resource/{quote(value, safe='/*:')}"


def _resource_covers(parent: str, child: str) -> bool:
    if parent == child:
        return True
    if parent.endswith("/*"):
        prefix = parent[:-2]
        return child == prefix or child.startswith(prefix + "/")
    return False


def _namespace(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme == "urn":
        parts = parsed.path.split(":")
        if parts and parts[0] == "ddf" and len(parts) > 1:
            return parts[1]
        return parts[0] if parts and parts[0] else "urn"
    if parsed.scheme == "arn":
        parts = value.split(":", 3)
        return parts[1] if len(parts) > 1 and parts[1] else "aws"
    return parsed.scheme or "legacy"


def _predicates(constraints: dict, purposes: list[str]) -> dict:
    clauses: list[dict] = []
    existing = constraints.get("predicates")
    if existing:
        clauses.append(existing)

    max_amount = constraints.get("max_amount")
    if max_amount is not None:
        clauses.append({"path": "context.amount", "op": "lte", "value": max_amount})
    currency = constraints.get("currency")
    if currency is not None:
        clauses.append({"path": "context.currency", "op": "eq", "value": currency})
    geographies = constraints.get("geographies")
    if geographies:
        clauses.append({"path": "context.geography", "op": "in", "value": geographies})
    audiences = constraints.get("audiences")
    if audiences:
        clauses.append({"path": "context.audience", "op": "in", "value": audiences})
    valid_from = constraints.get("valid_from")
    if valid_from is not None:
        clauses.append(
            {
                "path": "context.timestamp",
                "op": "gte",
                "value": valid_from.isoformat() if hasattr(valid_from, "isoformat") else valid_from,
            }
        )
    expires_at = constraints.get("expires_at")
    if expires_at is not None:
        clauses.append(
            {
                "path": "context.timestamp",
                "op": "lte",
                "value": expires_at.isoformat() if hasattr(expires_at, "isoformat") else expires_at,
            }
        )
    delegation_depth = constraints.get("delegation_depth_remaining")
    if delegation_depth is not None:
        clauses.append(
            {
                "path": "context.delegation_depth",
                "op": "lte",
                "value": delegation_depth,
            }
        )
    if purposes:
        clauses.append({"path": "context.purpose", "op": "in", "value": purposes})

    if not clauses:
        return {}
    return {"all": clauses}


def _assertions(row: Any, parent_actors: dict[str, str]) -> list[dict]:
    if not row["actions"] or not row["resources"]:
        raise RuntimeError(
            f"cannot safely migrate authority {row['authority_id']} without actions and resources"
        )
    try:
        operations = sorted({_OPERATIONS[action] for action in row["actions"]})
    except KeyError as exc:
        raise RuntimeError(
            f"cannot safely migrate unsupported legacy action {exc.args[0]!r} "
            f"on authority {row['authority_id']}"
        ) from exc

    issuer = parent_actors.get(row["parent_authority_id"], row["sponsor"])
    constraints = row["constraints_json"] or {}
    purposes = row["purposes"] or []
    predicates = _predicates(constraints, purposes)
    migrated: list[dict] = []
    for index, resource in enumerate(row["resources"]):
        target_resource = _resource_uri(resource)
        assertion = {
            "grant_id": str(
                uuid5(
                    NAMESPACE_URL,
                    f"{row['authority_id']}:{index}:{resource}",
                )
            ),
            "issuer": _principal_uri(issuer),
            "subject": _principal_uri(row["actor"]),
            "capability": {
                "target_namespace": _namespace(target_resource),
                "target_resource": target_resource,
                "operations": operations,
                "constraints": predicates,
            },
        }
        migrated.append(assertion)
    return migrated


def upgrade() -> None:
    op.create_table(
        "ddf_universal_assertions",
        sa.Column("grant_id", sa.String(36), primary_key=True),
        sa.Column("assertion_json", sa.JSON(), nullable=False),
        sa.Column("proof_json", sa.JSON(), nullable=True),
        sa.Column("parent_grant_id", sa.String(36), nullable=True),
        sa.Column("source_authority_id", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["parent_grant_id"],
            ["ddf_universal_assertions.grant_id"],
        ),
    )
    authorities = sa.table(
        "authorities",
        sa.column("authority_id", sa.String()),
        sa.column("actor", sa.String()),
        sa.column("sponsor", sa.String()),
        sa.column("actions", sa.JSON()),
        sa.column("resources", sa.JSON()),
        sa.column("purposes", sa.JSON()),
        sa.column("constraints_json", sa.JSON()),
        sa.column("parent_authority_id", sa.String()),
        sa.column("issued_at", sa.DateTime(timezone=True)),
    )
    connection = op.get_bind()
    rows = connection.execute(sa.select(authorities)).mappings().all()
    parent_actors = {row["authority_id"]: row["actor"] for row in rows}
    assertions_by_authority = {row["authority_id"]: _assertions(row, parent_actors) for row in rows}
    ordered_rows = []
    pending_rows = list(rows)
    migrated_authority_ids: set[str] = set()
    while pending_rows:
        ready = [
            row
            for row in pending_rows
            if row["parent_authority_id"] is None
            or row["parent_authority_id"] in migrated_authority_ids
        ]
        if not ready:
            raise RuntimeError("legacy authority graph contains an orphan or delegation cycle")
        for row in ready:
            pending_rows.remove(row)
            ordered_rows.append(row)
            migrated_authority_ids.add(row["authority_id"])

    universal_assertions = sa.table(
        "ddf_universal_assertions",
        sa.column("grant_id", sa.String(36)),
        sa.column("assertion_json", sa.JSON()),
        sa.column("proof_json", sa.JSON()),
        sa.column("parent_grant_id", sa.String(36)),
        sa.column("source_authority_id", sa.String(256)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )

    for row in ordered_rows:
        for assertion in assertions_by_authority[row["authority_id"]]:
            parent_grant_id = None
            parent_authority_id = row["parent_authority_id"]
            if parent_authority_id is not None:
                parent_assertions = assertions_by_authority.get(parent_authority_id, [])
                child_capability = assertion["capability"]
                parent_assertion = next(
                    (
                        candidate
                        for candidate in parent_assertions
                        if candidate["capability"]["target_namespace"]
                        == child_capability["target_namespace"]
                        and set(child_capability["operations"]).issubset(
                            candidate["capability"]["operations"]
                        )
                        and _resource_covers(
                            candidate["capability"]["target_resource"],
                            child_capability["target_resource"],
                        )
                    ),
                    None,
                )
                if parent_assertion is None:
                    raise RuntimeError(
                        f"cannot safely map authority {row['authority_id']} to a parent assertion"
                    )
                parent_grant_id = parent_assertion["grant_id"]
            connection.execute(
                universal_assertions.insert().values(
                    grant_id=assertion["grant_id"],
                    assertion_json=assertion,
                    proof_json=None,
                    parent_grant_id=parent_grant_id,
                    source_authority_id=row["authority_id"],
                    created_at=row["issued_at"],
                )
            )


def downgrade() -> None:
    op.drop_table("ddf_universal_assertions")
