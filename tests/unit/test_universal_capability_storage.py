"""Persistence and migration-boundary tests for universal assertions."""

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, create_engine, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateTable

from ddf.db.models import UniversalAssertionRecord


def _migration_module():
    migration_path = (
        Path(__file__).parents[2]
        / "alembic"
        / "versions"
        / "2a7f61c4d5e8_universal_capability_assertions.py"
    )
    spec = importlib.util.spec_from_file_location("universal_capability_migration", migration_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the universal capability migration")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_legacy_record_conversion_maps_verb_and_fixed_constraints() -> None:
    migration = _migration_module()
    legacy = {
        "authority_id": "ddf:authority:legacy-1",
        "actor": "agent:buyer",
        "sponsor": "user:issuer",
        "actions": ["purchase", "quote"],
        "resources": ["vendor/dell/order/*"],
        "purposes": ["procurement"],
        "constraints_json": {"max_amount": 2000, "currency": "GBP"},
        "parent_authority_id": None,
    }

    [assertion] = migration._assertions(legacy, {})
    capability = assertion["capability"]

    assert assertion["issuer"] == "user:issuer"
    assert assertion["subject"] == "agent:buyer"
    assert capability["target_namespace"] == "legacy"
    assert capability["operations"] == ["read", "write"]
    assert capability["constraints"] == {
        "all": [
            {"path": "context.amount", "op": "lte", "value": 2000},
            {"path": "context.currency", "op": "eq", "value": "GBP"},
            {"path": "context.purpose", "op": "in", "value": ["procurement"]},
        ]
    }
    assert not {"amount", "purpose", "actions", "resources"}.intersection(assertion)


def test_legacy_migration_fails_closed_for_unknown_actions() -> None:
    migration = _migration_module()
    legacy = {
        "authority_id": "ddf:authority:legacy-2",
        "actor": "agent:buyer",
        "sponsor": "user:issuer",
        "actions": ["wire_funds"],
        "resources": ["vendor/dell"],
        "purposes": ["procurement"],
        "constraints_json": {},
        "parent_authority_id": None,
    }

    try:
        migration._assertions(legacy, {})
    except RuntimeError as exc:
        assert "wire_funds" in str(exc)
    else:
        raise AssertionError("unsupported legacy actions must not be broadened")


def test_migration_backfills_persisted_assertions_and_parent_links() -> None:
    migration = _migration_module()
    engine = create_engine("sqlite:///:memory:")
    metadata = MetaData()
    authorities = Table(
        "authorities",
        metadata,
        Column("authority_id", String, primary_key=True),
        Column("actor", String, nullable=False),
        Column("sponsor", String, nullable=False),
        Column("actions", JSON, nullable=False),
        Column("resources", JSON, nullable=False),
        Column("purposes", JSON, nullable=False),
        Column("constraints_json", JSON, nullable=False),
        Column("parent_authority_id", String),
        Column("issued_at", DateTime(timezone=True), nullable=False),
    )
    metadata.create_all(engine)
    issued_at = datetime.now(UTC)
    with engine.begin() as connection:
        connection.execute(
            authorities.insert(),
            [
                {
                    "authority_id": "root",
                    "actor": "agent:planner",
                    "sponsor": "user:issuer",
                    "actions": ["purchase"],
                    "resources": ["vendor/*"],
                    "purposes": ["procurement"],
                    "constraints_json": {"max_amount": 2000},
                    "parent_authority_id": None,
                    "issued_at": issued_at,
                },
                {
                    "authority_id": "child",
                    "actor": "agent:buyer",
                    "sponsor": "user:issuer",
                    "actions": ["purchase"],
                    "resources": ["vendor/dell/*"],
                    "purposes": ["procurement"],
                    "constraints_json": {"max_amount": 1000},
                    "parent_authority_id": "root",
                    "issued_at": issued_at + timedelta(seconds=1),
                },
            ],
        )
        migration.op = Operations(MigrationContext.configure(connection))
        migration.upgrade()
        persisted = (
            connection.execute(
                select(
                    Table(
                        "ddf_universal_assertions",
                        MetaData(),
                        autoload_with=connection,
                    )
                ).order_by("source_authority_id")
            )
            .mappings()
            .all()
        )

    assert len(persisted) == 2
    root = next(row for row in persisted if row["source_authority_id"] == "root")
    child = next(row for row in persisted if row["source_authority_id"] == "child")
    assert root["proof_json"] is None
    assert child["parent_grant_id"] == root["grant_id"]
    assert child["assertion_json"]["capability"]["operations"] == ["write"]
    engine.dispose()


def test_universal_assertion_model_persists_json_and_compiles_for_postgresql() -> None:
    postgres_ddl = str(
        CreateTable(UniversalAssertionRecord.__table__).compile(dialect=postgresql.dialect())
    )
    assert "CREATE TABLE ddf_universal_assertions" in postgres_ddl
    assert "assertion_json JSON NOT NULL" in postgres_ddl
    assert "proof_json JSON" in postgres_ddl

    engine = create_engine("sqlite:///:memory:")
    UniversalAssertionRecord.__table__.create(engine)
    assertion_json = {
        "grant_id": "c1be5c2e-6cc8-4b9e-88aa-3d5a03275d9a",
        "issuer": "did:key:z6Mkissuer",
        "subject": "urn:agent:worker",
        "capability": {
            "target_namespace": "mcp",
            "target_resource": "urn:mcp:tools/sql_query",
            "operations": ["execute"],
            "constraints": {},
        },
    }

    with Session(engine) as session:
        session.add(
            UniversalAssertionRecord(
                grant_id=assertion_json["grant_id"],
                assertion_json=assertion_json,
                proof_json={"algorithm": "Ed25519", "key_id": "key-1"},
            )
        )
        session.commit()
        persisted = session.scalar(
            select(UniversalAssertionRecord).where(
                UniversalAssertionRecord.grant_id == assertion_json["grant_id"]
            )
        )

    assert persisted is not None
    assert persisted.assertion_json == assertion_json
    assert persisted.proof_json == {"algorithm": "Ed25519", "key_id": "key-1"}
    engine.dispose()
