"""Command-line interface for Dynamic Delegation Fabric."""

import asyncio
import json
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import click
from nacl.encoding import Base64Encoder
from nacl.signing import SigningKey
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ddf.authority.effective import (
    get_effective_authority,
    load_authority_chain,
)
from ddf.authority.models import (
    AuthorityConstraints,
    AuthorizationRequest,
)
from ddf.authorization.service import AuthorizationService
from ddf.db.models import AuthorizationLog
from ddf.delegation.service import (
    DelegationService,
    GrantService,
)
from ddf.identity.service import IdentityService
from ddf.revocation.service import RevocationService
from ddf.settings import get_settings


def _database_url() -> str:
    url = get_settings().database_url

    if url.startswith("postgresql://"):
        url = url.replace(
            "postgresql://",
            "postgresql+asyncpg://",
            1,
        )

    return url


@asynccontextmanager
async def _session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(
        _database_url(),
        echo=False,
    )

    maker = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    try:
        async with maker() as session:
            yield session
    finally:
        await engine.dispose()


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


@click.group()
def cli() -> None:
    """DDF — Dynamic Delegation Fabric."""


@cli.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8000, type=int)
def server(host: str, port: int) -> None:
    """Start the DDF API server."""
    import uvicorn

    uvicorn.run(
        "ddf.main:app",
        host=host,
        port=port,
        reload=False,
    )


@cli.group()
def identity() -> None:
    """Manage DDF identities."""


@identity.command("create")
@click.argument("identity_id")
@click.option("--display-name", default=None)
def identity_create(
    identity_id: str,
    display_name: str | None,
) -> None:
    """Create an identity and local Ed25519 key."""
    asyncio.run(
        _identity_create(
            identity_id,
            display_name,
        )
    )


async def _identity_create(
    identity_id: str,
    display_name: str | None,
) -> None:
    signing_key = SigningKey.generate()

    private_b64 = signing_key.encode(encoder=Base64Encoder).decode("ascii")

    public_b64 = signing_key.verify_key.encode(encoder=Base64Encoder).decode("ascii")

    safe_name = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        identity_id,
    )

    key_dir = Path.home() / ".ddf" / "keys"
    key_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    key_path = key_dir / f"{safe_name}.key"

    if key_path.exists():
        raise click.ClickException(f"Key already exists: {key_path}")

    key_path.write_text(private_b64)
    key_path.chmod(0o600)

    async with _session() as session:
        await IdentityService.create(
            session,
            identity_id=identity_id,
            public_key=public_b64,
            display_name=display_name,
        )

    click.echo(
        json.dumps(
            {
                "identity_id": identity_id,
                "public_key": public_b64,
                "private_key_file": str(key_path),
            },
            indent=2,
        )
    )


@identity.command("list")
def identity_list() -> None:
    """List registered identities."""
    asyncio.run(_identity_list())


async def _identity_list() -> None:
    async with _session() as session:
        identities = await IdentityService.list(session)

    for item in identities:
        click.echo(f"{item.id}\t{item.identity_type}\t{item.display_name or ''}")


@cli.command()
@click.option("--sponsor", required=True)
@click.option("--actor", required=True)
@click.option("--actions", required=True)
@click.option("--resources", required=True)
@click.option("--purposes", required=True)
@click.option("--max-amount", type=float)
@click.option("--currency")
@click.option("--geographies")
@click.option("--expires-hours", default=24, type=int)
def grant(
    sponsor: str,
    actor: str,
    actions: str,
    resources: str,
    purposes: str,
    max_amount: float | None,
    currency: str | None,
    geographies: str | None,
    expires_hours: int,
) -> None:
    """Create a root DDF authority."""
    asyncio.run(
        _grant(
            sponsor=sponsor,
            actor=actor,
            actions=_split_csv(actions),
            resources=_split_csv(resources),
            purposes=_split_csv(purposes),
            max_amount=max_amount,
            currency=currency,
            geographies=(_split_csv(geographies) if geographies else None),
            expires_hours=expires_hours,
        )
    )


async def _grant(**kwargs: Any) -> None:
    constraints_data = {
        key: value
        for key, value in {
            "max_amount": kwargs["max_amount"],
            "currency": kwargs["currency"],
            "geographies": kwargs["geographies"],
        }.items()
        if value is not None
    }

    constraints = AuthorityConstraints(**constraints_data)

    async with _session() as session:
        authority = await GrantService.create_grant(
            session=session,
            sponsor=kwargs["sponsor"],
            actor=kwargs["actor"],
            actions=kwargs["actions"],
            resources=kwargs["resources"],
            purposes=kwargs["purposes"],
            constraints=constraints,
            expires_in_hours=kwargs["expires_hours"],
        )

    click.echo(authority.model_dump_json(indent=2))


@cli.command()
@click.option("--parent", required=True)
@click.option("--to", "delegated_to", required=True)
@click.option("--actions")
@click.option("--resources")
@click.option("--purposes")
@click.option("--max-amount", type=float)
@click.option("--currency")
@click.option("--geographies")
def delegate(
    parent: str,
    delegated_to: str,
    actions: str | None,
    resources: str | None,
    purposes: str | None,
    max_amount: float | None,
    currency: str | None,
    geographies: str | None,
) -> None:
    """Create an attenuated child authority."""
    asyncio.run(
        _delegate(
            parent=parent,
            delegated_to=delegated_to,
            actions=(_split_csv(actions) if actions else None),
            resources=(_split_csv(resources) if resources else None),
            purposes=(_split_csv(purposes) if purposes else None),
            max_amount=max_amount,
            currency=currency,
            geographies=(_split_csv(geographies) if geographies else None),
        )
    )


async def _delegate(**kwargs: Any) -> None:
    constraint_values = {
        key: value
        for key, value in {
            "max_amount": kwargs["max_amount"],
            "currency": kwargs["currency"],
            "geographies": kwargs["geographies"],
        }.items()
        if value is not None
    }

    constraints = AuthorityConstraints(**constraint_values) if constraint_values else None

    async with _session() as session:
        authority, delegation_id = await DelegationService.create_delegation(
            session=session,
            parent_authority_id=kwargs["parent"],
            delegated_to=kwargs["delegated_to"],
            actions=kwargs["actions"],
            resources=kwargs["resources"],
            purposes=kwargs["purposes"],
            constraints=constraints,
        )

    click.echo(
        json.dumps(
            {
                "delegation_id": delegation_id,
                "authority": authority.model_dump(mode="json"),
            },
            indent=2,
        )
    )


@cli.command()
@click.option("--actor", required=True)
@click.option("--action", required=True)
@click.option("--resource", required=True)
@click.option("--purpose", required=True)
@click.option("--authority", "authority_id", required=True)
@click.option("--amount", type=float)
@click.option("--currency")
@click.option("--geography")
@click.option("--audience")
def authorize(
    actor: str,
    action: str,
    resource: str,
    purpose: str,
    authority_id: str,
    amount: float | None,
    currency: str | None,
    geography: str | None,
    audience: str | None,
) -> None:
    """Evaluate a DDF authorization request."""
    context = {
        key: value
        for key, value in {
            "amount": amount,
            "currency": currency,
            "geography": geography,
            "audience": audience,
        }.items()
        if value is not None
    }

    request = AuthorizationRequest(
        actor=actor,
        action=action,
        resource=resource,
        purpose=purpose,
        authority_id=authority_id,
        context=context,
    )

    asyncio.run(_authorize(request))


async def _authorize(
    request: AuthorizationRequest,
) -> None:
    async with _session() as session:
        decision = await AuthorizationService.authorize(
            session,
            request,
        )

    click.echo(decision.model_dump_json(indent=2))


@cli.command()
@click.argument("authority_id")
@click.option("--actor", required=True)
@click.option("--reason")
@click.option(
    "--cascade/--no-cascade",
    default=True,
)
def revoke(
    authority_id: str,
    actor: str,
    reason: str | None,
    cascade: bool,
) -> None:
    """Revoke an authority."""
    asyncio.run(
        _revoke(
            authority_id,
            actor,
            reason,
            cascade,
        )
    )


async def _revoke(
    authority_id: str,
    actor: str,
    reason: str | None,
    cascade: bool,
) -> None:
    async with _session() as session:
        result = await RevocationService.revoke(
            session,
            authority_id=authority_id,
            actor=actor,
            reason=reason,
            cascades=cascade,
        )

    click.echo(result.revocation_id)


@cli.command()
@click.argument("authority_id")
def chain(authority_id: str) -> None:
    """Show the validated authority chain."""
    asyncio.run(_chain(authority_id))


async def _chain(authority_id: str) -> None:
    async with _session() as session:
        authorities = await load_authority_chain(
            session,
            authority_id,
        )

        effective = await get_effective_authority(
            session,
            authority_id,
        )

    for authority in authorities:
        click.echo(f"{authority.authority_id}\t{authority.actor}")

    click.echo()
    click.echo(f"Effective: {effective.actor} / {effective.resources} / {effective.purposes}")


@cli.command()
@click.argument("decision_id")
def explain(decision_id: str) -> None:
    """Explain a recorded authorization decision."""
    asyncio.run(_explain(decision_id))


async def _explain(decision_id: str) -> None:
    async with _session() as session:
        result = await session.execute(
            select(AuthorizationLog).where(AuthorizationLog.decision_id == decision_id)
        )

        log = result.scalar_one_or_none()

    if log is None:
        raise click.ClickException(f"Decision not found: {decision_id}")

    click.echo(
        json.dumps(
            {
                "decision_id": log.decision_id,
                "decision": log.decision,
                "actor": log.actor,
                "action": log.action,
                "resource": log.resource,
                "purpose": log.purpose,
                "authority_id": log.authority_id,
                "reasons": log.reasons,
                "details": log.context_json,
            },
            indent=2,
            default=str,
        )
    )


@cli.group()
def demo() -> None:
    """Run DDF demonstrations."""


@demo.command("procurement")
def procurement_demo() -> None:
    """Run the procurement delegation demonstration."""
    from ddf.demo.procurement import run_demo

    asyncio.run(run_demo())


app = cli
main = cli


if __name__ == "__main__":
    cli()
