"""Command-line interface for Dynamic Delegation Fabric."""

import asyncio
import json
import os
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import click
import httpx
from nacl.encoding import Base64Encoder
from nacl.signing import SigningKey
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ddf.authority.capabilities import CapabilityAccessRequest
from ddf.authority.effective import (
    get_effective_authority,
    load_authority_chain,
)
from ddf.authority.models import SignedCapabilityAssertion
from ddf.db.models import AuthorizationLog
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


def _api_url() -> str:
    return os.getenv("DDF_API_URL", "http://127.0.0.1:8000").rstrip("/")


async def _post_api(path: str, payload: dict[str, Any], api_url: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(f"{api_url}{path}", json=payload)
    except httpx.HTTPError as exc:
        raise click.ClickException(f"DDF API request failed: {exc}") from exc
    if not response.is_success:
        raise click.ClickException(f"DDF API returned {response.status_code}: {response.text}")
    try:
        body = response.json()
    except ValueError as exc:
        raise click.ClickException("DDF API returned invalid JSON") from exc
    if not isinstance(body, dict):
        raise click.ClickException("DDF API response must be a JSON object")
    return body


@cli.command()
@click.option("--assertion-json", required=True)
@click.option("--api-url", default=_api_url, show_default="DDF_API_URL or localhost")
def grant(assertion_json: str, api_url: str) -> None:
    """Create a signed v0.2 universal capability grant."""
    try:
        signed = SignedCapabilityAssertion.model_validate_json(assertion_json)
    except ValueError as exc:
        raise click.BadParameter(f"invalid universal assertion: {exc}") from exc
    result = asyncio.run(_post_api("/v2/grants", signed.model_dump(mode="json"), api_url))
    click.echo(json.dumps(result, indent=2))


@cli.command()
@click.option("--parent", required=True)
@click.option("--assertion-json", required=True)
@click.option("--api-url", default=_api_url, show_default="DDF_API_URL or localhost")
def delegate(parent: str, assertion_json: str, api_url: str) -> None:
    """Create an attenuated v0.2 universal capability delegation."""
    try:
        signed = SignedCapabilityAssertion.model_validate_json(assertion_json)
    except ValueError as exc:
        raise click.BadParameter(f"invalid universal assertion: {exc}") from exc
    result = asyncio.run(
        _post_api(
            f"/v2/delegations/{parent}",
            {"child": signed.model_dump(mode="json")},
            api_url,
        )
    )
    click.echo(json.dumps(result, indent=2))


@cli.command()
@click.option("--grant", "grant_id", required=True)
@click.option("--request-json", required=True)
@click.option("--api-url", default=_api_url, show_default="DDF_API_URL or localhost")
def authorize(grant_id: str, request_json: str, api_url: str) -> None:
    """Evaluate a v0.2 capability with an EAT-bound runtime context."""
    try:
        request = CapabilityAccessRequest.model_validate_json(request_json)
    except ValueError as exc:
        raise click.BadParameter(f"invalid universal access request: {exc}") from exc
    result = asyncio.run(
        _post_api(
            "/v2/authorize",
            {
                "grant_id": grant_id,
                "request": request.model_dump(mode="json"),
            },
            api_url,
        )
    )
    click.echo(json.dumps(result, indent=2))


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
