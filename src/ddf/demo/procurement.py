"""End-to-end procurement delegation demonstration."""

import uuid

import click
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ddf.authority.models import (
    AuthorityConstraints,
    AuthorizationRequest,
)
from ddf.authorization.service import AuthorizationService
from ddf.delegation.service import (
    DelegationService,
    GrantService,
)
from ddf.revocation.service import RevocationService
from ddf.settings import get_settings


def _database_url() -> str:
    """Return the asynchronous PostgreSQL URL."""
    url = get_settings().database_url

    if url.startswith("postgresql://"):
        return url.replace(
            "postgresql://",
            "postgresql+asyncpg://",
            1,
        )

    return url


async def run_demo() -> None:
    """Run Alice → Planner → Procurement → Buyer."""
    engine = create_async_engine(_database_url())

    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    suffix = uuid.uuid4().hex[:6]

    alice = f"user:alice-{suffix}@example.com"
    planner = f"agent:planner-{suffix}"
    procurement = f"agent:procurement-{suffix}"
    buyer = f"agent:buyer-{suffix}"

    try:
        async with session_factory() as session:
            root = await GrantService.create_grant(
                session=session,
                sponsor=alice,
                actor=planner,
                actions=["purchase"],
                resources=["vendor/*"],
                purposes=["procurement"],
                constraints=AuthorityConstraints(
                    max_amount=10000,
                    currency="GBP",
                    geographies=["GB"],
                ),
            )

            procurement_authority, _ = await DelegationService.create_delegation(
                session=session,
                parent_authority_id=(root.authority_id),
                delegated_to=procurement,
                actions=["purchase"],
                resources=["vendor/dell/*"],
                purposes=["procurement"],
                constraints=AuthorityConstraints(
                    max_amount=5000,
                    currency="GBP",
                    geographies=["GB"],
                ),
            )

            buyer_authority, _ = await DelegationService.create_delegation(
                session=session,
                parent_authority_id=(procurement_authority.authority_id),
                delegated_to=buyer,
                actions=["purchase"],
                resources=["vendor/dell/order/*"],
                purposes=["procurement"],
                constraints=AuthorityConstraints(
                    max_amount=2000,
                    currency="GBP",
                    geographies=["GB"],
                ),
            )

            allowed_request = AuthorizationRequest(
                actor=buyer,
                action="purchase",
                resource=("vendor/dell/order/9281"),
                purpose="procurement",
                authority_id=(buyer_authority.authority_id),
                context={
                    "amount": 1500,
                    "currency": "GBP",
                    "geography": "GB",
                },
            )

            allowed = await AuthorizationService.authorize(
                session,
                allowed_request,
            )

            escalation_request = AuthorizationRequest(
                actor=buyer,
                action="purchase",
                resource=("vendor/dell/order/9281"),
                purpose="procurement",
                authority_id=(buyer_authority.authority_id),
                context={
                    "amount": 20000,
                    "currency": "GBP",
                    "geography": "GB",
                },
            )

            denied = await AuthorizationService.authorize(
                session,
                escalation_request,
            )

            click.echo()
            click.echo("DDF Procurement Demo")
            click.echo("====================")
            click.echo("Authority path: " + " -> ".join(allowed.authority_path))
            click.echo()
            click.echo(f"GBP 1,500 purchase: {allowed.decision}")
            click.echo(f"GBP 20,000 purchase: {denied.decision}")
            click.echo("Escalation reasons: " + ", ".join(denied.reasons))

            await RevocationService.revoke(
                session,
                authority_id=(procurement_authority.authority_id),
                actor=alice,
                reason=("procurement authority withdrawn"),
                cascades=True,
            )

            revoked = await RevocationService.is_effectively_revoked(
                session,
                buyer_authority.authority_id,
            )

            click.echo(f"Buyer invalid after ancestor revocation: {revoked}")

    finally:
        await engine.dispose()
