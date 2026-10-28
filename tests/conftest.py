"""Shared DDF test fixtures."""

import pytest
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ddf.db.models import Base
from ddf.settings import get_settings


@pytest.fixture
async def test_db():
    """Create an async database session for integration-style unit tests."""
    url = get_settings().database_url

    if url.startswith("postgresql://"):
        url = url.replace(
            "postgresql://",
            "postgresql+asyncpg://",
            1,
        )

    engine = create_async_engine(
        url,
        echo=False,
    )

    maker = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with maker() as session:
        yield session

    await engine.dispose()
