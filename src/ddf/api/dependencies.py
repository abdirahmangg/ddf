"""FastAPI dependency injection utilities."""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from ddf.settings import Settings, get_settings


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get a database session."""
    settings = get_settings()

    # Convert postgresql:// to postgresql+asyncpg://
    async_db_url = settings.database_url.replace(
        "postgresql://", "postgresql+asyncpg://"
    )

    engine = create_async_engine(
        async_db_url,
        echo=settings.sqlalchemy_echo,
        future=True,
    )

    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with async_session() as session:
        yield session


async def get_settings_dep() -> Settings:
    """Dependency to get application settings."""
    return get_settings()
