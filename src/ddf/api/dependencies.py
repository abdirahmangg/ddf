"""FastAPI dependency injection utilities."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ddf.settings import Settings, get_settings


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an asynchronous database session."""
    settings = get_settings()

    async_db_url = settings.database_url

    if async_db_url.startswith("postgresql://"):
        async_db_url = async_db_url.replace(
            "postgresql://",
            "postgresql+asyncpg://",
            1,
        )

    engine = create_async_engine(
        async_db_url,
        echo=settings.sqlalchemy_echo,
    )

    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    try:
        async with session_factory() as session:
            yield session
    finally:
        await engine.dispose()


async def get_settings_dep() -> Settings:
    """Return application settings."""
    return get_settings()
