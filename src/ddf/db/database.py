"""Database session management for DDF."""

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ddf.settings import get_settings


class Database:
    """Database connection and session management."""

    def __init__(self) -> None:
        """Initialize database state."""
        self.settings = get_settings()
        self.engine: AsyncEngine | None = None
        self.session_maker: async_sessionmaker[AsyncSession] | None = None

    async def initialize(self) -> None:
        """Initialize database engine and session maker."""
        url = self.settings.database_url

        if url.startswith("postgresql://"):
            url = url.replace(
                "postgresql://",
                "postgresql+asyncpg://",
                1,
            )

        self.engine = create_async_engine(
            url,
            echo=self.settings.sqlalchemy_echo,
            pool_pre_ping=True,
            pool_recycle=3600,
        )

        self.session_maker = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    async def get_session(self) -> AsyncSession:
        """Create a new database session."""
        if self.session_maker is None:
            await self.initialize()

        session_maker = self.session_maker

        if session_maker is None:
            raise RuntimeError("Database session maker was not initialized")

        return session_maker()

    async def close(self) -> None:
        """Close database connections."""
        if self.engine is not None:
            await self.engine.dispose()

        self.engine = None
        self.session_maker = None


_db: Database | None = None


def get_database() -> Database:
    """Return the process-wide Database instance."""
    global _db

    if _db is None:
        _db = Database()

    return _db
