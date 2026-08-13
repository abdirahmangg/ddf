"""Database session management for DDF."""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from ddf.settings import get_settings


class Database:
    """Database connection and session management."""

    def __init__(self):
        """Initialize database with settings."""
        self.settings = get_settings()
        self.engine = None
        self.session_maker = None

    async def initialize(self):
        """Initialize database engine and session maker."""
        # Convert postgresql:// URL to postgresql+asyncpg://
        url = self.settings.database_url
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)

        self.engine = create_async_engine(
            url,
            echo=self.settings.sqlalchemy_echo,
            pool_pre_ping=True,
            pool_recycle=3600,
        )

        self.session_maker = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            future=True,
        )

    async def get_session(self) -> AsyncSession:
        """Get a new database session."""
        if not self.session_maker:
            await self.initialize()
        return self.session_maker()

    async def close(self):
        """Close database connections."""
        if self.engine:
            await self.engine.dispose()


# Global database instance
_db = None


def get_database() -> Database:
    """Get global database instance."""
    global _db
    if _db is None:
        _db = Database()
    return _db
