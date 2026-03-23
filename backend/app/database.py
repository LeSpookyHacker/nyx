"""
Async SQLAlchemy database setup.
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

settings = get_settings()

_is_sqlite = "sqlite" in settings.DATABASE_URL
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,  # Never echo SQL — avoids query/param leakage in logs
    pool_timeout=30,       # Max seconds to wait for a connection from the pool (M-1)
    pool_recycle=1800,     # Recycle connections every 30 min to avoid stale connections
    connect_args=(
        {"check_same_thread": False}
        if _is_sqlite
        else {"command_timeout": 30}  # Statement timeout for PostgreSQL (M-1)
    ),
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Create all tables (development/SQLite). Use Alembic for production."""
    import app.models  # noqa: F401 – import all models to register metadata
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
