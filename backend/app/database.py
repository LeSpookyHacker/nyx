"""
Async SQLAlchemy database setup.
"""
from __future__ import annotations

from sqlalchemy import text
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
        if _is_sqlite:
            await _migrate_add_columns(conn)
        await _migrate_encrypt_raw_outputs(conn)


async def _migrate_encrypt_raw_outputs(conn) -> None:
    """
    Blocking one-shot backfill: encrypt any plaintext scans.raw_output rows in place.

    Detects ciphertext by the Fernet version prefix 'gAAAAA'. Idempotent — rows that
    already look like ciphertext are skipped, so re-running on every startup is cheap.
    Raises on encryption errors so we fail fast rather than silently leaving plaintext.
    """
    import logging
    from app.core.crypto import encrypt_secret, _get_fernet

    logger = logging.getLogger("nyx.migrate")
    if _get_fernet() is None:
        logger.warning(
            "NYX_SECRET_KEY not set — raw_output encryption at rest is disabled. "
            "Set NYX_SECRET_KEY and restart to encrypt existing rows."
        )
        return

    try:
        result = await conn.execute(
            text("SELECT id, raw_output FROM scans WHERE raw_output IS NOT NULL")
        )
        rows = result.fetchall()
    except Exception:
        return  # scans table may not exist yet on a fresh schema create (no-op)

    migrated = 0
    for row_id, raw in rows:
        if not raw or raw.startswith("gAAAAA"):
            continue
        encrypted = encrypt_secret(raw)
        if not encrypted or encrypted == raw:
            raise RuntimeError(
                f"Failed to encrypt scans.raw_output for scan {row_id} — aborting startup"
            )
        await conn.execute(
            text("UPDATE scans SET raw_output = :v WHERE id = :id"),
            {"v": encrypted, "id": row_id},
        )
        migrated += 1

    if migrated:
        logger.info("Encrypted %d plaintext raw_output row(s) at rest", migrated)


async def _migrate_add_columns(conn) -> None:
    """Best-effort ADD COLUMN migrations for SQLite dev databases.

    Alembic handles schema changes in production. For local SQLite databases
    created before new columns were added, we issue ALTER TABLE statements and
    silently swallow errors when the column already exists.
    """
    additions = [
        ("remediations", "confidence_flagged", "BOOLEAN NOT NULL DEFAULT 0"),
        ("remediations", "diff_warnings",      "TEXT"),
    ]
    for table, column, definition in additions:
        try:
            await conn.execute(
                text(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            )
        except Exception:
            pass  # column already exists or table not yet created — both are fine
