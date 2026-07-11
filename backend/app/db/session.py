"""Async SQLAlchemy engine/session setup.

Supports SQLite (zero-config local) and PostgreSQL (production) via the same
async API. The DATABASE_URL scheme selects the driver.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    pass


# check_same_thread is only meaningful for SQLite; harmless otherwise.
connect_args = {"check_same_thread": False} if settings.is_sqlite else {}

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    connect_args=connect_args,
    pool_pre_ping=not settings.is_sqlite,
)

AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncSession:
    """FastAPI dependency yielding a session with commit/rollback safety."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create tables. For MVP we use create_all; production uses Alembic."""
    from app import models  # noqa: F401  (ensure models are imported/registered)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
