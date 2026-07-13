"""Database engine + session management.

SQLite runs in WAL mode (§3.3.3) so the background worker can write while the web
process reads. The same code path works against Postgres via ``DATABASE_URL``.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings, get_settings
from app.models.base import Base

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def _configure_sqlite(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _set_pragma(dbapi_connection, _record):  # noqa: ANN001, ANN202
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


def init_engine(settings: Settings | None = None) -> Engine:
    """Create (once) and return the process-wide engine."""
    global _engine, _SessionLocal
    if _engine is not None:
        return _engine
    settings = settings or get_settings()
    if settings.database_url.startswith("sqlite"):
        settings.ensure_dirs()
    connect_args = (
        {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
    )
    _engine = create_engine(settings.database_url, future=True, connect_args=connect_args)
    if settings.database_url.startswith("sqlite"):
        _configure_sqlite(_engine)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _engine


def get_sessionmaker() -> sessionmaker[Session]:
    if _SessionLocal is None:
        init_engine()
    assert _SessionLocal is not None
    return _SessionLocal


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session context: commit on success, rollback on error."""
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def create_all(settings: Settings | None = None) -> None:
    """Create all tables directly (used by tests / first-run bootstrap).

    Production uses Alembic migrations; this is the fast path for an in-memory or
    throwaway database.
    """
    engine = init_engine(settings)
    Base.metadata.create_all(engine)


def reset_engine() -> None:
    """Drop cached engine/sessionmaker (test isolation)."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None
