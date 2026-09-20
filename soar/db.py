"""Database engine/session handling (SQLite for local dev, PostgreSQL in Docker)."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from soar.config import get_settings

_engine: Engine | None = None
_sessionmaker: sessionmaker | None = None


def _build_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if ":memory:" in url or url in ("sqlite://", "sqlite:///"):
            kwargs["poolclass"] = StaticPool
        else:
            path = url.replace("sqlite:///", "", 1)
            if path:
                import os
                os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        engine = create_engine(url, **kwargs)

        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn, _):  # noqa: ANN001
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()

        return engine
    if url.startswith("postgresql://"):  # psycopg3 driver
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    return create_engine(url, pool_pre_ping=True)


def get_engine() -> Engine:
    global _engine, _sessionmaker
    if _engine is None:
        _engine = _build_engine(get_settings().database_url)
        _sessionmaker = sessionmaker(bind=_engine, expire_on_commit=False, autoflush=True)
    return _engine


def reset_engine() -> None:
    """Dispose the engine (tests point the app at a fresh database)."""
    global _engine, _sessionmaker
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _sessionmaker = None


def new_session() -> Session:
    get_engine()
    assert _sessionmaker is not None
    return _sessionmaker()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on any error."""
    s = new_session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency. Handlers commit explicitly via the service layer."""
    s = new_session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()
