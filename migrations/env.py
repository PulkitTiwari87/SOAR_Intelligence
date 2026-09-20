"""Alembic environment. The database URL comes from soar settings (DATABASE_URL), never from
alembic.ini, and a connection handed in by soar.bootstrap is reused when present."""
from alembic import context

from soar.config import get_settings
from soar.db import _build_engine
from soar.models import Base

config = context.config
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(url=get_settings().database_url, target_metadata=target_metadata,
                      literal_binds=True, dialect_opts={"paramstyle": "named"},
                      render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


def _run(connection) -> None:  # noqa: ANN001
    context.configure(connection=connection, target_metadata=target_metadata,
                      render_as_batch=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return
    with _build_engine(get_settings().database_url).connect() as conn:
        _run(conn)
        conn.commit()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
