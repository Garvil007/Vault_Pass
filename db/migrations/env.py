"""Alembic environment for VaultPass.

Wires Alembic to our app config instead of a hardcoded URL:
- Loads ``.env`` and reads ``DATABASE_URL`` (same source as db/session.py), so
  migrations always target the same database the app uses.
- Points ``target_metadata`` at ``Base.metadata`` so ``--autogenerate`` can diff
  the models against the live schema.

Supports both offline mode (emit SQL without a DBAPI connection) and online mode
(run against a live connection).
"""
import os
import sys
from logging.config import fileConfig

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import engine_from_config, pool


sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from db.models import Base  # noqa: E402

# Alembic Config object (reads alembic.ini).
config = context.config

# Load .env, then inject DATABASE_URL into the Alembic config at runtime so the
# real URL is never committed in alembic.ini.
load_dotenv()
database_url = os.getenv("DATABASE_URL")
if not database_url:
    raise RuntimeError(
        "DATABASE_URL is not set. Add it to your .env before running Alembic."
    )
config.set_main_option("sqlalchemy.url", database_url)

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Model metadata for 'autogenerate' support.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — emit SQL using just a URL, no DBAPI."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode — against a live Engine/connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
