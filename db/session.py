"""Database engine + session factory.

Reads ``DATABASE_URL`` from the environment. If unset, falls back to a local
SQLite file (``vaultpass.db``) so the app runs with zero infra during dev —
no PostgreSQL required. ``get_db()`` yields a session and always closes it,
usable both as a plain context source (CLI) and a FastAPI ``Depends``.
"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from db.models import Base

# SQLite fallback when DATABASE_URL is not configured.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vaultpass.db")

# SQLite needs check_same_thread=False to be shared across FastAPI threads.
# pool_pre_ping validates connections before use (matters for Postgres, not SQLite).
_is_sqlite = DATABASE_URL.startswith("sqlite")
_engine_kwargs = {"pool_pre_ping": True}
if _is_sqlite:
    _engine_kwargs = {"connect_args": {"check_same_thread": False}}

engine = create_engine(DATABASE_URL, **_engine_kwargs)

SessionLocal = sessionmaker(
    bind=engine, autocommit=False, autoflush=False, class_=Session
)


def init_db() -> None:
    """Create all tables. Dev convenience for SQLite; use Alembic for Postgres."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """Yield a DB session, closing it on exit. Works for CLI and FastAPI Depends."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
