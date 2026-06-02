"""Database engine, session factory, and the get_db() dependency.

``get_db()`` is a generator that yields one SQLAlchemy ``Session`` and always
closes it in a ``finally`` block — even if the handler raises. This single
function serves two callers unchanged:

- CLI / tests: ``db = next(get_db())`` (or drive the generator manually).
- FastAPI (Phase 2): ``def route(db: Session = Depends(get_db)): ...`` — FastAPI
  drives the generator, injecting the yielded session and running the
  ``finally`` cleanup after the response is sent.

DATABASE_URL is read from the environment (loaded from .env). It is required:
the module raises rather than silently defaulting to None, so a misconfigured
deployment fails loudly at import instead of at first query. For zero-infra dev,
set ``DATABASE_URL=sqlite:///./vaultpass.db`` in your .env.
"""
import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from db.models import Base

# Load .env into os.environ before reading any config below.
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not set. Add it to your .env "
        "(e.g. DATABASE_URL=sqlite:///./vaultpass.db for local dev, "
        "or a postgresql+psycopg2://... URL)."
    )

# echo SQL only when DEBUG=1, to keep normal runs quiet.
_echo = os.getenv("DEBUG") == "1"

# SQLite needs check_same_thread=False to be shared across FastAPI's threads;
# harmless/ignored for other backends.
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    echo=_echo,
    connect_args=_connect_args,
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    class_=Session,
)


def get_db():
    """Yield a DB session and guarantee it is closed.

    Usable directly (CLI/tests) and as a FastAPI ``Depends(get_db)`` unchanged.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_all_tables() -> None:
    """Create every table defined on ``Base.metadata``.

    Dev/test convenience (cli.py, pytest). For production schema changes on
    PostgreSQL, use Alembic migrations instead.
    """
    Base.metadata.create_all(bind=engine)
