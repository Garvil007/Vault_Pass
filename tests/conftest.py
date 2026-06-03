"""Shared database fixtures for the integration test suite.

Targets a real, separate PostgreSQL database given by ``DATABASE_URL_TEST`` —
never the dev/prod ``DATABASE_URL``. The schema is built once per session by
running the project's Alembic migrations programmatically (no subprocess).

Isolation model:
- ``db_session`` opens a connection, begins an outer transaction, and binds the
  Session with ``join_transaction_mode="create_savepoint"`` so that even a
  ``commit()`` inside a test only releases a SAVEPOINT. The outer transaction is
  rolled back in teardown, so nothing persists between tests.
"""
import os

import pytest
from alembic import command
from alembic.config import Config
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from db.models import User

load_dotenv()


@pytest.fixture(scope="session")
def test_engine():
    """Session-scoped engine on DATABASE_URL_TEST, with migrations applied.

    Skips the whole suite if DATABASE_URL_TEST is unset, and refuses to run if
    it equals DATABASE_URL (guard against nuking the dev database).
    """
    test_url = os.getenv("DATABASE_URL_TEST")
    if not test_url:
        pytest.skip("DATABASE_URL_TEST is not set — skipping DB integration tests")

    dev_url = os.getenv("DATABASE_URL")
    assert test_url != dev_url, (
        "DATABASE_URL_TEST must differ from DATABASE_URL — refusing to test "
        "against the dev/prod database"
    )

    # Our env.py reads DATABASE_URL and overrides alembic's sqlalchemy.url, so
    # point DATABASE_URL at the test DB for the duration of the migration run.
    original = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = test_url
    try:
        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", test_url)
        command.upgrade(alembic_cfg, "head")
    finally:
        if original is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = original

    engine = create_engine(test_url, pool_pre_ping=True)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(test_engine):
    """Function-scoped session wrapped in a transaction that always rolls back."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def test_user(db_session):
    """Create and commit a User row, returning it. Uses the shared db_session."""
    user = User(
        email="test@example.com",
        argon2_salt=b"0123456789abcdef",  # 16 bytes
        kyber_public_key=b"",             # empty until a real key is set
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user
