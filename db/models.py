"""SQLAlchemy 2.0 ORM models for VaultPass.

Two tables: ``User`` (account + Kyber public key + Argon2 salt) and
``VaultItem`` (opaque encrypted blobs owned by a user). Types are chosen to work
on both PostgreSQL and the SQLite dev fallback:

- ``Uuid`` -> native ``UUID`` on Postgres, ``CHAR(32)`` on SQLite.
- ``LargeBinary`` -> ``BYTEA`` on Postgres, ``BLOB`` on SQLite.

The server stores ``encrypted_blob`` as raw bytes and never decrypts it
(zero-knowledge). Deleting a user cascades to their vault items.
"""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, LargeBinary, String, Uuid, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base; ``Base.metadata`` feeds create_all and Alembic."""


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    kyber_public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    argon2_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    items: Mapped[list["VaultItem"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class VaultItem(Base):
    __tablename__ = "vault_items"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    item_type: Mapped[str] = mapped_column(String(32), nullable=False)
    encrypted_blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    user: Mapped["User"] = relationship(back_populates="items")
