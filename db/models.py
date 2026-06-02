"""SQLAlchemy 2.0 ORM models for VaultPass (pure DB layer — no web imports).

Defines the persistence schema:
- ``User``      — account, Kyber public key, Argon2 salt.
- ``VaultItem`` — opaque encrypted blobs owned by a user (server never decrypts).

UUID primary keys use the PostgreSQL ``UUID`` type, with a ``with_variant``
fallback to SQLAlchemy's generic ``Uuid`` on SQLite so the local dev database
keeps working. All datetimes are timezone-aware (UTC) and set Python-side via
callables (never a frozen import-time value).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    LargeBinary,
    String,
    Uuid,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)

# Postgres-native UUID, but degrade to the cross-dialect generic Uuid on SQLite
# so the local fallback DB still stores/reads uuid.UUID objects correctly.
GUID = UUID(as_uuid=True).with_variant(Uuid(as_uuid=True), "sqlite")

# Allowed VaultItem.item_type values, enforced at the DB level.
ITEM_TYPES = ("password", "totp", "note")


def utcnow() -> datetime:
    """Timezone-aware current UTC time. Used as a column default callable."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Declarative base; ``Base.metadata`` drives create_all and Alembic."""


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    # Filled in when WebAuthn/Kyber registration completes (Phase 2), so nullable.
    kyber_public_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    argon2_salt: Mapped[bytes] = mapped_column(LargeBinary(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    items: Mapped[list["VaultItem"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class VaultItem(Base):
    __tablename__ = "vault_items"
    __table_args__ = (
        CheckConstraint(
            "item_type IN ('password', 'totp', 'note')",
            name="ck_vault_items_item_type",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    item_type: Mapped[str] = mapped_column(String(32), nullable=False)
    encrypted_blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="items")
