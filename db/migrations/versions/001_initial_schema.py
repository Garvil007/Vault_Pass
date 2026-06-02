"""initial_schema — create the users and vault_items tables.

Creates the two core VaultPass tables:
- ``users``        : account, Kyber public key (nullable until registration
                     completes), Argon2 salt, created_at.
- ``vault_items``  : opaque AES-GCM encrypted blobs owned by a user, with an
                     item_type constrained to password/totp/note and a
                     cascading FK so deleting a user removes their items.

Column types target PostgreSQL (UUID, BYTEA, TIMESTAMP WITH TIME ZONE) and
degrade to portable equivalents on SQLite via with_variant, so the migration
runs on both the Postgres prod DB and the local SQLite dev DB.

Revision ID: 001
Revises:
Create Date: 2026-06-02
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Postgres-native UUID, degrading to the generic Uuid (CHAR(32)) on SQLite.
GUID = postgresql.UUID(as_uuid=True).with_variant(sa.Uuid(as_uuid=True), "sqlite")


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", GUID, primary_key=True, nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("kyber_public_key", sa.LargeBinary(), nullable=True),
        sa.Column("argon2_salt", sa.LargeBinary(length=16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "vault_items",
        sa.Column("id", GUID, primary_key=True, nullable=False),
        sa.Column("user_id", GUID, nullable=False),
        sa.Column("item_type", sa.String(length=32), nullable=False),
        sa.Column("encrypted_blob", sa.LargeBinary(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.CheckConstraint(
            "item_type IN ('password', 'totp', 'note')",
            name="ck_vault_items_item_type",
        ),
    )
    op.create_index(
        "ix_vault_items_user_id", "vault_items", ["user_id"], unique=False
    )


def downgrade() -> None:
    # Reverse order: drop the child table (FK to users) before the parent.
    op.drop_index("ix_vault_items_user_id", table_name="vault_items")
    op.drop_table("vault_items")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
