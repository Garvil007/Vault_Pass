"""Pydantic v2 request/response schemas for the VaultPass API.

These define the JSON shapes crossing the HTTP boundary. Encrypted material
(``encrypted_blob``, ``kyber_ciphertext``) is carried as base64 strings because
raw bytes are not JSON-serialisable; the server treats them as opaque — it never
decrypts vault contents (zero-knowledge design).
"""
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr

# Allowed vault item kinds. Reused so the constraint lives in one place.
ItemType = Literal["password", "totp", "note"]


class WebAuthnRegisterBeginRequest(BaseModel):
    """Client kicks off WebAuthn registration with the account email."""

    email: EmailStr


class WebAuthnLoginBeginRequest(BaseModel):
    """Client kicks off WebAuthn login with the account email."""

    email: EmailStr


class VaultItemCreate(BaseModel):
    """Payload to store a new encrypted vault item.

    ``encrypted_blob`` is the base64 of ``nonce + ciphertext`` produced
    client-side by ``crypto.symmetric.encrypt`` — the server never sees plaintext.
    """

    item_type: ItemType
    encrypted_blob: str


class VaultItemResponse(BaseModel):
    """Full vault item returned to the owner, including the encrypted blob."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    item_type: str
    encrypted_blob: str
    updated_at: datetime


class VaultItemListResponse(BaseModel):
    """Lightweight vault item for list views — omits the blob to save bandwidth."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    item_type: str
    updated_at: datetime


class TokenResponse(BaseModel):
    """Issued on successful login.

    Carries the session JWT plus the Kyber ciphertext the client decapsulates
    with its secret key to recover the per-session vault key.
    """

    access_token: str
    token_type: str
    kyber_ciphertext: str
