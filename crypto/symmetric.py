"""AES-256-GCM vault-item encryption.

Encrypts a dict (JSON-serialised) with the Kyber shared secret as key.
Stored blob layout: nonce (12 bytes) || ciphertext+tag.
"""
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12


def encrypt(vault_key: bytes, data: dict, associated_data: bytes | None = None) -> bytes:
    """Return nonce || ciphertext. Fresh random nonce each call."""
    nonce = os.urandom(NONCE_BYTES)
    plaintext = json.dumps(data).encode("utf-8")
    ciphertext = AESGCM(vault_key).encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt(vault_key: bytes, blob: bytes, associated_data: bytes | None = None) -> dict:
    """Split nonce prefix, decrypt remainder, return original dict.

    Raises cryptography.exceptions.InvalidTag on tamper / wrong key.
    """
    nonce, ciphertext = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    plaintext = AESGCM(vault_key).decrypt(nonce, ciphertext, associated_data)
    return json.loads(plaintext.decode("utf-8"))
