"""Tests for crypto.symmetric — AES-256-GCM encrypt/decrypt of vault items."""
import pytest
from cryptography.exceptions import InvalidTag

from crypto import symmetric


def test_encrypt_decrypt_roundtrip(vault_key):
    """Encrypting a dict then decrypting must return the original dict."""
    data = {"url": "https://example.com", "username": "alice", "password": "s3cret"}
    blob = symmetric.encrypt(vault_key, data)
    out = symmetric.decrypt(vault_key, blob)
    assert out == data, f"expected {data} got {out}"


def test_tampered_blob_raises_invalid_tag(vault_key):
    """Flipping any byte of the blob must raise InvalidTag on decrypt."""
    blob = bytearray(symmetric.encrypt(vault_key, {"k": "v"}))
    blob[-1] ^= 0x01  # flip one bit in the auth tag
    with pytest.raises(InvalidTag):
        symmetric.decrypt(vault_key, bytes(blob))


def test_different_nonces_each_call(vault_key):
    """Two encryptions of identical data must differ (fresh random nonce)."""
    data = {"k": "v"}
    b1 = symmetric.encrypt(vault_key, data)
    b2 = symmetric.encrypt(vault_key, data)
    assert b1 != b2, "two encryptions must differ due to random nonces"


def test_output_minimum_length(vault_key):
    """Output must be at least 12 (nonce) + 16 (GCM tag) = 28 bytes."""
    blob = symmetric.encrypt(vault_key, {})
    assert len(blob) >= 28, f"expected >= 28 bytes, got {len(blob)}"


def test_empty_dict_roundtrip(vault_key):
    """Encrypting an empty dict must round-trip back to an empty dict."""
    blob = symmetric.encrypt(vault_key, {})
    out = symmetric.decrypt(vault_key, blob)
    assert out == {}, f"expected empty dict, got {out}"
