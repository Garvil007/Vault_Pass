"""Tests for crypto.kdf — Argon2id key derivation and salt generation."""
from crypto import kdf


def test_derive_key_is_deterministic():
    """Same password + same salt must always yield the same key."""
    salt = kdf.generate_salt()
    k1 = kdf.derive_key("correct-horse", salt)
    k2 = kdf.derive_key("correct-horse", salt)
    assert k1 == k2, f"expected identical keys, got {k1!r} vs {k2!r}"


def test_derive_key_different_passwords():
    """Different passwords with the same salt must produce different keys."""
    salt = kdf.generate_salt()
    k1 = kdf.derive_key("password-a", salt)
    k2 = kdf.derive_key("password-b", salt)
    assert k1 != k2, "different passwords must not collide to the same key"


def test_derive_key_different_salts():
    """Same password with different salts must produce different keys."""
    k1 = kdf.derive_key("same-password", kdf.generate_salt())
    k2 = kdf.derive_key("same-password", kdf.generate_salt())
    assert k1 != k2, "different salts must produce different keys"


def test_derive_key_output_length():
    """Derived key must always be exactly 32 bytes."""
    key = kdf.derive_key("any-password", kdf.generate_salt())
    assert len(key) == 32, f"expected 32 bytes, got {len(key)}"


def test_generate_salt_length():
    """Generated salt must always be exactly 16 bytes."""
    salt = kdf.generate_salt()
    assert len(salt) == 16, f"expected 16 bytes, got {len(salt)}"


def test_generate_salt_is_random():
    """Two salt generations must differ (cryptographically random)."""
    s1 = kdf.generate_salt()
    s2 = kdf.generate_salt()
    assert s1 != s2, "two generated salts must not be identical"
