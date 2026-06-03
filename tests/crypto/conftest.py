"""Shared pytest fixtures for the crypto test suite (no DB, crypto only).

- ``kyber_keypair`` is session-scoped: the Kyber keypair is generated once and
  reused across every test, since keygen is relatively expensive.
- ``vault_key`` is function-scoped: each test gets a fresh encapsulated shared
  secret (the per-session AES vault key), exercising a new encapsulation.
"""
import pytest

from crypto import kyber


@pytest.fixture(scope="session")
def kyber_keypair():
    """Generate one Kyber keypair for the whole test session.

    Returns ``(public_key, secret_key)``.
    """
    return kyber.generate_keypair()


@pytest.fixture
def vault_key(kyber_keypair):
    """Encapsulate a fresh shared secret (the AES vault key) per test.

    Returns the 32-byte shared secret recovered by decapsulation, so it is
    identical to what the client would derive.
    """
    public_key, secret_key = kyber_keypair
    ciphertext, _shared_secret = kyber.encapsulate(public_key)
    return kyber.decapsulate(secret_key, ciphertext)
