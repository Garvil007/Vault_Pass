"""Tests for crypto.kyber — Kyber-1024 key encapsulation."""
from crypto import kyber


def test_keypair_generates_nonempty_keys(kyber_keypair):
    """Both public and secret keys must be non-empty bytes."""
    public_key, secret_key = kyber_keypair
    assert isinstance(public_key, bytes) and len(public_key) > 0, "public key empty"
    assert isinstance(secret_key, bytes) and len(secret_key) > 0, "secret key empty"


def test_encap_decap_shared_secret_matches(kyber_keypair):
    """Encapsulation and decapsulation must agree on the same shared secret."""
    public_key, secret_key = kyber_keypair
    ciphertext, ss_server = kyber.encapsulate(public_key)
    ss_client = kyber.decapsulate(secret_key, ciphertext)
    assert ss_server == ss_client, (
        f"shared secrets differ: server {ss_server!r} vs client {ss_client!r}"
    )


def test_wrong_secret_key_produces_different_secret(kyber_keypair):
    """Decapsulating with a wrong secret key must not recover the secret."""
    public_key, _secret_key = kyber_keypair
    _wrong_pub, wrong_secret_key = kyber.generate_keypair()
    ciphertext, ss_server = kyber.encapsulate(public_key)
    ss_wrong = kyber.decapsulate(wrong_secret_key, ciphertext)
    assert ss_wrong != ss_server, "wrong secret key must not match the shared secret"


def test_keypair_keys_are_different(kyber_keypair):
    """Public and secret keys must not be identical."""
    public_key, secret_key = kyber_keypair
    assert public_key != secret_key, "public and secret keys must differ"
