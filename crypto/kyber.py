"""Kyber-1024 key encapsulation (KEM) — quantum-safe key exchange.

Registration: generate keypair. Public key -> server, secret key -> client.
Login: server encapsulates against public key -> (ciphertext, shared_secret),
sends ciphertext to client. Client decapsulates with secret key to recover the
same shared_secret, which becomes the AES vault key for the session.
"""
import oqs

ALG = "Kyber1024"


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (public_key, secret_key)."""
    with oqs.KeyEncapsulation(ALG) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    return public_key, secret_key


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Server-side. Return (ciphertext, shared_secret)."""
    with oqs.KeyEncapsulation(ALG) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Client-side. Return shared_secret."""
    with oqs.KeyEncapsulation(ALG, secret_key=secret_key) as kem:
        return kem.decap_secret(ciphertext)
