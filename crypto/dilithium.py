"""ML-DSA-65 signing — STUB for Phase 3 (audit-event signing / blockchain anchor).

NIST FIPS 204 standardised successor of round-3 Dilithium3 (same security level
= NIST Level 3). Plan called this "Dilithium3"; module name kept for continuity.
"""
import oqs

ALG = "ML-DSA-65"


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (public_key, secret_key)."""
    with oqs.Signature(ALG) as sig:
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
    return public_key, secret_key


def sign(secret_key: bytes, message: bytes) -> bytes:
    with oqs.Signature(ALG, secret_key=secret_key) as sig:
        return sig.sign(message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    with oqs.Signature(ALG) as sig:
        return sig.verify(message, signature, public_key)
