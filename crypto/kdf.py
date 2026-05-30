"""Argon2id master-key derivation.

Derives a 32-byte key from the master password + per-user salt.
Derived key protects the Kyber private key client-side; the server
never sees the master password.
"""
import os

from argon2.low_level import Type, hash_secret_raw

SALT_BYTES = 16
HASH_LENGTH = int(os.getenv("ARGON2_HASH_LENGTH", "32"))
TIME_COST = int(os.getenv("ARGON2_TIME_COST", "3"))
MEMORY_COST = int(os.getenv("ARGON2_MEMORY_COST", "65536"))
PARALLELISM = int(os.getenv("ARGON2_PARALLELISM", "1"))


def generate_salt() -> bytes:
    """Random per-user salt. Store alongside the user record."""
    return os.urandom(SALT_BYTES)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a deterministic 32-byte key from password + salt.

    Same password + same salt always yields the same key.
    """
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=TIME_COST,
        memory_cost=MEMORY_COST,
        parallelism=PARALLELISM,
        hash_len=HASH_LENGTH,
        type=Type.ID,
    )
