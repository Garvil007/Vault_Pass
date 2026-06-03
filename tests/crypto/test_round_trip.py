"""Full-stack integration tests: crypto -> PostgreSQL -> crypto.

Exercises the real flow an item takes through VaultPass: a Kyber-derived vault
key encrypts a dict with AES-256-GCM, the blob is stored in Postgres, read back,
and decrypted to the original — plus per-user isolation and cascade delete.

These use the DB fixtures from tests/conftest.py (test_user, db_session) and
require DATABASE_URL_TEST to point at a real, separate Postgres database.
"""
from crypto import kyber, symmetric
from db.models import User, VaultItem


def test_full_encrypt_store_retrieve_decrypt(db_session, test_user):
    """Encrypt a dict, store the blob, read it back, and decrypt to the original."""
    # 1. Generate a Kyber keypair.
    public_key, secret_key = kyber.generate_keypair()

    # 2. Attach the real public key to the user.
    test_user.kyber_public_key = public_key
    db_session.commit()

    # 3. Derive a vault key and encrypt an item.
    ciphertext, vault_key = kyber.encapsulate(public_key)
    original = {"url": "https://bank.example", "username": "alice", "password": "p@ss"}
    blob = symmetric.encrypt(vault_key, original)

    item = VaultItem(user_id=test_user.id, item_type="password", encrypted_blob=blob)
    db_session.add(item)
    db_session.commit()
    item_id = item.id

    # 4. Read the row back fresh from the DB.
    db_session.expire_all()
    fetched = db_session.get(VaultItem, item_id)
    assert fetched is not None, "stored VaultItem could not be retrieved"
    assert fetched.encrypted_blob == blob, "stored blob differs from what was written"

    # 5. Recover the same vault key via decapsulation.
    recovered_key = kyber.decapsulate(secret_key, ciphertext)
    assert recovered_key == vault_key, "decapsulated key does not match"

    # 6. Decrypt and compare to the original dict.
    decrypted = symmetric.decrypt(recovered_key, fetched.encrypted_blob)
    assert decrypted == original, f"expected {original} got {decrypted}"


def test_two_users_cannot_share_items(db_session):
    """An item owned by user 1 must not be reachable when filtering by user 2."""
    user1 = User(email="u1@example.com", argon2_salt=b"salt-one--------", kyber_public_key=b"")
    user2 = User(email="u2@example.com", argon2_salt=b"salt-two--------", kyber_public_key=b"")
    db_session.add_all([user1, user2])
    db_session.commit()

    item = VaultItem(user_id=user1.id, item_type="note", encrypted_blob=b"\x00secret")
    db_session.add(item)
    db_session.commit()

    leaked = (
        db_session.query(VaultItem)
        .filter_by(id=item.id, user_id=user2.id)
        .one_or_none()
    )
    assert leaked is None, "user2 must not be able to access user1's item"


def test_deleted_user_cascades_to_items(db_session):
    """Deleting a user must remove all their vault items (cascade)."""
    user = User(email="gone@example.com", argon2_salt=b"salt-gone-------", kyber_public_key=b"")
    db_session.add(user)
    db_session.commit()

    item = VaultItem(user_id=user.id, item_type="totp", encrypted_blob=b"\x00otp")
    db_session.add(item)
    db_session.commit()
    item_id = item.id

    db_session.delete(user)
    db_session.commit()

    assert db_session.get(VaultItem, item_id) is None, "item should be gone after user delete"
