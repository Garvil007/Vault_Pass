#!/usr/bin/env python3
"""VaultPass dev CLI — register a user, add/list/get vault items.

Standalone demo driver for the local stack (crypto -> DB -> crypto). Uses
``get_db()`` for every DB operation and calls ``create_all_tables()`` at startup
so it works before Alembic is ever run.

Crypto note (IMPORTANT — differs from a naive reading of the task):
    Kyber is a KEM. ``encapsulate(pubkey)`` returns ``(ciphertext, shared_secret)``
    where ``shared_secret`` is RANDOM per call. The ONLY way to recover that exact
    secret later is ``decapsulate(secret_key, ciphertext)`` using THAT ciphertext.
    Therefore the KEM ciphertext MUST be persisted alongside the encrypted blob —
    "re-encapsulating" at read time would yield a different key and the AES-GCM
    decrypt would fail with InvalidTag. The ciphertext is NOT secret (it is the
    public encapsulation), so storing it is safe. The vault_key (shared secret)
    is never persisted and never printed.

Stored blob layout:  uint16 kem_ct_len (big-endian) || kem_ct || nonce || aes_ct
"""
import argparse
import json
import struct
import sys
import uuid
from contextlib import contextmanager

from crypto import kdf, kyber, symmetric
from db.models import User, VaultItem
from db.session import create_all_tables, get_db

PRIVKEY_SUFFIX = ".privkey"


@contextmanager
def session_scope():
    """Wrap get_db() (a generator) in a context manager that always closes it."""
    gen = get_db()
    db = next(gen)
    try:
        yield db
    finally:
        gen.close()


def _privkey_path(email: str) -> str:
    return f"{email}{PRIVKEY_SUFFIX}"


def _load_user(db, email: str) -> User:
    user = db.query(User).filter_by(email=email).one_or_none()
    if user is None:
        raise SystemExit(f"error: no user registered with email {email!r}")
    return user


# --- commands ---------------------------------------------------------------

def cmd_register(args) -> None:
    salt = kdf.generate_salt()
    # vault keys are derived per-session at add/get time; here we only need the
    # long-term Kyber identity keypair.
    public_key, secret_key = kyber.generate_keypair()  # SENSITIVE: secret_key

    with session_scope() as db:
        user = User(
            email=args.email,
            kyber_public_key=public_key,
            argon2_salt=salt,
        )
        db.add(user)
        try:
            db.commit()
        except Exception:
            db.rollback()
            raise SystemExit(f"error: email {args.email!r} is already registered")
        db.refresh(user)
        user_id = user.id

    # WARNING: DEMO ONLY. Writing the Kyber secret key to an unencrypted file on
    # disk defeats the zero-knowledge design. In production the secret key never
    # touches the server and is sealed client-side under the Argon2id-derived key
    # (see crypto/kdf.py). NEVER do this in a real deployment.
    with open(_privkey_path(args.email), "wb") as fh:
        fh.write(secret_key)  # SENSITIVE: secret_key leaves memory -> disk (demo)

    print(f"Registered {args.email}. User ID: {user_id}")


def cmd_add(args) -> None:
    with session_scope() as db:
        user = _load_user(db, args.email)

        # SENSITIVE: vault_key (Kyber shared secret) created here. kem_ct is the
        # public encapsulation and IS persisted; vault_key is NOT.
        kem_ct, vault_key = kyber.encapsulate(user.kyber_public_key)

        item_dict = {
            "url": args.url,
            "username": args.username,
            "password": args.password,
        }
        aes_blob = symmetric.encrypt(vault_key, item_dict)
        del vault_key  # SENSITIVE: discard the shared secret immediately

        stored = struct.pack(">H", len(kem_ct)) + kem_ct + aes_blob

        item = VaultItem(
            user_id=user.id,
            item_type="password",
            encrypted_blob=stored,
        )
        db.add(item)
        db.commit()
        db.refresh(item)
        item_id = item.id

    print(f"Stored. Item ID: {item_id}")


def cmd_get(args) -> None:
    try:
        with open(_privkey_path(args.email), "rb") as fh:
            secret_key = fh.read()  # SENSITIVE: secret_key loaded from disk (demo)
    except FileNotFoundError:
        raise SystemExit(
            f"error: private key file {_privkey_path(args.email)!r} not found "
            f"(did you register {args.email!r} on this machine?)"
        )

    try:
        item_uuid = uuid.UUID(args.item_id)
    except ValueError:
        # malformed id is treated the same as "not found" — reveal nothing.
        raise SystemExit("error: item not found")

    with session_scope() as db:
        user = _load_user(db, args.email)

        # Ownership check folded into the query: an item owned by someone else is
        # indistinguishable from a nonexistent one. Do NOT leak its existence.
        item = (
            db.query(VaultItem)
            .filter_by(id=item_uuid, user_id=user.id)
            .one_or_none()
        )
        if item is None:
            raise SystemExit("error: item not found")
        stored = item.encrypted_blob

    (ct_len,) = struct.unpack(">H", stored[:2])
    kem_ct = stored[2 : 2 + ct_len]
    aes_blob = stored[2 + ct_len :]

    # SENSITIVE: recover the SAME vault_key via decapsulation of the stored
    # ciphertext. Never printed; discarded after decrypt.
    vault_key = kyber.decapsulate(secret_key, kem_ct)
    item_dict = symmetric.decrypt(vault_key, aes_blob)
    del vault_key, secret_key  # SENSITIVE: discard

    print(json.dumps(item_dict, indent=2))


def cmd_list(args) -> None:
    with session_scope() as db:
        user = _load_user(db, args.email)
        items = (
            db.query(VaultItem)
            .filter_by(user_id=user.id)
            .order_by(VaultItem.updated_at)
            .all()
        )
        rows = [(str(i.id), i.item_type, i.updated_at.isoformat()) for i in items]

    if not rows:
        print(f"No vault items for {args.email}.")
        return

    print(f"{'ID':36} | {'type':8} | updated_at")
    print("-" * 36 + "-+-" + "-" * 8 + "-+-" + "-" * 25)
    for item_id, item_type, updated in rows:
        print(f"{item_id:36} | {item_type:8} | {updated}")


# --- argparse wiring --------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vaultpass", description="VaultPass dev CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_reg = sub.add_parser("register", help="register a new user")
    p_reg.add_argument("--email", required=True)
    p_reg.set_defaults(func=cmd_register)

    p_add = sub.add_parser("add", help="add a password item")
    p_add.add_argument("--email", required=True)
    p_add.add_argument("--url", required=True)
    p_add.add_argument("--username", required=True)
    p_add.add_argument("--password", required=True)
    p_add.set_defaults(func=cmd_add)

    p_get = sub.add_parser("get", help="decrypt and print one item")
    p_get.add_argument("--email", required=True)
    p_get.add_argument("--item-id", required=True)
    p_get.set_defaults(func=cmd_get)

    p_list = sub.add_parser("list", help="list item metadata (no decryption)")
    p_list.add_argument("--email", required=True)
    p_list.set_defaults(func=cmd_list)

    return parser


def main(argv=None) -> None:
    # Dev convenience: ensure tables exist even before Alembic is run.
    create_all_tables()
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
