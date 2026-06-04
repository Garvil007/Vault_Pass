# VaultPass

A post-quantum, zero-knowledge password manager. The server stores only opaque
encrypted blobs — it never sees plaintext, the master password, or the vault key.

## Cryptographic design

| Primitive | Algorithm | Role |
|-----------|-----------|------|
| KEM | **Kyber-1024** | Per-session shared secret = the AES vault key |
| Symmetric | **AES-256-GCM** | Encrypts each vault item (`nonce(12) ‖ ciphertext+tag(16)`) |
| KDF | **Argon2id** | Derives a 32-byte key from master password + 16-byte salt (client-side) |
| Signatures | **ML-DSA-65** (FIPS-204) | Audit-event signing (Phase 3) |

> **Note:** upstream liboqs dropped the legacy `Dilithium3`; `crypto/dilithium.py`
> uses `ML-DSA-65` (the same NIST Level 3 scheme).

### Why these choices
- **Zero-knowledge:** the Kyber secret key and the master password never leave the
  client. The server holds the public key and the encrypted blobs, nothing else.
- **Quantum-safe:** Kyber (KEM) and ML-DSA (signatures) are NIST PQC standards, so
  vaults stay confidential even against a future quantum adversary.

## Project layout

```
crypto/   kdf.py kyber.py symmetric.py dilithium.py   (Phase 1 — done)
db/       models.py session.py migrations/            (Phase 2)
api/      main.py schemas.py dependencies.py routers/  (Phase 2 — scaffold)
tests/    conftest.py (DB fixtures) crypto/*           (20 tests)
cli.py    standalone dev CLI (register / add / list / get)
```

## Requirements

- **Python 3.10** (developed on 3.10.6, Windows).
- **liboqs** native library, built locally (provides Kyber + ML-DSA via
  `liboqs-python`). On this machine the DLL lives at `C:\Users\garvi\_oqs\bin`;
  `crypto/__init__.py` prepends it to `PATH` at import.
- **PostgreSQL** for production / the integration test suite. SQLite works for
  local dev (see below).

Python dependencies (`requirements.txt`): `liboqs-python`, `cryptography`,
`argon2-cffi`, `SQLAlchemy`, `alembic`, `psycopg2-binary`, `pytest`,
`python-dotenv`. The API layer also needs `fastapi` and `uvicorn`.

## Setup

```powershell
# 1. Create / activate the virtualenv (repo uses myenv\)
python -m venv myenv
myenv\Scripts\python.exe -m pip install -r requirements.txt fastapi uvicorn

# 2. Configure environment
copy .env.example .env
# edit .env: set DATABASE_URL (and DATABASE_URL_TEST for the integration suite)

# 3. Apply migrations
myenv\Scripts\python.exe -m alembic upgrade head
```

### Environment variables (`.env`, gitignored)

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | **Required.** App/dev database. `sqlite:///./vaultpass.db` for zero-infra dev, or `postgresql+psycopg2://…` |
| `DATABASE_URL_TEST` | Separate database for the integration suite. Must differ from `DATABASE_URL`. Unset → those tests skip. |
| `ARGON2_TIME_COST` / `ARGON2_MEMORY_COST` / `ARGON2_PARALLELISM` / `ARGON2_HASH_LENGTH` | Argon2id tuning (defaults: 3 / 65536 / 1 / 32) |

`db/session.py` **raises** if `DATABASE_URL` is unset — no silent default.

## The CLI

A standalone dev driver that exercises the full stack (crypto → DB → crypto).
It calls `create_all_tables()` at startup, so it works before Alembic is run.

```powershell
$env:DATABASE_URL = "sqlite:///./vaultpass.db"

# Register a user (writes <email>.privkey locally — DEMO ONLY, see warning below)
myenv\Scripts\python.exe cli.py register --email alice@example.com

# Add an encrypted item
myenv\Scripts\python.exe cli.py add --email alice@example.com `
    --url https://bank.example --username alice --password "p@ss123"

# List item metadata (no decryption)
myenv\Scripts\python.exe cli.py list --email alice@example.com

# Decrypt one item by id (loads the .privkey, recovers the vault key, decrypts)
myenv\Scripts\python.exe cli.py get --email alice@example.com --item-id <uuid>
```

> **⚠ Security — demo only.** `register` writes the Kyber **secret key** to an
> unencrypted `<email>.privkey` file in the working directory. This defeats the
> zero-knowledge design and exists purely so the CLI can decrypt locally. In a
> real deployment the secret key never touches disk in the clear — it is sealed
> client-side under the Argon2id-derived key. `*.privkey` is gitignored.

### How an item round-trips

Kyber is a KEM: `encapsulate(public_key)` returns `(ciphertext, shared_secret)`,
where the shared secret is **random on every call**. The only way to recover that
exact secret later is `decapsulate(secret_key, ciphertext)` with *that* ciphertext.
So the CLI persists the KEM ciphertext alongside the AES blob (it is not secret —
it is the public encapsulation):

```
stored blob = uint16 ct_len  ‖  kem_ct  ‖  nonce(12)  ‖  aes_ct+tag
```

`get` reads the stored `kem_ct` and decapsulates it — it does **not** re-encapsulate
(that would produce a different key and fail AES-GCM authentication). The vault key
is never written to disk and never printed.

## REST API (Phase 2 — scaffold)

```powershell
myenv\Scripts\python.exe -m uvicorn api.main:app --reload
```

- `GET /` — health check (`{"status": "ok"}`)
- `auth` and `vault` routers are mounted but are mostly stubs (see Status).
- CORS allows `http://localhost:3000` and `http://localhost:5173`.

## Testing

```powershell
# Unit tests (DB integration tests skip without DATABASE_URL_TEST)
myenv\Scripts\python.exe -m pytest tests/ -v

# Include DB integration tests against a throwaway SQLite DB
$env:DATABASE_URL_TEST = "sqlite:///./test_vaultpass.db"
myenv\Scripts\python.exe -m pytest tests/ -v
```

20 tests: 17 crypto unit tests + 3 full-stack integration round-trips
(`tests/crypto/test_round_trip.py`). The integration suite targets a **separate**
database (`DATABASE_URL_TEST`) and runs Alembic migrations programmatically; each
test runs in a transaction that is rolled back, so nothing persists between tests.

## Conventions & gotchas

- **SQLite fallback is deliberate.** Models use
  `UUID(as_uuid=True).with_variant(Uuid, "sqlite")` so the same schema runs on
  Postgres (prod) and SQLite (dev). Migration `001` inlines the same trick.
- **tz-aware datetimes via callables** — `default=utcnow` (a callable), never a
  frozen import-time `datetime.now(UTC)`. SQLite strips tzinfo on read-back;
  Postgres `TIMESTAMPTZ` round-trips.
- **`item_type` is DB-constrained** to `password` / `totp` / `note` via a
  `CheckConstraint`.
- **Cascade delete** — deleting a `User` removes their `VaultItem`s, enforced both
  by the ORM `delete-orphan` relationship and the DB-level `ON DELETE CASCADE`.
- **Alembic `env.py` overrides `sqlalchemy.url`** from `DATABASE_URL` at runtime,
  so the real URL is never committed in `alembic.ini`.

## Status

| Phase | State |
|-------|-------|
| Phase 1 — crypto (`kdf`, `kyber`, `symmetric`, `dilithium`) | ✅ Done, 17 unit tests |
| Phase 2 — DB models, session, migrations | ✅ Done, 3 integration tests |
| Phase 2 — API scaffold (FastAPI, routers) | 🟡 Stubs — `get_current_user` is a 501 placeholder, vault CRUD not implemented |
| CLI dev driver | ✅ Done |
| Phase 3 — audit/blockchain, ML-DSA signing, WebAuthn, JWT | ⬜ Not started |

### Known landmine (TODO)
`api/schemas.py:VaultItemResponse.encrypted_blob` is typed `str` (base64) but the
model column is `bytes`. `model_validate(orm, from_attributes=True)` does **not**
base64-encode — Pydantic UTF-8-decodes the bytes, which is wrong and crashes on
non-UTF-8 ciphertext. The vault `GET` handler must call
`base64.b64encode(item.encrypted_blob).decode()` explicitly.
