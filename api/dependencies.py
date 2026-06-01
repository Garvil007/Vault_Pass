"""Shared FastAPI dependencies.

Wires reusable pieces into route handlers via ``Depends``:
- ``get_db`` — per-request DB session, re-exported from ``db.session``.
- ``get_current_user`` — auth gate. Stubbed to 501 until JWT/WebAuthn lands (Day 3).
"""
from fastapi import Depends, HTTPException, status

# Re-export so routers depend on `api.dependencies.get_db`, not `db.session`
# directly — lets us swap the session source later without touching routers.
from db.session import get_db  # noqa: F401


def get_current_user(db=Depends(get_db)):
    """Resolve the authenticated user from the request.

    Not implemented yet — replaced on Day 3 with JWT decode + DB lookup.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Authentication not implemented yet",
    )
