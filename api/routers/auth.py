"""Authentication routes — WebAuthn registration/login + token issuance.

Stub for now; real WebAuthn + Kyber session handshake lands in later Phase 2 days.
"""
from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/")
def auth_placeholder():
    return {"message": "coming soon"}
