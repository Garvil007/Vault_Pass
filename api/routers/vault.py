"""Vault routes — CRUD over encrypted vault items.

Stub for now; real create/list/get/delete handlers land in later Phase 2 days
and operate only on opaque encrypted blobs (server never decrypts).
"""
from fastapi import APIRouter

router = APIRouter(prefix="/vault", tags=["vault"])


@router.get("/")
def vault_placeholder():
    return {"message": "coming soon"}
