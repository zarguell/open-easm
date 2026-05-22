"""Legal disclaimer and acceptance API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from pydantic import BaseModel, Field

from easm.api.deps import get_store
from easm.legal.acceptance import create_acceptance, validate_acceptance
from easm.legal.terms import legal_payload

router = APIRouter(prefix="/legal", tags=["legal"])


class LegalAcceptRequest(BaseModel):
    accepted: bool = Field(False, description="Confirms acceptance of the terms.")
    terms_hash: str | None = Field(None, description="SHA-256 hash of the displayed terms text.")


@router.get("/terms")
async def api_legal_terms():
    """Return the current legal disclaimer text, version, and hash."""
    return legal_payload()


@router.post("/accept")
async def api_accept_terms(payload: LegalAcceptRequest, request: Request):
    """Record acceptance of the legal terms. Returns a token for subsequent requests."""
    store = get_store()
    client_host = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    try:
        return await create_acceptance(
            store.pool,
            client_ip=client_host,
            user_agent=user_agent,
            accepted=payload.accepted,
            supplied_hash=payload.terms_hash,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/status")
async def api_legal_status(token: str | None = None):
    """Validate a legal acceptance token."""
    store = get_store()
    return await validate_acceptance(store.pool, token)
