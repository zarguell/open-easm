"""Domain verification API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from easm.api.deps import get_store
from easm.validators import normalize_domain
from easm.verification.dns_verification import (
    start_verification,
    check_verification,
    get_domain_status,
    list_verified_domains,
    delete_verification,
)

router = APIRouter(prefix="/domains", tags=["verification"])


class VerificationStartRequest(BaseModel):
    domain: str = Field(..., description="Domain to verify, e.g. example.com")


@router.post("/verification/start")
async def api_start_verification(payload: VerificationStartRequest):
    try:
        domain = normalize_domain(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    store = get_store()
    return await start_verification(store.pool, domain)


@router.post("/{domain}/verification/check")
async def api_check_verification(domain: str):
    try:
        normalized = normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    store = get_store()
    result = await check_verification(store.pool, normalized)
    if not result:
        raise HTTPException(status_code=404, detail="No verification started for this domain.")
    return result


@router.get("/verified")
async def api_list_verified():
    store = get_store()
    return await list_verified_domains(store.pool)


@router.get("/{domain}/verification")
async def api_get_verification(domain: str):
    try:
        normalized = normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    store = get_store()
    return await get_domain_status(store.pool, normalized)


@router.delete("/{domain}/verification")
async def api_delete_verification(domain: str):
    try:
        normalized = normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    store = get_store()
    deleted = await delete_verification(store.pool, normalized)
    return {"domain": normalized, "deleted": deleted}
