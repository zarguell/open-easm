from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from easm.api.deps import get_store
from easm.store import Store

router = APIRouter(tags=["certificates"])


@router.get("/certificates/inventory")
async def list_certificate_inventory(
    target_id: str | None = Query(None),
    deployment_state: str | None = Query(None),
    risk: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    store: Store = Depends(get_store),
):
    certificates = await store.list_certificate_inventory(
        target_id=target_id,
        deployment_state=deployment_state,
        risk=risk,
        limit=limit,
        offset=offset,
    )
    return {"certificates": certificates}


@router.get("/certificates/summary")
async def summarize_certificate_inventory(
    target_id: str | None = Query(None),
    store: Store = Depends(get_store),
):
    return await store.summarize_certificate_inventory(target_id=target_id)
