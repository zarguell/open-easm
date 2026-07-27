from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from easm.api.deps import current_org_id, get_store
from easm.api.pagination import PaginatedResponse
from easm.store import Store

router = APIRouter(tags=["certificates"])


@router.get("/certificates/inventory")
async def list_certificate_inventory(
    target_id: str | None = Query(None),
    deployment_state: str | None = Query(None),
    risk: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    org_id_: str = Depends(lambda r: current_org_id(r)),
    store: Store = Depends(get_store),
):
    result = await store.list_certificate_inventory(
        target_id=target_id,
        deployment_state=deployment_state,
        risk=risk,
        limit=limit,
        offset=offset,
        org_id=org_id_,
    )
    return PaginatedResponse(
        items=result["certificates"],
        total=result["total_count"],
    )


@router.get("/certificates/summary")
async def summarize_certificate_inventory(
    target_id: str | None = Query(None),
    org_id_: str = Depends(lambda r: current_org_id(r)),
    store: Store = Depends(get_store),
):
    return await store.summarize_certificate_inventory(
        target_id=target_id, org_id=org_id_,
    )
