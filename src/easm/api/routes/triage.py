from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query

from easm.api.deps import get_store
from easm.store import Store

router = APIRouter(prefix="/api/triage", tags=["triage"])


@router.get("/inbox")
async def triage_inbox(
    org_id: str = Query(...),
    target_id: str | None = Query(None),
    entity_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    store: Store = Depends(get_store),
):
    rows = await store.get_triage_inbox(
        org_id=org_id, target_id=target_id, entity_type=entity_type,
        limit=limit, offset=offset,
    )
    total = rows[0]["total_count"] if rows else 0
    return {
        "items": [{k: v for k, v in r.items() if k != "total_count"} for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.patch("/{entity_id}/state")
async def set_triage_state(
    entity_id: uuid.UUID,
    org_id: str = Query(...),
    triage_state: str = Query(..., description="discovered | adopted | dismissed | active"),
    store: Store = Depends(get_store),
):
    ok = await store.set_entity_triage_state(org_id, entity_id, triage_state)
    if not ok:
        return {"ok": False, "error": "entity not found or invalid state"}
    return {"ok": True, "entity_id": str(entity_id), "triage_state": triage_state}


@router.post("/batch")
async def batch_set_triage_state(
    org_id: str = Query(...),
    triage_state: str = Query(...),
    entity_ids: list[uuid.UUID] = Query(...),
    store: Store = Depends(get_store),
):
    results = []
    for eid in entity_ids[:100]:
        ok = await store.set_entity_triage_state(org_id, eid, triage_state)
        results.append({"entity_id": str(eid), "ok": ok})
    return {"results": results}


@router.get("/active-targets")
async def list_active_targets(
    org_id: str = Query(...),
    target_id: str = Query(...),
    store: Store = Depends(get_store),
):
    targets = await store.get_active_scan_targets(org_id, target_id)
    return {"targets": targets, "count": len(targets)}
