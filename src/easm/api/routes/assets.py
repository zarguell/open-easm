from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, Query
from starlette.responses import StreamingResponse

from easm.api.deps import current_org_id, get_store
from easm.api.pagination import PaginatedResponse
from easm.assets.export import asset_to_source_of_truth_record
from easm.store import Store

router = APIRouter(tags=["assets"])


@router.get("/assets/inventory")
async def list_asset_inventory(
    target_id: str | None = Query(None),
    confidence_level: str | None = Query(None),
    risk_level: str | None = Query(None),
    feed_eligible: bool | None = Query(None),
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    org_id_: str = Depends(lambda r: current_org_id(r)),
    store: Store = Depends(get_store),
):
    result = await store.list_asset_inventory(
        target_id=target_id,
        confidence_level=confidence_level,
        risk_level=risk_level,
        feed_eligible=feed_eligible,
        limit=limit,
        offset=offset,
        org_id=org_id_,
    )
    return PaginatedResponse(
        items=result["entities"],
        total=result["total_count"],
    )


@router.get("/assets/changes")
async def list_asset_changes(
    target_id: str | None = Query(None),
    entity_id: uuid.UUID | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    org_id_: str = Depends(lambda r: current_org_id(r)),
    store: Store = Depends(get_store),
):
    changes = await store.list_asset_change_events(
        target_id=target_id,
        entity_id=entity_id,
        org_id=org_id_,
        limit=limit,
        offset=offset,
    )
    return {"changes": changes}


@router.get("/assets/export.ndjson")
async def export_assets_ndjson(
    target_id: str | None = Query(None),
    org_id_: str = Depends(lambda r: current_org_id(r)),
    store: Store = Depends(get_store),
):
    async def generate():
        offset = 0
        batch_size = 1000
        while True:
            result = await store.list_asset_inventory(
                target_id=target_id,
                feed_eligible=True,
                limit=batch_size,
                offset=offset,
                org_id=org_id_,
            )
            entities = result["entities"]
            if not entities:
                break
            for asset in entities:
                yield json.dumps(asset_to_source_of_truth_record(asset), default=str) + "\n"
            if len(entities) < batch_size:
                break
            offset += batch_size

    return StreamingResponse(
        generate(),
        media_type="application/x-ndjson",
    )
