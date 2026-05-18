from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse

from easm.api.deps import get_store
from easm.assets.export import assets_to_ndjson
from easm.store import Store

router = APIRouter(tags=["assets"])


@router.get("/assets/inventory")
async def list_asset_inventory(
    target_id: str | None = Query(None),
    confidence_level: str | None = Query(None),
    risk_level: str | None = Query(None),
    feed_eligible: bool | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    store: Store = Depends(get_store),
):
    assets = await store.list_asset_inventory(
        target_id=target_id,
        confidence_level=confidence_level,
        risk_level=risk_level,
        feed_eligible=feed_eligible,
        limit=limit,
        offset=offset,
        org_id="default",
    )
    return {"assets": assets}


@router.get("/assets/changes")
async def list_asset_changes(
    target_id: str | None = Query(None),
    entity_id: uuid.UUID | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    store: Store = Depends(get_store),
):
    changes = await store.list_asset_change_events(
        target_id=target_id,
        entity_id=entity_id,
        org_id="default",
        limit=limit,
        offset=offset,
    )
    return {"changes": changes}


@router.get("/assets/export.ndjson")
async def export_assets_ndjson(
    target_id: str | None = Query(None),
    store: Store = Depends(get_store),
):
    assets = await store.list_asset_inventory(
        target_id=target_id,
        feed_eligible=True,
        limit=500,
        offset=0,
        org_id="default",
    )
    return PlainTextResponse(
        assets_to_ndjson(assets),
        media_type="application/x-ndjson",
    )
