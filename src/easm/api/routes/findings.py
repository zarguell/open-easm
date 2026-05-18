from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from easm.api.deps import get_store
from easm.correlation.rule import VALID_FINDING_STATUSES
from easm.store import Store

router = APIRouter(tags=["findings"])


class PatchFindingRequest(BaseModel):
    status: str


@router.get("/findings/count")
async def count_findings(
    target_id: str | None = Query(None),
    risk: str | None = Query(None),
    status: str | None = Query(None),
    rule_id: str | None = Query(None),
    store: Store = Depends(get_store),
):
    count = await store.count_findings(
        target_id=target_id, risk=risk, status=status, rule_id=rule_id,
    )
    return {"count": count}


@router.get("/findings")
async def list_findings(
    target_id: str | None = Query(None),
    risk: str | None = Query(None),
    status: str | None = Query(None),
    rule_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    store: Store = Depends(get_store),
):
    results = await store.list_findings(
        target_id=target_id, risk=risk, status=status,
        rule_id=rule_id, limit=limit, offset=offset,
    )
    return {"findings": results}


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str, store: Store = Depends(get_store)):
    try:
        fid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail={"error": "invalid_id", "detail": "Invalid UUID format"}) from None
    result = await store.get_finding(fid)
    if result is None:
        raise HTTPException(status_code=404, detail={"error": "not_found", "detail": "Finding not found"}) from None
    return result


@router.patch("/findings/{finding_id}")
async def update_finding_status(
    finding_id: str,
    body: PatchFindingRequest,
    store: Store = Depends(get_store),
):
    if body.status not in VALID_FINDING_STATUSES:
        raise HTTPException(status_code=422, detail={
            "error": "invalid_status",
            "detail": f"Status must be one of: {', '.join(sorted(VALID_FINDING_STATUSES))}",
        })
    try:
        fid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail={"error": "invalid_id", "detail": "Invalid UUID format"}) from None
    existing = await store.get_finding(fid)
    if existing is None:
        raise HTTPException(status_code=404, detail={"error": "not_found", "detail": "Finding not found"}) from None
    await store.update_finding_status(fid, body.status)
    updated = await store.get_finding(fid)
    assert updated is not None
    return updated
