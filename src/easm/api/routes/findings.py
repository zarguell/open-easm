from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from easm.api.deps import get_store
from easm.correlation.findings_store import FindingsStore
from easm.correlation.rule import VALID_FINDING_STATUSES
from easm.store import Store

router = APIRouter(tags=["findings"])


class PatchFindingRequest(BaseModel):
    status: str


def _get_findings_store(store: Store = Depends(get_store)) -> FindingsStore:
    return FindingsStore(store.pool)


@router.get("/findings")
async def list_findings(
    target_id: str | None = Query(None),
    risk: str | None = Query(None),
    status: str | None = Query(None),
    rule_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    findings_store: FindingsStore = Depends(_get_findings_store),
):
    results = await findings_store.list_findings(
        target_id=target_id,
        risk=risk,
        status=status,
        rule_id=rule_id,
        limit=limit,
        offset=offset,
    )
    return {"findings": results}


@router.get("/findings/{finding_id}")
async def get_finding(
    finding_id: str,
    findings_store: FindingsStore = Depends(_get_findings_store),
):
    try:
        fid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail={"error": "invalid_id", "detail": "Invalid UUID format"})

    result = await findings_store.get_finding(fid)
    if result is None:
        raise HTTPException(status_code=404, detail={"error": "not_found", "detail": "Finding not found"})
    return result


@router.patch("/findings/{finding_id}")
async def update_finding_status(
    finding_id: str,
    body: PatchFindingRequest,
    findings_store: FindingsStore = Depends(_get_findings_store),
):
    if body.status not in VALID_FINDING_STATUSES:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_status",
                "detail": f"Status must be one of: {', '.join(sorted(VALID_FINDING_STATUSES))}",
            },
        )

    try:
        fid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail={"error": "invalid_id", "detail": "Invalid UUID format"})

    existing = await findings_store.get_finding(fid)
    if existing is None:
        raise HTTPException(status_code=404, detail={"error": "not_found", "detail": "Finding not found"})

    await findings_store.update_finding_status(fid, body.status)
    updated = await findings_store.get_finding(fid)
    assert updated is not None
    return updated
