from __future__ import annotations

import asyncio
import json
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from starlette.responses import StreamingResponse

from easm.api.deps import current_org_id, get_store
from easm.api.pagination import PaginatedResponse
from easm.api.sse import get_finding_stream
from easm.correlation.rule import VALID_FINDING_STATUSES
from easm.sla.models import compute_sla_status, compute_sla_summary
from easm.store import Store

logger = logging.getLogger(__name__)

router = APIRouter(tags=["findings"])


@router.get("/findings/rules")
async def list_finding_rules(store: Store = Depends(get_store)):
    """Return distinct rule IDs from the findings table."""
    return {"rules": await store.list_finding_rules()}


class PatchFindingRequest(BaseModel):
    status: str


@router.get("/findings/stream")
async def stream_findings(
    target_id: str | None = Query(None),
    risk: str | None = Query(None),
) -> StreamingResponse:
    """SSE endpoint for real-time finding notifications."""
    stream = get_finding_stream()
    queue = stream.subscribe()

    async def event_generator():
        try:
            while True:
                try:
                    finding = await asyncio.wait_for(queue.get(), timeout=30)
                    # Apply filters if specified
                    if target_id and finding.get("target_id") != target_id:
                        continue
                    if risk and finding.get("risk") != risk:
                        continue
                    data = json.dumps(finding, default=str)
                    yield f"data: {data}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            logger.debug("SSE findings stream cancelled by client")
        finally:
            stream.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


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
    q: str | None = Query(None),
    confidence_min: float | None = Query(None, description="Minimum confidence score (0-100)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    org_id_: str = Depends(lambda r: current_org_id(r)),
    store: Store = Depends(get_store),
):
    results = await store.list_findings(
        org_id=org_id_, target_id=target_id, risk=risk, status=status,
        rule_id=rule_id, q=q, confidence_min=confidence_min,
        limit=limit, offset=offset,
    )
    for f in results:
        f["sla"] = compute_sla_status(
            severity=f.get("risk", "info"),
            first_seen_at=f.get("first_seen_at"),
            finding_status=f.get("status", "open"),
        ).to_dict()
    total = await store.count_findings(
        target_id=target_id, risk=risk, status=status, rule_id=rule_id,
    )
    return PaginatedResponse(items=results, total=total)


@router.get("/findings/sla-summary")
async def sla_summary(
    target_id: str | None = Query(None),
    org_id_: str = Depends(lambda r: current_org_id(r)),
    store: Store = Depends(get_store),
):
    findings = await store.list_findings(
        org_id=org_id_, target_id=target_id, limit=5000,
    )
    return compute_sla_summary(findings)


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
