from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from easm.api.deps import get_store

router = APIRouter(prefix="/pivot-queue", tags=["pivot-queue"])


class TriggerPivotRequest(BaseModel):
    target_id: str
    entity_type: str
    entity_value: str
    pivot_type: str
    org_id: str = "default"
    depth: int = 1


@router.post("/trigger")
async def trigger_pivot(req: TriggerPivotRequest):
    """Manually enqueue a pivot job. The worker will pick it up on its next poll."""
    store = get_store()

    entity_row = await store.pool.fetchrow(
        "SELECT id FROM entities "
        "WHERE target_id = $1 AND entity_type = $2 AND entity_value = $3 "
        "LIMIT 1",
        req.target_id, req.entity_type, req.entity_value,
    )
    if not entity_row:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No entity found with type={req.entity_type} "
                f"value={req.entity_value} for target {req.target_id}"
            ),
        )
    entity_id = entity_row["id"]

    job_id = await store.enqueue_pivot_job(
        org_id=req.org_id,
        target_id=req.target_id,
        entity_type=req.entity_type,
        entity_value=req.entity_value,
        entity_id=entity_id,
        pivot_type=req.pivot_type,
        depth=req.depth,
    )
    return {"job_id": str(job_id), "status": "pending"}


@router.post("/{job_id}/retry")
async def retry_pivot(job_id: str):
    """Re-queue a failed or completed pivot job."""
    store = get_store()
    result = await store.pool.execute(
        "UPDATE pivot_queue SET status='pending', started_at=NULL, completed_at=NULL, "
        "error_message=NULL WHERE id = $1::uuid AND status IN ('failed', 'completed')",
        uuid.UUID(job_id),
    )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Job not found or not in a retryable state")
    return {"job_id": job_id, "status": "pending"}


@router.get("")
async def list_pivot_queue(
    status: str | None = Query(None),
    target_id: str | None = Query(None),
    entity_type: str | None = Query(None),
    pivot_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    cursor: str | None = Query(None),
):
    store = get_store()
    conditions: list[str] = []
    params: list[object] = []
    idx = 0

    if status:
        idx += 1
        conditions.append(f"status = ${idx}")
        params.append(status)
    if target_id:
        idx += 1
        conditions.append(f"target_id = ${idx}")
        params.append(target_id)
    if entity_type:
        idx += 1
        conditions.append(f"entity_type = ${idx}")
        params.append(entity_type)
    if pivot_type:
        idx += 1
        conditions.append(f"pivot_type = ${idx}")
        params.append(pivot_type)
    if cursor:
        idx += 1
        conditions.append(f"id < ${idx}::uuid")
        params.append(cursor)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    idx += 1
    query = f"""
        SELECT id, org_id, target_id, entity_type, entity_value, entity_id,
               pivot_type, depth, parent_entity_id, discovery_session_id,
               status, enqueued_at, started_at, completed_at, run_id,
               error_message, skip_reason
        FROM pivot_queue
        {where}
        ORDER BY enqueued_at DESC
        LIMIT ${idx}
    """
    params.append(limit + 1)

    rows = await store.pool.fetch(query, *params)
    has_more = len(rows) > limit
    results = rows[:limit]

    jobs = []
    for r in results:
        job = {
            "id": str(r["id"]),
            "org_id": r["org_id"],
            "target_id": r["target_id"],
            "entity_type": r["entity_type"],
            "entity_value": r["entity_value"],
            "entity_id": str(r["entity_id"]),
            "pivot_type": r["pivot_type"],
            "depth": r["depth"],
            "parent_entity_id": (
                str(r["parent_entity_id"]) if r["parent_entity_id"] else None
            ),
            "discovery_session_id": (
                str(r["discovery_session_id"]) if r["discovery_session_id"] else None
            ),
            "status": r["status"],
            "enqueued_at": r["enqueued_at"].isoformat(),
            "started_at": r["started_at"].isoformat() if r["started_at"] else None,
            "completed_at": r["completed_at"].isoformat() if r["completed_at"] else None,
            "run_id": str(r["run_id"]) if r["run_id"] else None,
            "error_message": r["error_message"],
            "skip_reason": r["skip_reason"],
        }
        jobs.append(job)

    next_cursor = str(results[-1]["id"]) if has_more and results else None
    return {"jobs": jobs, "next_cursor": next_cursor}
