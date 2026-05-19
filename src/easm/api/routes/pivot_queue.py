from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from easm.api.deps import get_store
from easm.tasks.pivot import execute_pivot

router = APIRouter(prefix="/pivot-queue", tags=["pivot-queue"])

_PIVOT_TASK = "easm.tasks.pivot.execute_pivot"

_STATUS_MAP = {
    "todo": "pending",
    "doing": "running",
    "succeeded": "completed",
    "failed": "failed",
}

_REVERSE_STATUS = {v: k for k, v in _STATUS_MAP.items()}


class TriggerPivotRequest(BaseModel):
    target_id: str
    entity_type: str
    entity_value: str
    pivot_type: str
    org_id: str = "default"
    depth: int = 1


@router.post("/trigger")
async def trigger_pivot(req: TriggerPivotRequest):
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
    entity_id = str(entity_row["id"])

    await execute_pivot.configure(queue="pivot").defer_async(
        org_id=req.org_id,
        target_id=req.target_id,
        entity_type=req.entity_type,
        entity_value=req.entity_value,
        entity_id=entity_id,
        pivot_type=req.pivot_type,
        depth=req.depth,
    )
    return {"status": "pending"}


@router.post("/{job_id}/retry")
async def retry_pivot(job_id: str):
    store = get_store()
    row = await store.pool.fetchrow(
        "SELECT args FROM procrastinate_jobs "
        "WHERE id = $1::bigint AND task_name = $2 AND status IN ('failed', 'succeeded')",
        int(job_id), _PIVOT_TASK,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Job not found or not in a retryable state")
    args = row["args"]
    await execute_pivot.configure(queue="pivot").defer_async(**args)
    return {"status": "pending"}


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
    conditions: list[str] = ["task_name = $1"]
    params: list[object] = [_PIVOT_TASK]
    idx = 1

    if status:
        proc_status = _REVERSE_STATUS.get(status, status)
        idx += 1
        conditions.append(f"status = ${idx}")
        params.append(proc_status)
    if target_id:
        idx += 1
        conditions.append(f"args->>'target_id' = ${idx}")
        params.append(target_id)
    if entity_type:
        idx += 1
        conditions.append(f"args->>'entity_type' = ${idx}")
        params.append(entity_type)
    if pivot_type:
        idx += 1
        conditions.append(f"args->>'pivot_type' = ${idx}")
        params.append(pivot_type)
    if cursor:
        idx += 1
        conditions.append(f"id < ${idx}::bigint")
        params.append(int(cursor))

    where = f"WHERE {' AND '.join(conditions)}"
    idx += 1
    query = f"""
        SELECT id, args->>'org_id' as org_id,
               args->>'target_id' as target_id,
               args->>'entity_type' as entity_type,
               args->>'entity_value' as entity_value,
               args->>'entity_id' as entity_id,
               args->>'pivot_type' as pivot_type,
               args->>'depth' as depth,
               status, scheduled_at, attempts
        FROM procrastinate_jobs
        {where}
        ORDER BY id DESC
        LIMIT ${idx}
    """
    params.append(limit + 1)

    rows = await store.pool.fetch(query, *params)
    has_more = len(rows) > limit
    results = rows[:limit]

    jobs = []
    for r in results:
        jobs.append({
            "id": str(r["id"]),
            "org_id": r["org_id"],
            "target_id": r["target_id"],
            "entity_type": r["entity_type"],
            "entity_value": r["entity_value"],
            "entity_id": r["entity_id"],
            "pivot_type": r["pivot_type"],
            "depth": int(r["depth"]) if r["depth"] else None,
            "status": _STATUS_MAP.get(r["status"], r["status"]),
            "enqueued_at": r["scheduled_at"].isoformat() if r["scheduled_at"] else None,
            "started_at": None,
            "completed_at": None,
            "error_message": None,
            "skip_reason": None,
        })

    next_cursor = str(results[-1]["id"]) if has_more and results else None
    return {"jobs": jobs, "next_cursor": next_cursor}


@router.get("/count")
async def count_pivot_queue(
    status: str | None = Query(None),
    target_id: str | None = Query(None),
    entity_type: str | None = Query(None),
    pivot_type: str | None = Query(None),
):
    store = get_store()
    conditions: list[str] = ["task_name = $1"]
    params: list[object] = [_PIVOT_TASK]
    idx = 1

    if status:
        proc_status = _REVERSE_STATUS.get(status, status)
        idx += 1
        conditions.append(f"status = ${idx}")
        params.append(proc_status)
    if target_id:
        idx += 1
        conditions.append(f"args->>'target_id' = ${idx}")
        params.append(target_id)
    if entity_type:
        idx += 1
        conditions.append(f"args->>'entity_type' = ${idx}")
        params.append(entity_type)
    if pivot_type:
        idx += 1
        conditions.append(f"args->>'pivot_type' = ${idx}")
        params.append(pivot_type)

    where = f"WHERE {' AND '.join(conditions)}"
    count = await store.pool.fetchval(
        f"SELECT COUNT(*) FROM procrastinate_jobs {where}", *params
    )
    return {"count": count}
