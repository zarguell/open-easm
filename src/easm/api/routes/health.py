from __future__ import annotations

from fastapi import APIRouter

from easm.api.deps import get_scheduler, get_store
from easm.api.schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthResponse)
async def healthz():
    store = get_store()
    scheduler = get_scheduler()

    try:
        async with store.pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        db_status = "ok"
    except Exception:
        db_status = "error"

    scheduler_status = "running" if scheduler.running else "stopped"
    overall = "ok" if db_status == "ok" else "degraded"
    return HealthResponse(
        status=overall,
        database=db_status,
        scheduler=scheduler_status,
        config_loaded=True,
    )
