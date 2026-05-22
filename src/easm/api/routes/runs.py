from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query

from easm.api.deps import get_config, get_store
from easm.api.schemas import RunDetail, RunSummary, RunTriggerResponse

router = APIRouter(prefix="/runs", tags=["runs"])

ACTIVE_RUNNERS = {"nuclei", "portscan", "screenshot", "wappalyzer"}


@router.get("/count")
async def count_runs(
    target_id: str | None = None,
    source: str | None = None,
    status: str | None = None,
    trigger_type: str | None = None,
    start: str | None = None,
    end: str | None = None,
):
    store = get_store()
    start_dt = datetime.fromisoformat(start) if start else None
    end_dt = datetime.fromisoformat(end) if end else None
    count = await store.count_runs(
        target_id=target_id, source=source, status=status,
        trigger_type=trigger_type, start=start_dt, end=end_dt,
    )
    return {"count": count}


@router.get("", response_model=list[RunSummary])
async def list_runs(
    target_id: str | None = None,
    source: str | None = None,
    status: str | None = None,
    trigger_type: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[RunSummary]:
    store = get_store()
    start_dt = datetime.fromisoformat(start) if start else None
    end_dt = datetime.fromisoformat(end) if end else None
    runs = await store.list_runs(
        target_id=target_id, source=source, status=status,
        trigger_type=trigger_type, start=start_dt, end=end_dt,
        limit=limit, offset=offset,
    )
    return [RunSummary(**r) for r in runs]


@router.get("/{run_id}", response_model=RunDetail)
async def get_run(run_id: str) -> RunDetail:
    store = get_store()
    try:
        uid = uuid.UUID(run_id)
    except ValueError:
        raise HTTPException(
            status_code=400, detail={"error": "invalid_id", "detail": "Invalid run ID format"}
        ) from None
    run = await store.get_run(uid)
    if run is None:
        raise HTTPException(
            status_code=404, detail={"error": "not_found", "detail": "Run not found"}
        )
    return RunDetail(**run)


@router.post("/{target_id}/{runner}", response_model=RunTriggerResponse)
async def trigger_run(target_id: str, runner: str) -> RunTriggerResponse:
    config = get_config()
    store = get_store()

    target = next((t for t in config.targets if t.id == target_id), None)
    if target is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "not_found", "detail": f"Target '{target_id}' not found"},
        )
    if not target.enabled:
        raise HTTPException(
            status_code=400, detail={"error": "disabled", "detail": "Target is disabled"}
        )

    runner_cfg = target.runners.get(runner)
    if runner_cfg is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "unknown_runner",
                "detail": f"Runner '{runner}' not configured for target",
            },
        )
    cfg_dict = runner_cfg.model_dump()
    if not cfg_dict.get("enabled", False):
        raise HTTPException(
            status_code=400,
            detail={"error": "disabled", "detail": f"Runner '{runner}' is disabled for target"},
        )

    from easm.runners import get_all_runners
    from easm.runtime import get_runtime
    from easm.tasks.runner import execute_runner as defer_runner

    runners = get_all_runners()
    runner_def = runners.get(runner)
    if runner_def is None or not runner_def.supports_manual_trigger:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "not_supported",
                "detail": f"Runner '{runner}' does not support manual trigger",
            },
        )

    runtime = get_runtime()
    if not runtime.config.allow_active_scanning and runner in ACTIVE_RUNNERS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "active_scanning_disabled",
                "detail": f"Runner '{runner}' is disabled by runtime policy",
            },
        )

    await defer_runner.configure(
        priority=1,
    ).defer_async(
        runner_name=runner,
        target_id=target.id,
        trigger_type="manual",
        org_id=getattr(target, "org_id", "default"),
    )
    return RunTriggerResponse(
        status="accepted",
        message=f"Manual run deferred for {runner} on target {target_id}",
    )
