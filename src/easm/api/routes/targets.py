from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from easm.api.deps import get_config, get_store
from easm.api.schemas import TargetDetail, TargetSummary

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("", response_model=list[TargetSummary])
async def list_targets() -> list[TargetSummary]:
    config = get_config()
    store = get_store()
    results: list[TargetSummary] = []
    for target in config.targets:
        runner_info: dict[str, Any] = {}
        for name, cfg in target.runners.items():
            cfg_dict = cfg.model_dump()
            info: dict[str, Any] = {
                "enabled": cfg_dict.get("enabled", False),
                "schedule": cfg_dict.get("schedule"),
            }
            last_runs = await store.list_runs(target_id=target.id, source=name, limit=1)
            if last_runs:
                info["last_run_id"] = last_runs[0]["id"]
                info["last_run_status"] = last_runs[0]["status"]
            runner_info[name] = info
        results.append(
            TargetSummary(
                id=target.id,
                name=target.name,
                type=target.type,
                enabled=target.enabled,
                labels=target.labels,
                runners=runner_info,
            )
        )
    return results


@router.get("/{target_id}", response_model=TargetDetail)
async def get_target(target_id: str) -> TargetDetail:
    config = get_config()
    for target in config.targets:
        if target.id == target_id:
            match_rules = target.match_rules.model_dump()
            runners = {}
            for name, cfg in target.runners.items():
                runners[name] = cfg.model_dump()
            return TargetDetail(
                id=target.id,
                name=target.name,
                type=target.type,
                enabled=target.enabled,
                labels=target.labels,
                match_rules=match_rules,
                runners=runners,
            )
    raise HTTPException(
        status_code=404,
        detail={"error": "not_found", "detail": f"Target '{target_id}' not found"},
    )
