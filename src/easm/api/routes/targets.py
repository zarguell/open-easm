from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from easm.api.deps import get_config
from easm.api.schemas import TargetSummary, TargetDetail

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("", response_model=list[TargetSummary])
async def list_targets():
    config = get_config()
    results: list[TargetSummary] = []
    for target in config.targets:
        runner_info: dict[str, Any] = {}
        for name, cfg in target.runners.items():
            cfg_dict = cfg if isinstance(cfg, dict) else cfg.model_dump()
            runner_info[name] = {
                "enabled": cfg_dict.get("enabled", False),
                "schedule": cfg_dict.get("schedule"),
            }
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
async def get_target(target_id: str):
    config = get_config()
    for target in config.targets:
        if target.id == target_id:
            match_rules = target.match_rules.model_dump() if hasattr(target.match_rules, "model_dump") else {}
            runners = {}
            for name, cfg in target.runners.items():
                runners[name] = cfg.model_dump() if hasattr(cfg, "model_dump") else cfg
            return TargetDetail(
                id=target.id,
                name=target.name,
                type=target.type,
                enabled=target.enabled,
                labels=target.labels,
                match_rules=match_rules,
                runners=runners,
            )
    raise HTTPException(status_code=404, detail={"error": "not_found", "detail": f"Target '{target_id}' not found"})
