from __future__ import annotations

import logging
import os
from pathlib import Path

import yaml
from fastapi import APIRouter, Depends, HTTPException

from easm.api.deps import get_config, get_scheduler, get_store, set_config
from easm.api.schemas import ConfigSnapshot
from easm.config import Config, load_config
from easm.scheduler import Scheduler
from easm.store import Store

logger = logging.getLogger(__name__)

router = APIRouter(tags=["config"])


@router.get("/config", response_model=dict)
async def get_full_config(config: Config = Depends(get_config)):
    return config.model_dump(mode="json")


@router.put("/config")
async def update_config(
    body: dict,
    config: Config = Depends(get_config),
    store: Store = Depends(get_store),
):
    current = config.model_dump()
    for key in ("targets", "saas_providers", "alerts"):
        if key in body:
            current[key] = body[key]

    try:
        new_config = Config.model_validate(current)
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail={"error": "validation", "detail": str(e)},
        ) from None

    config_path = os.environ.get("EASM_CONFIG_PATH", "config.yaml")
    yaml_text = yaml.dump(current, allow_unicode=True, sort_keys=False)
    Path(config_path).write_text(yaml_text)

    await store.save_config_snapshot(current)

    set_config(new_config)

    return {"status": "ok", "message": "config updated and validated"}


@router.get("/config/history", response_model=list[ConfigSnapshot])
async def config_history(store: Store = Depends(get_store)):
    rows = await store.pool.fetch(
        "SELECT id, snapshot->'targets' AS targets, created_at "
        "FROM config_snapshots ORDER BY created_at DESC LIMIT 20"
    )
    return [
        ConfigSnapshot(
            id=str(r["id"]),
            target_count=len(r["targets"] or []),
            created_at=r["created_at"].isoformat(),
        )
        for r in rows
    ]


@router.post("/config/reload")
async def reload_config(
    config: Config = Depends(get_config),
    scheduler: Scheduler = Depends(get_scheduler),
    store: Store = Depends(get_store),
):
    new_config = load_config("config.yaml")

    old_ids = {t.id for t in config.targets}
    new_ids = {t.id for t in new_config.targets}
    added = new_ids - old_ids
    removed = old_ids - new_ids

    for target_id in removed:
        scheduler.remove_jobs_for_target(target_id)

    for target in new_config.targets:
        if target.id in added:
            scheduler.add_jobs_for_target(target, store=store)

    raw = yaml.safe_load(open("config.yaml"))
    await store.save_config_snapshot(raw)

    set_config(new_config)

    return {"status": "ok", "added": list(added), "removed": list(removed), "modified": []}
