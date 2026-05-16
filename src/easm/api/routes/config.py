from __future__ import annotations

import logging

import yaml
from fastapi import APIRouter, Depends

from easm.api.deps import get_config, get_scheduler, get_store, set_config
from easm.config import Config, load_config
from easm.runners import RUNNER_REGISTRY
from easm.scheduler import Scheduler
from easm.store import Store

logger = logging.getLogger(__name__)

router = APIRouter(tags=["config"])


@router.post("/config/reload")
async def reload_config(
    config: Config = Depends(get_config),
    scheduler: Scheduler = Depends(get_scheduler),
    store: Store = Depends(get_store),
):
    # Reload and re-validate config
    new_config = load_config("config.yaml")

    # Diff targets
    old_ids = {t.id for t in config.targets}
    new_ids = {t.id for t in new_config.targets}
    added = new_ids - old_ids
    removed = old_ids - new_ids

    # Remove deleted targets
    for target_id in removed:
        scheduler.remove_jobs_for_target(target_id)

    # Add new targets
    for target in new_config.targets:
        if target.id in added:
            scheduler.add_jobs_for_target(target, RUNNER_REGISTRY, store)

    # Persist config snapshot
    raw = yaml.safe_load(open("config.yaml"))
    await store.save_config_snapshot(raw)

    # Update in-memory config
    set_config(new_config)

    return {"status": "ok", "added": list(added), "removed": list(removed), "modified": []}
