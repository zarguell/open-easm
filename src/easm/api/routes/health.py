from __future__ import annotations

import logging
import shutil
import subprocess

from fastapi import APIRouter

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


def check_binaries() -> dict:
    results = {}
    for binary in ["subfinder", "asnmap", "dnstwist"]:
        path = shutil.which(binary)
        if path:
            try:
                version = subprocess.run(
                    [binary, "--version"], capture_output=True, text=True, timeout=5
                )
                version_str = version.stdout.strip() or version.stderr.strip() or None
            except Exception:
                version_str = None
            results[binary] = {"path": path, "version": version_str, "ok": True}
        else:
            results[binary] = {"path": None, "version": None, "ok": False, "error": "not found on PATH"}
    return results


@router.get("/healthz")
async def healthz():
    from easm.api.deps import get_store, get_scheduler

    store = None
    scheduler = None
    try:
        store = get_store()
        scheduler = get_scheduler()
    except RuntimeError:
        pass

    db_ok = False
    if store:
        try:
            await store.pool.fetchval("SELECT 1")
            db_ok = True
        except Exception:
            db_ok = False

    sched_ok = scheduler.running if scheduler and hasattr(scheduler, "running") else False
    binaries = check_binaries()
    all_ok = db_ok and sched_ok and all(b["ok"] for b in binaries.values())

    return {
        "status": "ok" if all_ok else "degraded",
        "database": "connected" if db_ok else "disconnected",
        "scheduler": "running" if sched_ok else "stopped",
        "config_loaded": True,
        "binaries": binaries,
    }
