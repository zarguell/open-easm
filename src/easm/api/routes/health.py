from __future__ import annotations

import logging
import shutil
import subprocess

from fastapi import APIRouter

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


def check_binaries() -> dict:
    from easm.runtime import get_runtime

    runtime = get_runtime()
    results = {}
    for binary in ["subfinder", "asnmap", "dnstwist"]:
        if runtime.is_simulation or not runtime.config.allow_subprocess:
            results[binary] = {
                "path": None,
                "version": None,
                "ok": True,
                "mode": runtime.config.mode,
                "note": "binary probe skipped by runtime policy",
            }
            continue
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
    from easm.runtime import get_runtime

    store = None
    scheduler = None
    try:
        store = get_store()
        scheduler = get_scheduler()
    except RuntimeError:
        pass

    db_ok = False
    pivot_queue = {}
    if store:
        try:
            await store.pool.fetchval("SELECT 1")
            db_ok = True
            for status in ("pending", "running", "completed", "failed", "skipped_covered"):
                pivot_queue[status] = await store.count_pivot_jobs(status=status)
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
        "runtime": {
            "mode": get_runtime().config.mode,
            "fixtures_path": get_runtime().config.fixtures_path,
            "allow_external_network": get_runtime().config.allow_external_network,
            "allow_subprocess": get_runtime().config.allow_subprocess,
            "allow_active_scanning": get_runtime().config.allow_active_scanning,
        },
        "pivot_queue": pivot_queue,
        "binaries": binaries,
    }
