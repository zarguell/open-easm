from __future__ import annotations

import logging
import shutil
import subprocess
from datetime import UTC, datetime

from fastapi import APIRouter

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


def check_binaries() -> dict:
    from easm.runtime import get_runtime

    runtime = get_runtime()
    results = {}
    for binary in ["subfinder", "asnmap", "dnstwist", "webanalyze", "nuclei", "nmap"]:
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

    scheduler_ok = (
        scheduler.running if scheduler and hasattr(scheduler, "running") else False
    )

    return {
        "status": "ok",
        "version": "0.1.0",
        "database": "connected" if db_ok else "error",
        "scheduler": "running" if scheduler_ok else "stopped",
        "timestamp": datetime.now(UTC).isoformat(),
    }
