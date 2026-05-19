from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

import structlog
from alembic.command import upgrade as alembic_upgrade
from alembic.config import Config as AlembicConfig

from easm.api.app import create_app
from easm.api.deps import set_config, set_scheduler, set_store
from easm.api.routes.health import check_binaries
from easm.config import load_config
from easm.db import close_pool, create_pool
from easm.queue import app as procrastinate_app
from easm.runtime import configure_runtime
from easm.scheduler import Scheduler
from easm.store import Store

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
    force=True,
)

logger = structlog.get_logger(__name__)


async def main() -> None:
    config_path = os.environ.get("EASM_CONFIG_PATH", "/app/config.yaml")
    dsn = os.environ.get("EASM_DATABASE_DSN", "postgresql://easm:easm@postgres:5432/easm")

    logger.info("loading config", path=config_path)
    try:
        config = load_config(config_path)
    except Exception as e:
        logger.error("failed to load config", path=config_path, error=str(e))
        sys.exit(1)

    configure_runtime(config.runtime)
    logger.info(
        "configured runtime",
        mode=config.runtime.mode,
        fixtures_path=config.runtime.fixtures_path,
        allow_external_network=config.runtime.allow_external_network,
        allow_subprocess=config.runtime.allow_subprocess,
        allow_active_scanning=config.runtime.allow_active_scanning,
    )

    pdcp_key = os.environ.get("PDCP_API_KEY")
    if pdcp_key:
        provider_dir = Path.home() / ".config" / "subfinder"
        provider_dir.mkdir(parents=True, exist_ok=True)
        config_file = provider_dir / "provider-config.yaml"
        config_file.write_text(f"asnmap:\n  - key: \"{pdcp_key}\"\n")
        logger.info("wrote PDCP provider config")

    logger.info("creating database pool")
    pool = await create_pool(dsn)

    logger.info("waiting for database to be ready")
    for attempt in range(30):
        try:
            await pool.fetchval("SELECT 1")
            logger.info("database is ready")
            break
        except Exception as e:
            if attempt == 29:
                logger.error("database not ready after 30 attempts", error=str(e))
                raise
            logger.warning("database not ready, retrying", attempt=attempt + 1, error=str(e))
            await asyncio.sleep(2)

    logger.info("applying database migrations")
    alembic_cfg = AlembicConfig("alembic.ini")
    async_dsn = dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    alembic_cfg.set_main_option("sqlalchemy.url", async_dsn)
    from concurrent.futures import ThreadPoolExecutor
    loop = asyncio.get_running_loop()
    try:
        with ThreadPoolExecutor() as executor:
            await loop.run_in_executor(executor, alembic_upgrade, alembic_cfg, "head")
        logger.info("database migrations applied successfully")
    except Exception as e:
        logger.exception("migration failed", error=str(e))
        raise

    store = Store(pool)
    await store.save_config_snapshot(config.model_dump())

    binaries = check_binaries()
    for name, info in binaries.items():
        if info["ok"]:
            logger.info("binary found", extra={"name": name, "path": info["path"], "version": info.get("version")})
        else:
            logger.warning("binary not found", extra={"name": name, "error": info.get("error")})

    scheduler = Scheduler()

    set_config(config)
    set_store(store)
    set_scheduler(scheduler)

    await procrastinate_app.open_async()

    scheduler.setup_jobs(config, store)
    scheduler.start()
    scheduler.setup_janitor(store)

    mode = os.environ.get("EASM_MODE", "all")

    if config.runtime.mode == "simulate" or not config.runtime.refresh_kev_on_startup:
        logger.info(
            "skipping kev refresh",
            mode=config.runtime.mode,
            refresh_kev_on_startup=config.runtime.refresh_kev_on_startup,
        )
    else:
        from easm.vuln_cache import refresh_kev_cache
        try:
            kev_count = await asyncio.wait_for(refresh_kev_cache(pool), timeout=30)
            logger.info("initial kev cache populated", count=kev_count)
        except Exception:
            logger.exception("initial kev cache population failed (non-fatal)")

        scheduler.setup_kev_refresh(pool)

    app = create_app()

    if mode != "web":
        for target in config.targets:
            runner_cfg = target.runners.get("certstream")
            if runner_cfg and runner_cfg.enabled:
                if config.runtime.mode == "simulate" or not config.runtime.allow_external_network:
                    logger.info(
                        "skipping certstream due to runtime policy",
                        target_id=target.id,
                        mode=config.runtime.mode,
                        allow_external_network=config.runtime.allow_external_network,
                    )
                    continue
                from easm.runners import get_all_runners
                from easm.runners.engine import execute_runner
                cert_def = get_all_runners()["certstream"]
                asyncio.create_task(
                    execute_runner("certstream", cert_def.run_fn, target, store, "stream"),
                    name=f"certstream-{target.id}",
                )
                logger.info("started certstream", target_id=target.id)

    else:
        logger.info("running in web-only mode, workers run separately")

    import uvicorn
    uvicorn_cfg = uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="info")
    server = uvicorn.Server(uvicorn_cfg)

    async def monitor_background_tasks():
        while True:
            try:
                await asyncio.sleep(60)
                logger.debug("heartbeat: background tasks running")
            except asyncio.CancelledError:
                logger.info("background task monitor cancelled")
                break

    async def health_check_and_restart():
        import httpx

        while True:
            await asyncio.sleep(30)
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get("http://localhost:8000/api/healthz")
                    if resp.status_code != 200:
                        logger.warning("health check returned non-200", status=resp.status_code)
                    else:
                        logger.debug("health check OK")
            except httpx.TimeoutException:
                logger.warning("health check timeout - server unresponsive, will restart")
                os._exit(1)
            except httpx.ConnectError:
                logger.warning("health check connection failed - server down, will restart")
                os._exit(1)
            except Exception as e:
                logger.warning("health check error", error=str(e))

    monitor_task = asyncio.create_task(monitor_background_tasks())
    health_task = asyncio.create_task(health_check_and_restart())

    try:
        await server.serve()
    except Exception as e:
        logger.exception("server crashed", error=str(e))
    finally:
        logger.info("shutting down services")
        monitor_task.cancel()
        health_task.cancel()
        await procrastinate_app.close_async()
        await scheduler.shutdown()
        await close_pool(pool)
        logger.info("shutdown complete")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("received interrupt, shutting down")
    except Exception as e:
        logger.exception("fatal error", error=str(e))
        sys.exit(1)
