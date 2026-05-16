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
from easm.config import load_config
from easm.db import close_pool, create_pool
from easm.runners import RUNNER_REGISTRY
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
    level=logging.INFO, format="%(message)s", handlers=[logging.StreamHandler(sys.stdout)]
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

    pdcp_key = os.environ.get("PDCP_API_KEY")
    if pdcp_key:
        provider_dir = Path.home() / ".config" / "subfinder"
        provider_dir.mkdir(parents=True, exist_ok=True)
        config_file = provider_dir / "provider-config.yaml"
        config_file.write_text(f"asnmap:\n  - key: \"{pdcp_key}\"\n")
        logger.info("wrote PDCP provider config")

    logger.info("creating database pool")
    pool = await create_pool(dsn)

    logger.info("applying database migrations")
    alembic_cfg = AlembicConfig("alembic.ini")
    async_dsn = dsn.replace("postgresql://", "postgresql+asyncpg://")
    alembic_cfg.set_main_option("sqlalchemy.url", async_dsn)
    from concurrent.futures import ThreadPoolExecutor
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor() as executor:
        await loop.run_in_executor(executor, alembic_upgrade, alembic_cfg, "head")

    store = Store(pool)
    await store.save_config_snapshot(config.model_dump())

    scheduler = Scheduler()
    for name, cls in RUNNER_REGISTRY.items():
        scheduler.register_runner(name, cls)

    set_config(config)
    set_store(store)
    set_scheduler(scheduler)

    scheduler.setup_jobs(config, store)
    scheduler.start()

    app = create_app()

    for target in config.targets:
        runner_raw = target.runners.get("certstream")
        if runner_raw:
            cfg_dict = runner_raw if isinstance(runner_raw, dict) else runner_raw.model_dump()
            if cfg_dict.get("enabled", False):
                certstream_runner_cls = RUNNER_REGISTRY["certstream"]
                cert_runner = certstream_runner_cls(store)  # type: ignore[abstract]
                asyncio.create_task(
                    cert_runner.execute(target, "stream"),
                    name=f"certstream-{target.id}",
                )
                logger.info("started certstream", target_id=target.id)

    import uvicorn
    uvicorn_cfg = uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="info")
    server = uvicorn.Server(uvicorn_cfg)
    try:
        await server.serve()
    finally:
        await scheduler.shutdown()
        await close_pool(pool)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("received interrupt, shutting down")
