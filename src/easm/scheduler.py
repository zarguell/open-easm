from __future__ import annotations

import logging
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


class Scheduler:
    def __init__(self) -> None:
        self._scheduler = AsyncIOScheduler()

    def _schedule_runner(
        self,
        target: Any,
        runner_name: str,
        runner_def: Any,  # RunnerDef
        cfg_dict: dict[str, Any],
        store: Any,
    ) -> None:
        """Schedule a single runner for a target. Shared by setup_jobs and add_jobs_for_target."""
        if not runner_def.supports_schedule:
            return
        schedule = cfg_dict.get("schedule", "0 0 * * *")
        job_id = f"{target.id}-{runner_name}"
        if self._scheduler.get_job(job_id) is not None:
            return

        from easm.runners.engine import execute_runner
        import httpx

        async def _run_job():
            active = await store.count_active_runs(target.id, runner_def.source_name)
            if active > 0:
                logger.info(
                    "skipping scheduled run: previous run still active",
                    extra={"target_id": target.id, "runner": runner_name, "active_runs": active},
                )
                return

            http_client = httpx.AsyncClient(timeout=30.0)
            try:
                await execute_runner(
                    runner_def.source_name,
                    runner_def.run_fn,
                    target,
                    store,
                    "scheduled",
                    http_client=http_client,
                )
            finally:
                await http_client.aclose()

        self._scheduler.add_job(
            _run_job,
            "cron",
            id=job_id,
            **self._parse_cron(schedule),
            replace_existing=True,
        )
        logger.info(
            "scheduled job",
            extra={"job_id": job_id, "schedule": schedule, "target_id": target.id},
        )

    def setup_jobs(self, config: Any, store: Any) -> None:
        from easm.runners import get_all_runners
        runners = get_all_runners()

        for target in config.targets:
            if not target.enabled:
                continue
            for runner_name, runner_cfg in target.runners.items():
                cfg_dict = runner_cfg.model_dump()
                if not cfg_dict.get("enabled", False):
                    continue
                if runner_name not in runners:
                    logger.warning("unknown runner %s for target %s", runner_name, target.id)
                    continue
                self._schedule_runner(target, runner_name, runners[runner_name], cfg_dict, store)

    def add_jobs_for_target(self, target: Any, _registry: Any = None, store: Any = None) -> None:
        from easm.runners import get_all_runners
        runners = get_all_runners()

        for runner_name, runner_cfg in target.runners.items():
            cfg_dict = runner_cfg.model_dump()
            if not cfg_dict.get("enabled", False):
                continue
            if runner_name not in runners:
                logger.warning("unknown runner %s for target %s", runner_name, target.id)
                continue
            self._schedule_runner(target, runner_name, runners[runner_name], cfg_dict, store)

    def setup_kev_refresh(self, pool: Any) -> None:
        from easm.vuln_cache import refresh_kev_cache

        async def _refresh() -> None:
            try:
                await refresh_kev_cache(pool)
            except Exception:
                logger.exception("kev refresh failed")

        self._scheduler.add_job(
            _refresh,
            "cron",
            id="kev-refresh",
            day_of_week="0",
            hour="3",
            minute="0",
            replace_existing=True,
        )
        logger.info("scheduled kev refresh job")

    def _parse_cron(self, schedule: str) -> dict[str, str]:
        parts = schedule.split()
        if len(parts) != 5:
            raise ValueError(f"Invalid cron expression: {schedule}")
        return {
            "minute": parts[0],
            "hour": parts[1],
            "day": parts[2],
            "month": parts[3],
            "day_of_week": parts[4],
        }

    def start(self) -> None:
        if not self._scheduler.running:
            self._scheduler.start()
            logger.info("scheduler started")

    async def shutdown(self, wait: bool = True) -> None:
        self._scheduler.shutdown(wait=wait)
        logger.info("scheduler shutdown")

    def remove_jobs_for_target(self, target_id: str) -> None:
        prefix = f"{target_id}-"
        jobs = self._scheduler.get_jobs()
        for job in jobs:
            if job.id.startswith(prefix):
                self._scheduler.remove_job(job.id)
                logger.info("removed job", extra={"job_id": job.id, "target_id": target_id})

    def get_running_jobs(self) -> list[Any]:
        jobs = self._scheduler.get_jobs()
        return list(jobs) if jobs is not None else []

    @property
    def running(self) -> bool:
        return bool(self._scheduler.running)
