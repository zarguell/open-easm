from __future__ import annotations

import logging
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


class Scheduler:
    def __init__(self) -> None:
        self._scheduler = AsyncIOScheduler()
        self._runner_registry: dict[str, type] = {}

    def register_runner(self, name: str, runner_cls: type) -> None:
        self._runner_registry[name] = runner_cls

    def setup_jobs(self, config: Any, store: Any) -> None:
        for target in config.targets:
            if not target.enabled:
                continue
            for runner_name, runner_cfg in target.runners.items():
                cfg_dict = runner_cfg.model_dump()
                if not cfg_dict.get("enabled", False):
                    continue
                if runner_name not in self._runner_registry:
                    logger.warning("unknown runner %s for target %s", runner_name, target.id)
                    continue

                runner_cls = self._runner_registry[runner_name]

                if getattr(runner_cls, "supports_schedule", False):
                    schedule = cfg_dict.get("schedule", "0 0 * * *")
                    job_id = f"{target.id}-{runner_name}"
                    existing = self._scheduler.get_job(job_id)
                    if existing is None:
                        runner = runner_cls(store)
                        self._scheduler.add_job(
                            runner.execute,
                            "cron",
                            args=[target, "scheduled"],
                            id=job_id,
                            **self._parse_cron(schedule),
                            replace_existing=True,
                        )
                        logger.info(
                            "scheduled job",
                            extra={"job_id": job_id, "schedule": schedule, "target_id": target.id},
                        )

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

    def add_jobs_for_target(self, target: Any, runner_registry: dict[str, type], store: Any = None) -> None:
        for runner_name, runner_cfg in target.runners.items():
            cfg_dict = runner_cfg if isinstance(runner_cfg, dict) else runner_cfg.model_dump()
            if not cfg_dict.get("enabled", False):
                continue
            if runner_name not in runner_registry:
                logger.warning("unknown runner %s for target %s", runner_name, target.id)
                continue

            runner_cls = runner_registry[runner_name]
            if getattr(runner_cls, "supports_schedule", False):
                schedule = cfg_dict.get("schedule", "0 0 * * *")
                job_id = f"{target.id}-{runner_name}"
                existing = self._scheduler.get_job(job_id)
                if existing is None:
                    runner = runner_cls(store)  # type: ignore[arg-type]
                    self._scheduler.add_job(
                        runner.execute,
                        "cron",
                        args=[target, "scheduled"],
                        id=job_id,
                        **self._parse_cron(schedule),
                        replace_existing=True,
                    )
                    logger.info(
                        "scheduled job",
                        extra={"job_id": job_id, "schedule": schedule, "target_id": target.id},
                    )

    def get_running_jobs(self) -> list[Any]:
        jobs = self._scheduler.get_jobs()
        return list(jobs) if jobs is not None else []

    @property
    def running(self) -> bool:
        return bool(self._scheduler.running)
