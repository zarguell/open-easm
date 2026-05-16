from __future__ import annotations

import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from easm.models import RunStatus
from easm.store import Store

logger = logging.getLogger(__name__)


class BaseRunner(ABC):
    source_name: str
    supports_schedule: bool = False
    supports_manual_trigger: bool = False
    is_continuous: bool = False

    def __init__(self, store: Store) -> None:
        self.store = store

    def get_runner_config(self, target: Any) -> dict[str, Any]:
        runner_raw = target.runners.get(self.source_name, {})
        if isinstance(runner_raw, dict):
            return runner_raw
        return runner_raw.model_dump() if hasattr(runner_raw, "model_dump") else {}

    async def _exec_subprocess(
        self, cmd: list[str], *, timeout: int = 300
    ) -> tuple[bool, str, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return False, "", f"binary not found: {cmd[0]}"
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return False, "", "timeout"
        if proc.returncode != 0:
            return False, stdout.decode(errors="replace"), stderr.decode(errors="replace")
        return True, stdout.decode(errors="replace"), ""

    @abstractmethod
    async def run_once(
        self, target: Any, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        ...

    async def execute(self, target: Any, trigger_type: str) -> uuid.UUID:
        run_id = await self.store.create_run(target.id, self.source_name, trigger_type, org_id=target.org_id)
        start = datetime.now(UTC)
        await self.store.mark_run_started(run_id, start)

        inserted = 0
        deduped = 0
        errors = 0
        error_message: str | None = None

        try:
            inserted, deduped, errors = await self.run_once(target, trigger_type, run_id)
            status = RunStatus.COMPLETED.value
        except Exception as e:
            status = RunStatus.FAILED.value
            error_message = str(e)
            errors += 1
            logger.exception(
                "runner failed",
                extra={"run_id": str(run_id), "target_id": target.id, "source": self.source_name},
            )

        end = datetime.now(UTC)
        duration_ms = int((end - start).total_seconds() * 1000)
        await self.store.mark_run_finished(
            run_id,
            status,
            end,
            duration_ms,
            inserted,
            deduped,
            errors,
            error_message=error_message,
        )

        logger.info(
            "run finished",
            extra={
                "run_id": str(run_id),
                "target_id": target.id,
                "source": self.source_name,
                "status": status,
                "duration_ms": duration_ms,
                "inserted": inserted,
                "deduped": deduped,
                "errors": errors,
            },
        )
        return run_id
