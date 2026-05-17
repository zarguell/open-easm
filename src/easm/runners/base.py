from __future__ import annotations

import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

import httpx

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
        self._log_lines: list[str] = []

    def _log(self, msg: str) -> None:
        self._log_lines.append(msg)

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
            self._log("[stderr] timeout")
            return False, "", "timeout"
        stdout_text = stdout.decode(errors="replace")
        stderr_text = stderr.decode(errors="replace")
        for line in stdout_text.splitlines():
            self._log(f"[stdout] {line}")
        for line in stderr_text.splitlines():
            self._log(f"[stderr] {line}")
        if proc.returncode != 0:
            return False, stdout_text, stderr_text
        return True, stdout_text, ""

    @abstractmethod
    async def run_once(
        self, target: Any, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        ...

    async def execute(self, target: Any, trigger_type: str) -> uuid.UUID:
        self._log_lines = []
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
        log_text = "\n".join(self._log_lines) if self._log_lines else None
        await self.store.mark_run_finished(
            run_id,
            status,
            end,
            duration_ms,
            inserted,
            deduped,
            errors,
            error_message=error_message,
            logs=log_text,
        )

        # Compute run counters
        try:
            run_data = await self.store.get_run(run_id)
            session_id = run_data.get("discovery_session_id") if run_data else None
            if session_id:
                new_count = await self.store.pool.fetchval(
                    "SELECT COUNT(*) FROM entities WHERE discovery_session_id = $1 AND is_first_discovery = TRUE",
                    uuid.UUID(session_id),
                )
                total_count = await self.store.pool.fetchval(
                    "SELECT COUNT(*) FROM entities WHERE discovery_session_id = $1",
                    uuid.UUID(session_id),
                )
                await self.store.pool.execute(
                    "UPDATE runs SET new_entity_count = $1, total_entity_count = $2 WHERE id = $3",
                    new_count or 0, total_count or 0, run_id,
                )
        except Exception:
            logger.exception("failed to compute run counters", extra={"run_id": str(run_id)})

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


class ApiRunner(BaseRunner):
    is_api_runner: bool = True

    def __init__(self, store: Store, http_client: httpx.AsyncClient | None = None):
        super().__init__(store)
        self._http_client = http_client

    async def close(self):
        if self._http_client:
            await self._http_client.aclose()
