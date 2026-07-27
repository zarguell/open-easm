from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import TYPE_CHECKING, Any, Callable

import asyncpg
import httpx

from easm.runners.ingestion import _ingest_entities
from easm.runtime import get_runtime

if TYPE_CHECKING:
    from easm.store import Store

logger = logging.getLogger(__name__)


async def exec_subprocess(
    cmd: list[str],
    *,
    timeout: int = 300,
    logger_fn: Callable[[str], None] | None = None,
) -> tuple[bool, str, str]:
    if logger_fn is None:
        logger_fn = lambda _: None
    runtime = get_runtime()
    if runtime.is_simulation or not runtime.config.allow_subprocess:
        return await runtime.exec_subprocess(cmd, timeout=timeout, logger_fn=logger_fn)
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
        logger_fn("[stderr] timeout")
        return False, "", "timeout"
    stdout_text = stdout.decode(errors="replace")
    stderr_text = stderr.decode(errors="replace")
    for line in stdout_text.splitlines():
        logger_fn(f"[stdout] {line}")
    for line in stderr_text.splitlines():
        logger_fn(f"[stderr] {line}")
    if proc.returncode != 0:
        return False, stdout_text, stderr_text
    return True, stdout_text, ""


async def standard_subprocess_run(
    target: Any,
    store: "Store",
    trigger_type: str,  # noqa: ARG001
    run_id: uuid.UUID,
    log: Callable[[str], None],
    http_client: httpx.AsyncClient | None,  # noqa: ARG001
    *,
    source_name: str,
    binary: str,
    args_template: list[str],
    iterate_over: Callable[[Any], list[str]],
    timeout: int = 300,
    transform_fn: Callable[[dict, str], dict | None] | None = None,
    output_schema: Any | None = None,
    pool: Any | None = None,
) -> tuple[int, int, int]:
    inserted = deduped = errors = 0
    items = iterate_over(target)
    log(f"[runner] {source_name}: iterating over {len(items)} item(s)")
    first_error: str | None = None

    for item in items:
        cmd = [binary] + [arg.replace("[item]", item) for arg in args_template]
        log(f"[runner] {source_name}: running {' '.join(cmd)}")

        ok, stdout, stderr = await exec_subprocess(cmd, timeout=timeout, logger_fn=log)
        if not ok:
            errors += 1
            err_msg = stderr[:200] if stderr else "unknown error"
            if first_error is None:
                first_error = f"{binary} failed for {item}: {err_msg}"
            logger.warning(
                "%s error for %s", binary, item,
                extra={
                    "item": item,
                    "target_id": target.id,
                    "stderr": stderr[:200] if stderr else "",
                },
            )
            continue

        if not stdout.strip():
            logger.warning(
                "%s produced no output for %s", binary, item,
                extra={"item": item, "target_id": target.id},
            )
            continue

        for line in stdout.strip().split("\n"):
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                errors += 1
                continue

            raw = transform_fn(parsed, item) if transform_fn else parsed
            if raw is None:
                continue

            raw_event_id = await store.insert_raw_event(
                target.org_id, target.id, source_name, raw, run_id,
            )
            if raw_event_id is not None:
                inserted += 1
                if output_schema:
                    await _ingest_entities(store, output_schema, raw, run_id,
                                          target.org_id, target.id, target=target,
                                          pool=pool or getattr(store, "pool", None),
                                          raw_event_id=raw_event_id)
            else:
                deduped += 1

    if errors > 0 and inserted == 0 and first_error:
        raise RuntimeError(first_error)

    return inserted, deduped, errors
