from __future__ import annotations

import asyncio
import json
import logging
import random
import uuid
from datetime import UTC, datetime
from typing import Any, Awaitable, Callable

import httpx

from easm.models import RunStatus
from easm.store import Store

logger = logging.getLogger(__name__)


def get_runner_config(target: Any, source_name: str) -> dict[str, Any]:
    """Get runner-specific config dict from a target's runners config.

    Mirrors ``BaseRunner.get_runner_config()``.
    """
    cfg = target.runners.get(source_name) if hasattr(target, "runners") else None
    if cfg is None:
        return {}
    return cfg.model_dump() if hasattr(cfg, "model_dump") else {}


def iterate_domains_x2(target: Any) -> list[str]:
    """Produce ``https://<domain>`` and ``http://<domain>`` for every domain.

    Used by nuclei and wappalyzer which scan both schemes.
    """
    items: list[str] = []
    for domain in target.match_rules.domains:
        items.append(f"https://{domain}")
        items.append(f"http://{domain}")
    return items


# ---------------------------------------------------------------------------
# Subprocess execution
# ---------------------------------------------------------------------------

async def exec_subprocess(
    cmd: list[str],
    *,
    timeout: int = 300,
    logger_fn: Callable[[str], None] | None = None,
) -> tuple[bool, str, str]:
    """Execute a subprocess and return ``(ok, stdout, stderr)``.

    Mirrors ``BaseRunner._exec_subprocess()`` exactly.
    ``logger_fn`` is called for each stdout/stderr line to allow log
    collection by the caller.
    """
    if logger_fn is None:
        logger_fn = lambda _: None
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


# ---------------------------------------------------------------------------
# Full run lifecycle (mirrors BaseRunner.execute)
# ---------------------------------------------------------------------------

async def execute_runner(
    source_name: str,
    run_fn: Callable[..., Awaitable[tuple[int, int, int]]],
    target: Any,
    store: Store,
    trigger_type: str,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> uuid.UUID:
    """Execute a runner's full lifecycle and return the ``run_id``.

    This mirrors ``BaseRunner.execute()``:
    * create a run record
    * mark it started
    * call ``run_fn(target, store, trigger_type, run_id, log, http_client)``
    * handle exceptions
    * mark the run finished with counters
    * compute ``new_entity_count`` / ``total_entity_count``
    """
    log_lines: list[str] = []

    def log(msg: str) -> None:
        log_lines.append(msg)

    run_id = await store.create_run(
        target.id, source_name, trigger_type, org_id=target.org_id,
    )
    start = datetime.now(UTC)
    await store.mark_run_started(run_id, start)

    inserted = deduped = errors = 0
    error_message: str | None = None

    try:
        inserted, deduped, errors = await run_fn(
            target, store, trigger_type, run_id, log, http_client,
        )
        status = RunStatus.COMPLETED.value
    except Exception as e:
        status = RunStatus.FAILED.value
        error_message = str(e)
        errors += 1
        logger.exception(
            "runner failed",
            extra={
                "run_id": str(run_id),
                "target_id": target.id,
                "source": source_name,
            },
        )

    end = datetime.now(UTC)
    duration_ms = int((end - start).total_seconds() * 1000)
    log_text = "\n".join(log_lines) if log_lines else None
    await store.mark_run_finished(
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

    # Compute run counters ------------------------------------------------
    try:
        run_data = await store.get_run(run_id)
        session_id = run_data.get("discovery_session_id") if run_data else None
        if session_id:
            new_count = await store.pool.fetchval(
                "SELECT COUNT(*) FROM entities WHERE discovery_session_id = $1 AND is_first_discovery = TRUE",
                uuid.UUID(session_id),
            )
            total_count = await store.pool.fetchval(
                "SELECT COUNT(*) FROM entities WHERE discovery_session_id = $1",
                uuid.UUID(session_id),
            )
            await store.pool.execute(
                "UPDATE runs SET new_entity_count = $1, total_entity_count = $2 WHERE id = $3",
                new_count or 0,
                total_count or 0,
                run_id,
            )
    except Exception:
        logger.exception(
            "failed to compute run counters", extra={"run_id": str(run_id)},
        )

    logger.info(
        "run finished",
        extra={
            "run_id": str(run_id),
            "target_id": target.id,
            "source": source_name,
            "status": status,
            "duration_ms": duration_ms,
            "inserted": inserted,
            "deduped": deduped,
            "errors": errors,
        },
    )
    return run_id


# ---------------------------------------------------------------------------
# Generic subprocess runner
# ---------------------------------------------------------------------------

async def standard_subprocess_run(
    target: Any,
    store: Store,
    trigger_type: str,  # noqa: ARG001 (part of the run_fn signature contract)
    run_id: uuid.UUID,
    log: Callable[[str], None],
    http_client: httpx.AsyncClient | None,  # noqa: ARG001 (subprocess runners don't use HTTP)
    *,
    source_name: str,
    binary: str,
    args_template: list[str],
    iterate_over: Callable[[Any], list[str]],
    timeout: int = 300,
    transform_fn: Callable[[dict, str], dict | None] | None = None,
) -> tuple[int, int, int]:
    """Generic subprocess runner for tools that output JSON-lines on stdout.

    For each item returned by ``iterate_over(target)``:
    1. Build ``[binary, *args_template]`` with ``[item]`` placeholders replaced
    2. ``exec_subprocess``
    3. Parse each stdout line as JSON
    4. Apply ``transform_fn(parsed, item)`` if given
    5. ``store.insert_raw_event``

    Returns ``(inserted, deduped, errors)``.
    """
    inserted = deduped = errors = 0

    for item in iterate_over(target):
        cmd = [binary] + [arg.replace("[item]", item) for arg in args_template]

        ok, stdout, stderr = await exec_subprocess(cmd, timeout=timeout, logger_fn=log)
        if not ok:
            errors += 1
            logger.warning(
                "%s error for %s", binary, item,
                extra={
                    "item": item,
                    "target_id": target.id,
                    "stderr": stderr[:200] if stderr else "",
                },
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

            result = await store.insert_raw_event(
                target.org_id, target.id, source_name, raw, run_id,
            )
            if result:
                inserted += 1
            else:
                deduped += 1

    return inserted, deduped, errors


# ---------------------------------------------------------------------------
# Generic HTTP runner
# ---------------------------------------------------------------------------

async def standard_http_run(
    target: Any,
    store: Store,
    trigger_type: str,  # noqa: ARG001
    run_id: uuid.UUID,
    log: Callable[[str], None],
    http_client: httpx.AsyncClient | None,
    *,
    source_name: str,
    url_template: str,
    iterate_over: Callable[[Any], list[str]],
    timeout: float = 30.0,
    transform_fn: Callable[[dict, str], dict | None] | None = None,
    max_retries: int = 0,
    retry_statuses: tuple[int, ...] = (),
    inter_delay: float = 0.0,
) -> tuple[int, int, int]:
    """Generic HTTP runner with optional retry and rate-limiting.

    For each item returned by ``iterate_over(target)``:
    1. Build URL by replacing ``[item]`` in ``url_template``
    2. Fetch with retry logic (``max_retries`` total attempts)
    3. Parse response as JSON array, single JSON object, or NDJSON
    4. Apply ``transform_fn(record, item)`` if given
    5. ``store.insert_raw_event``

    ``retry_statuses`` — HTTP status codes that trigger a retry.
    ``inter_delay`` — seconds to sleep between items (avoids rate-limiting).

    When ``http_client`` is ``None`` a temporary client is created and
    closed automatically.
    """
    own_client = http_client is None
    http = http_client or httpx.AsyncClient(timeout=timeout)
    inserted = deduped = errors = 0

    try:
        for item in iterate_over(target):
            url = url_template.replace("[item]", item)

            try:
                resp_text = await _http_fetch_with_retry(
                    http, url, max_retries, retry_statuses, log,
                )
            except Exception as e:
                errors += 1
                logger.warning(
                    "%s error for %s: %s", source_name, item, e,
                    extra={"item": item, "target_id": target.id},
                )
                if inter_delay:
                    await asyncio.sleep(inter_delay)
                continue

            if resp_text is None:
                errors += 1
                logger.warning(
                    "%s returned no data for %s", source_name, item,
                    extra={"item": item, "target_id": target.id},
                )
                if inter_delay:
                    await asyncio.sleep(inter_delay)
                continue

            records = _parse_response_text(resp_text)
            for record in records:
                raw = transform_fn(record, item) if transform_fn else record
                if raw is None:
                    continue
                result = await store.insert_raw_event(
                    target.org_id, target.id, source_name, raw, run_id,
                )
                if result:
                    inserted += 1
                else:
                    deduped += 1

            if inter_delay:
                await asyncio.sleep(inter_delay)
    finally:
        if own_client:
            await http.aclose()

    return inserted, deduped, errors


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _http_fetch_with_retry(
    http: httpx.AsyncClient,
    url: str,
    max_retries: int,
    retry_statuses: tuple[int, ...],
    log: Callable[[str], None],
) -> str | None:
    """Fetch a URL with exponential backoff for retryable status codes.

    ``max_retries`` is the total number of attempts (1 = no retry).
    Returns the response text on success, or ``None`` on failure.
    """
    for attempt in range(max_retries):
        resp = await http.get(url)
        if resp.status_code == 200:
            return resp.text
        if attempt < max_retries - 1 and resp.status_code in retry_statuses:
            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                try:
                    wait = float(retry_after)
                except ValueError:
                    wait = float(2**attempt) + random.uniform(0, 1)
            else:
                wait = float(2**attempt) + random.uniform(0, 1)
            log(
                f"[http] retry {attempt + 1}/{max_retries - 1} "
                f"after {wait:.1f}s (status {resp.status_code})",
            )
            await asyncio.sleep(wait)
            continue
        # Non-retryable status or final attempt
        return None
    return None


def _parse_response_text(text: str) -> list[dict]:
    """Parse HTTP response body as JSON array, single JSON object, or NDJSON."""
    stripped = text.strip()
    if not stripped:
        return []
    try:
        data = json.loads(stripped)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except json.JSONDecodeError:
        # Try NDJSON (one JSON object per line)
        records: list[dict] = []
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records
