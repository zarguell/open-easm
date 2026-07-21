from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Awaitable, Callable

import asyncpg
import httpx

from easm.models import RunStatus
from easm.runners.ingestion import _ensure_seed_entities, _ingest_entities

if TYPE_CHECKING:
    from easm.store import Store

logger = logging.getLogger(__name__)


async def execute_runner(
    source_name: str,
    run_fn: Callable[..., Awaitable[tuple[int, int, int]]],
    target: Any,
    store: "Store",
    trigger_type: str,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> uuid.UUID:
    log_lines: list[str] = []

    def log(msg: str) -> None:
        log_lines.append(msg)

    run_id = await store.create_run(
        target.id, source_name, trigger_type, org_id=target.org_id,
    )

    seed_map: dict[tuple[str, str], uuid.UUID] = {}
    try:
        seed_map = await _ensure_seed_entities(store, target, target.org_id, run_id)
    except (asyncpg.PostgresError, ValueError) as e:
        logger.debug(
            "seed entity pre-creation failed",
            exc_info=True, extra={"error": str(e)},
        )

    target._seed_map = seed_map

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

    if status == RunStatus.COMPLETED.value:
        try:
            from easm.runners import get_all_runners as _get_all_runners

            _runner_def = _get_all_runners().get(source_name)
            if _runner_def and _runner_def.output_schema:
                _raw_events = await store.pool.fetch(
                    "SELECT id, raw FROM raw_events WHERE run_id = $1",
                    run_id,
                )
                if _raw_events:
                    _total_entities = 0
                    for _re in _raw_events:
                        try:
                            await _ingest_entities(
                                store, _runner_def.output_schema,
                                _re["raw"], run_id,
                                target.org_id, target.id, target=target,
                                pool=store.pool, raw_event_id=_re["id"],
                            )
                            _raw_parsed = json.loads(_re["raw"]) if isinstance(_re["raw"], str) else _re["raw"]
                            _ents, _ = _runner_def.output_schema(_raw_parsed)
                            _total_entities += len(_ents)
                        except (ValueError, KeyError, TypeError, asyncpg.PostgresError) as e:
                            logger.debug(
                                "post-run entity ingest failed",
                                exc_info=True, extra={"error": str(e)},
                            )
                    logger.info(
                        "%s: processed %d raw events into %d entities via output_schema",
                        source_name, len(_raw_events), _total_entities,
                    )
        except (asyncpg.PostgresError, ValueError) as e:
            logger.debug(
                "output_schema post-processing failed",
                exc_info=True, extra={"error": str(e)},
            )

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
    except (asyncpg.PostgresError, ValueError, KeyError, TypeError) as e:
        logger.exception(
            "failed to compute run counters",
            extra={"run_id": str(run_id), "error": str(e)},
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
