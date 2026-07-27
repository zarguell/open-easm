from __future__ import annotations

import asyncio
import json
import logging
import random
import uuid
from typing import TYPE_CHECKING, Any, Callable

import asyncpg
import httpx

from easm.network_guard import create_guard_client
from easm.runners.ingestion import _ingest_entities

if TYPE_CHECKING:
    from easm.store import Store

logger = logging.getLogger(__name__)


async def standard_http_run(
    target: Any,
    store: "Store",
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
    output_schema: Any | None = None,
    max_retries: int = 0,
    retry_statuses: tuple[int, ...] = (),
    inter_delay: float = 0.0,
    max_concurrent: int = 1,
    pool: Any | None = None,
) -> tuple[int, int, int]:
    own_client = http_client is None
    http = http_client or create_guard_client(timeout=timeout)
    inserted = deduped = errors = 0

    try:
        if max_concurrent > 1:
            sem = asyncio.Semaphore(max_concurrent)

            async def _process_item(item: str) -> tuple[int, int, int]:
                async with sem:
                    url = url_template.replace("[item]", item)
                    try:
                        resp_text = await _http_fetch_with_retry(
                            http, url, max_retries, retry_statuses, log,
                        )
                    except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as exc:
                        logger.warning(
                            "%s error for %s: %s", source_name, item, exc,
                            extra={"item": item, "target_id": target.id},
                        )
                        return 0, 0, 1

                    if resp_text is None:
                        logger.warning(
                            "%s returned no data for %s", source_name, item,
                            extra={"item": item, "target_id": target.id},
                        )
                        return 0, 0, 1

                    ins = ded = 0
                    records = _parse_response_text(resp_text)
                    for record in records:
                        raw = transform_fn(record, item) if transform_fn else record
                        if raw is None:
                            continue
                        raw_event_id = await store.insert_raw_event(
                            target.org_id, target.id, source_name, raw, run_id,
                        )
                        if raw_event_id is not None:
                            ins += 1
                            if output_schema:
                                await _ingest_entities(
                                    store, output_schema, raw, run_id,
                                    target.org_id, target.id,
                                    target=target, pool=pool or store.pool,
                                    raw_event_id=raw_event_id,
                                )
                        else:
                            ded += 1
                    return ins, ded, 0

            items = iterate_over(target)
            results = await asyncio.gather(*[_process_item(i) for i in items])
            for ins, ded, err in results:
                inserted += ins
                deduped += ded
                errors += err
        else:
            for item in iterate_over(target):
                url = url_template.replace("[item]", item)

                try:
                    resp_text = await _http_fetch_with_retry(
                        http, url, max_retries, retry_statuses, log,
                    )
                except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as e:
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

                if inter_delay:
                    await asyncio.sleep(inter_delay)
    finally:
        if own_client:
            await http.aclose()

    return inserted, deduped, errors


async def _http_fetch_with_retry(
    http: httpx.AsyncClient,
    url: str,
    max_retries: int,
    retry_statuses: tuple[int, ...],
    log: Callable[[str], None],
) -> str | None:
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
        return None
    return None


def _parse_response_text(text: str) -> list[dict]:
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
