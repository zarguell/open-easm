from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import asyncpg

from easm.runners.http_runner import (
    _http_fetch_with_retry,
    _parse_response_text,
    standard_http_run,
)
from easm.runners.ingestion import _ensure_seed_entities, _ingest_entities
from easm.runners.lifecycle import execute_runner
from easm.runners.subprocess_runner import exec_subprocess, standard_subprocess_run

if TYPE_CHECKING:
    from easm.store import Store

logger = logging.getLogger(__name__)


def get_runner_config(target: Any, source_name: str) -> dict[str, Any]:
    cfg = target.runners.get(source_name) if hasattr(target, "runners") else None
    if cfg is None:
        return {}
    return cfg.model_dump() if hasattr(cfg, "model_dump") else {}


def iterate_domains_x2(target: Any) -> list[str]:
    items: list[str] = []
    for domain in target.match_rules.domains:
        items.append(f"https://{domain}")
        items.append(f"http://{domain}")
    return items


async def iterate_hostnames_x2(target: Any, pool: Any) -> list[str]:
    items: list[str] = []

    for domain in target.match_rules.domains:
        items.append(f"https://{domain}")
        items.append(f"http://{domain}")

    if pool is not None:
        try:
            rows = await pool.fetch(
                "SELECT entity_value FROM entities "
                "WHERE target_id = $1 AND entity_type = 'hostname' "
                "ORDER BY last_seen_at DESC",
                target.id,
            )
            existing: set[str] = set()
            for domain in target.match_rules.domains:
                existing.add(f"https://{domain}")
                existing.add(f"http://{domain}")
            for row in rows:
                hostname = row["entity_value"]
                https_url = f"https://{hostname}"
                http_url = f"http://{hostname}"
                if https_url not in existing:
                    items.append(https_url)
                if http_url not in existing:
                    items.append(http_url)
        except (asyncpg.PostgresError, KeyError) as e:
            logger.debug(
                "hostname query failed; falling back to domains only",
                exc_info=True, extra={"target_id": target.id, "error": str(e)},
            )

    return items


__all__ = [
    "_ensure_seed_entities",
    "_http_fetch_with_retry",
    "_ingest_entities",
    "_parse_response_text",
    "exec_subprocess",
    "execute_runner",
    "get_runner_config",
    "iterate_domains_x2",
    "iterate_hostnames_x2",
    "standard_http_run",
    "standard_subprocess_run",
]
