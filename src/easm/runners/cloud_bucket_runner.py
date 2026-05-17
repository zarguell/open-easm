from __future__ import annotations

import asyncio
import json
import logging
import uuid

import httpx

from easm.config import TargetConfig
from easm.runners.base import ApiRunner

logger = logging.getLogger(__name__)

CLOUD_PROVIDERS = ["aws_s3", "gcs", "azure_blob"]

COMMON_BUCKET_PREFIXES = [
    "", "backup", "backups", "uploads", "assets", "logs", "data",
    "files", "public", "static", "media", "dev", "staging", "prod",
    "test", "bucket", "storage", "archive", "cdn", "downloads",
    "resources", "config", "configs", "db", "database", "sql",
]

BUCKET_CHECK_TIMEOUT = 10.0
CONCURRENCY_LIMIT = 20


def _derive_bucket_prefixes(domain: str) -> list[str]:
    prefixes: list[str] = []
    domain = domain.lower().strip()
    prefixes.append(domain)

    parts = domain.split(".")
    if len(parts) >= 2:
        prefixes.append("-".join(parts))
        prefixes.append(parts[0])

    if len(parts) >= 3:
        prefixes.append("-".join(parts[:-2]))

    for common in COMMON_BUCKET_PREFIXES:
        if common:
            prefixes.append(f"{parts[0]}-{common}")
            prefixes.append(f"{common}-{parts[0]}")

    return list(dict.fromkeys(p for p in prefixes if p and len(p) <= 63))


def _provider_check_urls(prefix: str, provider: str) -> list[tuple[str, str]]:
    if provider == "aws_s3":
        return [(f"https://{prefix}.s3.amazonaws.com", "aws_s3")]
    elif provider == "gcs":
        return [(f"https://storage.googleapis.com/{prefix}", "gcs")]
    elif provider == "azure_blob":
        return [(f"https://{prefix}.blob.core.windows.net", "azure_blob")]
    return []


class CloudBucketRunner(ApiRunner):
    source_name = "cloud_enum"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False
    is_api_runner = True

    def __init__(
        self,
        store,
        http_client: httpx.AsyncClient | None = None,
        semaphore: asyncio.Semaphore | None = None,
    ):
        super().__init__(store, http_client=http_client)
        self._semaphore = semaphore or asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        from easm.store import _compute_event_hash

        http = self._http_client or httpx.AsyncClient(timeout=BUCKET_CHECK_TIMEOUT)
        inserted = deduped = errors = 0

        check_urls: list[tuple[str, str, str]] = []
        for domain in target.match_rules.domains:
            prefixes = _derive_bucket_prefixes(domain)
            for prefix in prefixes:
                for provider in CLOUD_PROVIDERS:
                    for url, prov in _provider_check_urls(prefix, provider):
                        check_urls.append((url, prov, prefix))

        logger.info(
            "cloud_enum: checking %d bucket URLs across %d providers for %s",
            len(check_urls), len(CLOUD_PROVIDERS), target.id,
        )

        sem = self._semaphore

        async def _check(url: str, provider: str, prefix: str) -> dict | None:
            async with sem:
                try:
                    resp = await http.head(url, follow_redirects=True)
                    status = resp.status_code
                    public_access = status in (200, 204, 403)
                    public_list = status in (200, 204)

                    if status in (200, 204, 403):
                        return {
                            "bucket_url": url,
                            "provider": provider,
                            "bucket_name": prefix,
                            "public_access": public_access,
                            "public_list": public_list,
                            "status_code": status,
                        }
                    return None
                except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError) as e:
                    logger.debug("cloud_enum: check failed for %s: %s", url, e)
                    return None

        results = await asyncio.gather(
            *[_check(url, prov, pfx) for url, prov, pfx in check_urls],
            return_exceptions=False,
        )

        for result in results:
            if result is None:
                continue
            try:
                event_hash = _compute_event_hash(
                    target.org_id, target.id, self.source_name, result
                )
                db_result = await self.store.pool.execute(
                    """INSERT INTO raw_events (org_id, target_id, source, raw, event_hash, run_id)
                       VALUES ($1, $2, $3, $4::jsonb, $5, $6)
                       ON CONFLICT (event_hash) DO NOTHING""",
                    target.org_id, target.id, self.source_name,
                    json.dumps(result), event_hash, run_id,
                )
                if db_result == "INSERT 0 0":
                    deduped += 1
                else:
                    inserted += 1
            except Exception as e:
                errors += 1
                logger.warning("cloud_enum: insert error: %s", e)

        if not self._http_client:
            await http.aclose()

        logger.info(
            "cloud_enum: inserted=%d deduped=%d errors=%d",
            inserted, deduped, errors,
        )
        return inserted, deduped, errors
