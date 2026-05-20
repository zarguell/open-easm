from __future__ import annotations

import asyncio
import inspect
import json
import logging
from pathlib import Path
from datetime import UTC, datetime
from typing import Any

import httpx

from easm.certificates import certificate_inventory_to_findings
from easm.correlation.engine import CorrelationEngine
from easm.correlation.loader import load_rules_from_dir
from easm.pivot.handlers import PIVOT_HANDLER_REGISTRY, PIVOT_SOURCE_NAMES
from easm.pivot.resolver import PivotResolver
from easm.rate_limiter import get_default_limiters
from easm.runtime import get_runtime
from easm.runners.schemas import OUTPUT_SCHEMAS
from easm.store import Store, _compute_event_hash

logger = logging.getLogger(__name__)

CORRELATIONS_DIR = Path(__file__).parent.parent.parent / "correlations"

MAX_TRANSIENT_RETRIES = 3


def _dispatch_finding_notification(f: Any, finding_id: Any) -> None:
    """Fire-and-forget notification dispatch for a newly created finding."""
    from easm.notifications.dispatcher import get_dispatcher
    from easm.notifications.types import NotificationPayload

    dispatcher = get_dispatcher()
    if not dispatcher:
        return
    try:
        import asyncio

        payload = NotificationPayload(
            finding_id=str(finding_id),
            rule_id=f.rule_id,
            headline=f.headline,
            risk=f.risk.value if hasattr(f.risk, "value") else str(f.risk),
            severity=f.risk.value if hasattr(f.risk, "value") else str(f.risk),
            target_id=f.target_id,
            entity_ids=f.entity_ids,
            evidence=f.evidence,
        )
        loop = asyncio.get_running_loop()
        loop.create_task(dispatcher.dispatch(payload))
    except Exception:
        logger.debug("notification dispatch error (non-fatal)", exc_info=True)


async def _run_correlation(store: Store, org_id: str, target_id: str) -> None:
    try:
        if not CORRELATIONS_DIR.exists():
            return
        rules = load_rules_from_dir(CORRELATIONS_DIR)
        if not rules:
            return
        engine = CorrelationEngine(store.pool)
        findings = await engine.evaluate_rules(rules, org_id, target_id)
        if not findings:
            return
        for f in findings:
            try:
                finding_id = await store.create_finding(f)
                _dispatch_finding_notification(f, finding_id)
            except Exception:
                logger.exception("failed to save finding", extra={"rule_id": f.rule_id})
    except Exception:
        logger.exception("correlation engine failed")

    try:
        cert_rows = await store.list_certificate_inventory(
            target_id=target_id, org_id=org_id, limit=500
        )
        if cert_rows:
            cert_findings = certificate_inventory_to_findings(
                org_id=org_id, target_id=target_id, rows=cert_rows
            )
            for f in cert_findings:
                try:
                    finding_id = await store.create_finding(f)
                    _dispatch_finding_notification(f, finding_id)
                except Exception:
                    logger.exception(
                        "failed to save certificate finding",
                        extra={"rule_id": f.rule_id},
                    )
            logger.info(
                "Certificate analysis produced %d findings for target %s",
                len(cert_findings),
                target_id,
            )
    except Exception:
        logger.exception("certificate findings generation failed")


def _resolve_target_config(config: Any | None, target_id: str) -> Any | None:
    if config is None:
        return None
    for t in config.targets:
        if t.id == target_id:
            return t
    return None


async def _process_one_pivot_job(
    *,
    pool: Any,
    store: Store,
    config: Any | None,
    shared_http: httpx.AsyncClient,
    limiters: Any,
    resolver: PivotResolver,
    job: dict[str, Any],
) -> None:
    runtime = get_runtime()
    run_id = job.get("run_id")
    created_pivot_run = False
    run_start = datetime.now(UTC)
    inserted = deduped = errors = 0
    try:
        handler_fn = PIVOT_HANDLER_REGISTRY.get(job["pivot_type"])
        if not handler_fn:
            await store.mark_pivot_failed(job["id"], "no handler for pivot type")
            return

        sig = inspect.signature(handler_fn)
        kwargs: dict = {}
        if "http_client" in sig.parameters:
            kwargs["http_client"] = shared_http
        if "limiters" in sig.parameters:
            kwargs["limiters"] = limiters
        results = await runtime.run_pivot_handler(
            job["pivot_type"], job, handler_fn, pool, **kwargs
        )
        source_name = PIVOT_SOURCE_NAMES.get(job["pivot_type"], job["pivot_type"])
        if source_name is None:
            source_name = job["pivot_type"]

        if not run_id:
            run_id = await store.create_run(
                job["target_id"], f"pivot:{job['pivot_type']}",
                "pivot", org_id=job["org_id"],
            )
            created_pivot_run = True
            await store.mark_run_started(run_id, run_start)

        raw_event_ids: list = []
        for raw_result in results:
            discovery_session_id = job.get("discovery_session_id")
            meta = {
                "_meta": {
                    "session_id": (
                        str(discovery_session_id)
                        if discovery_session_id
                        else None
                    ),
                    "pivot_job_id": str(job["id"]),
                },
                **raw_result,
            }
            event_hash = _compute_event_hash(
                job["org_id"], job["target_id"], source_name, meta,
            )
            raw_json = json.dumps(meta)
            raw_event_uuid = await pool.fetchval(
                """INSERT INTO raw_events
                   (org_id, target_id, source, raw, event_hash, run_id)
                   VALUES ($1, $2, $3, $4::jsonb, $5, $6)
                   ON CONFLICT (event_hash) DO NOTHING
                   RETURNING id""",
                job["org_id"], job["target_id"], source_name,
                raw_json, event_hash, run_id,
            )
            raw_event_ids.append(raw_event_uuid)
            if raw_event_uuid:
                inserted += 1
            else:
                deduped += 1

        target_config = _resolve_target_config(config, job["target_id"])

        schema_fn = OUTPUT_SCHEMAS.get(
            source_name or job["pivot_type"],
        )
        if schema_fn:
            for i, raw_result in enumerate(results):
                re_id = raw_event_ids[i] if i < len(raw_event_ids) else None
                try:
                    entities, rels = schema_fn(raw_result)
                    for ec in entities:
                        try:
                            entity_id, is_new = await store.upsert_entity(
                                job["org_id"], job["target_id"],
                                ec.entity_type, ec.value,
                                ec.attributes, raw_event_id=re_id,
                                discovery_session_id=job.get("discovery_session_id"),
                                discovery_run_id=run_id,
                                discovery_pivot_id=job["id"],
                            )

                            if ec.entity_type == "ip":
                                try:
                                    import ipaddress
                                    ip_obj = ipaddress.ip_address(ec.value)
                                    rows = await store.pool.fetch(
                                        """
                                        SELECT id, entity_value FROM entities
                                        WHERE org_id = $1 AND target_id = $2 AND entity_type = 'ip_range'
                                        """,
                                        job["org_id"], job["target_id"],
                                    )
                                    for row in rows:
                                        try:
                                            network = ipaddress.ip_network(row["entity_value"], strict=False)
                                            if ip_obj in network:
                                                await store.upsert_relationship(
                                                    job["org_id"],
                                                    entity_id,
                                                    row["id"],
                                                    "ip_in_range",
                                                    "auto_association",
                                                    evidence_raw_event_id=re_id,
                                                    runner=source_name or job["pivot_type"],
                                                )
                                                logger.debug("associated IP %s with range %s", ec.value, row["entity_value"])
                                                break
                                        except ValueError:
                                            continue
                                except Exception:
                                    logger.debug("ip range association failed", exc_info=True)

                            if ec.entity_type == "ip":
                                try:
                                    from easm.pivot.handlers import GeoIpLookup
                                    lookup = GeoIpLookup()
                                    result = lookup.lookup(ec.value)
                                    if result:
                                        existing = await store.pool.fetchrow(
                                            "SELECT attributes FROM entities WHERE id = $1",
                                            entity_id,
                                        )
                                        attrs = existing["attributes"] if existing else {}
                                        if isinstance(attrs, str):
                                            attrs = json.loads(attrs)
                                        if not attrs:
                                            attrs = {}
                                        attrs["geo"] = result.to_dict()
                                        await store.pool.execute(
                                            "UPDATE entities SET attributes = $1::jsonb WHERE id = $2",
                                            json.dumps(attrs), entity_id,
                                        )
                                        logger.debug("enriched IP %s with geo data", ec.value)
                                except Exception:
                                    logger.debug("geo enrichment failed", exc_info=True)

                            try:
                                source = source_name or job["pivot_type"] or "unknown"
                                target_domains = (
                                    list(target_config.match_rules.domains)
                                    if target_config
                                    and hasattr(target_config, "match_rules")
                                    else []
                                )
                                target_asns = (
                                    list(target_config.match_rules.asns)
                                    if target_config
                                    and hasattr(target_config, "match_rules")
                                    else []
                                )
                                await store.apply_asset_profile_for_entity(
                                    org_id=job["org_id"],
                                    target_id=job["target_id"],
                                    entity_id=entity_id,
                                    entity_type=ec.entity_type,
                                    entity_value=ec.value,
                                    source=source,
                                    raw_event_id=re_id,
                                    target_domains=target_domains,
                                    target_asns=target_asns,
                                    summary=(
                                        f"{source} observed "
                                        f"{ec.entity_type} {ec.value}"
                                    ),
                                )
                            except Exception:
                                logger.debug(
                                    "asset profile update from pivot failed",
                                    exc_info=True,
                                )
                            if is_new and target_config:
                                try:
                                    await resolver.check_and_enqueue(
                                        target_config,
                                        ec.entity_type, ec.value,
                                        entity_id,
                                        depth=job.get("depth", 1) + 1,
                                        parent_entity_id=job["entity_id"],
                                        discovery_session_id=(
                                            job.get("discovery_session_id")
                                        ),
                                    )
                                except Exception:
                                    errors += 1
                                    logger.debug(
                                        "recursive pivot failed",
                                        exc_info=True,
                                    )
                        except Exception:
                            errors += 1
                            logger.debug(
                                "entity upsert from pivot failed",
                                exc_info=True,
                            )
                    for rc in rels:
                        try:
                            await store.upsert_relationship_by_value(
                                job["org_id"], job["target_id"],
                                rc.source_type, rc.source_value,
                                rc.target_type, rc.target_value,
                                rc.relationship_type, rc.relationship_source,
                                evidence_raw_event_id=re_id,
                            )
                        except Exception:
                            errors += 1
                            logger.debug(
                                "relationship upsert from pivot failed",
                                exc_info=True,
                            )
                except Exception:
                    errors += 1
                    logger.debug(
                        "output schema failed for pivot result",
                        exc_info=True,
                    )
        materialization_error = None
        if errors:
            materialization_error = f"pivot materialization failed: {errors} error(s)"
            await store.mark_pivot_failed(job["id"], materialization_error)
        else:
            await store.mark_pivot_completed(job["id"])

        if created_pivot_run:
            run_end = datetime.now(UTC)
            run_status = "failed" if materialization_error else "completed"
            await store.mark_run_finished(
                run_id,
                run_status,
                run_end,
                int((run_end - run_start).total_seconds() * 1000),
                inserted,
                deduped,
                errors,
                error_message=materialization_error,
                metadata={
                    "pivot_job_id": str(job["id"]),
                    "pivot_type": job["pivot_type"],
                    "entity_value": job["entity_value"],
                    "discovery_session_id": (
                        str(job.get("discovery_session_id"))
                        if job.get("discovery_session_id")
                        else None
                    ),
                },
            )
    except (httpx.TransportError, httpx.ReadTimeout, httpx.ConnectError, httpx.NetworkError):
        logger.exception(
            "pivot transient error, will retry: "
            "job_id=%s pivot_type=%s entity_value=%s",
            str(job["id"]), job["pivot_type"], job["entity_value"],
        )
        err = job.get("error_message") or ""
        retry_count = 0
        if err.startswith("transient_error|"):
            try:
                retry_count = int(err.split("|")[1])
            except (ValueError, IndexError):
                retry_count = 0
        if retry_count < MAX_TRANSIENT_RETRIES:
            await pool.execute(
                "UPDATE pivot_queue SET status='pending', enqueued_at=NOW(), "
                "error_message=$2 WHERE id=$1",
                job["id"], f"transient_error|{retry_count + 1}",
            )
        else:
            await store.mark_pivot_failed(
                job["id"],
                f"permanent: transport error after {retry_count} retries",
            )
            if created_pivot_run and run_id:
                run_end = datetime.now(UTC)
                await store.mark_run_finished(
                    run_id,
                    "failed",
                    run_end,
                    int((run_end - run_start).total_seconds() * 1000),
                    inserted,
                    deduped,
                    errors + 1,
                    error_message="transport error",
                    metadata={
                        "pivot_job_id": str(job["id"]),
                        "pivot_type": job["pivot_type"],
                        "entity_value": job["entity_value"],
                    },
                )
    except Exception:
        logger.exception(
            "pivot job failed: job_id=%s pivot_type=%s entity_value=%s",
            str(job["id"]), job["pivot_type"], job["entity_value"],
        )
        await store.mark_pivot_failed(job["id"], "see logs")
        if created_pivot_run and run_id:
            run_end = datetime.now(UTC)
            await store.mark_run_finished(
                run_id,
                "failed",
                run_end,
                int((run_end - run_start).total_seconds() * 1000),
                inserted,
                deduped,
                errors + 1,
                error_message="see logs",
                metadata={
                    "pivot_job_id": str(job["id"]),
                    "pivot_type": job["pivot_type"],
                    "entity_value": job["entity_value"],
                },
            )


async def _process_pivot_jobs(
    *,
    pool: Any,
    store: Store,
    config: Any | None,
    shared_http: httpx.AsyncClient,
    limiters: Any,
    resolver: PivotResolver,
    limit: int,
) -> int:
    jobs = await store.dequeue_pivot_jobs_batch(limit=limit)
    if not jobs:
        return 0

    for job in jobs:
        await _process_one_pivot_job(
            pool=pool,
            store=store,
            config=config,
            shared_http=shared_http,
            limiters=limiters,
            resolver=resolver,
            job=job,
        )

    first = jobs[0]
    await _run_correlation(store, first["org_id"], first["target_id"])
    return len(jobs)


async def process_pivot_job_batch(
    pool: Any,
    config: Any | None = None,
    *,
    limit: int = 20,
) -> int:
    store = Store(pool)
    runtime = get_runtime()
    shared_http = runtime.make_http_client()
    limiters = get_default_limiters()
    resolver = PivotResolver(pool)
    try:
        return await _process_pivot_jobs(
            pool=pool,
            store=store,
            config=config,
            shared_http=shared_http,
            limiters=limiters,
            resolver=resolver,
            limit=limit,
        )
    finally:
        await shared_http.aclose()


async def pivot_worker_pool(
    pool, config: Any | None = None, n: int = 3, batch_interval_ms: int = 200,
):
    store = Store(pool)
    await store.reset_orphaned_pivot_jobs()

    runtime = get_runtime()
    shared_http = runtime.make_http_client()

    limiters = get_default_limiters()
    resolver = PivotResolver(pool)

    async def worker_loop():
        while True:
            processed = await _process_pivot_jobs(
                pool=pool,
                store=store,
                config=config,
                shared_http=shared_http,
                limiters=limiters,
                resolver=resolver,
                limit=20,
            )
            if not processed:
                await asyncio.sleep(batch_interval_ms / 1000)

    try:
        async with asyncio.TaskGroup() as tg:
            for _ in range(n):
                tg.create_task(worker_loop())
    finally:
        await shared_http.aclose()
