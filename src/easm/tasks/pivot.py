from __future__ import annotations

import inspect
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg
import httpx
import procrastinate

from easm.queue import app

logger = logging.getLogger(__name__)

TRANSIENT_EXCEPTIONS = (
    httpx.TransportError,
    httpx.ReadTimeout,
    httpx.ConnectError,
    httpx.NetworkError,
)


def _resolve_target_config(config: Any | None, target_id: str) -> Any | None:
    if config is None:
        return None
    for t in config.targets:
        if t.id == target_id:
            return t
    return None


@app.task(
    queue="pivot",
    retry=procrastinate.RetryStrategy(
        max_attempts=4,
        retry_exceptions=TRANSIENT_EXCEPTIONS,
        exponential_wait=2,
    ),
    pass_context=True,
)
async def execute_pivot(
    context: procrastinate.JobContext,
    *,
    org_id: str,
    target_id: str,
    entity_type: str,
    entity_value: str,
    entity_id: str,
    pivot_type: str,
    depth: int = 1,
    parent_entity_id: str | None = None,
    discovery_session_id: str | None = None,
) -> dict:
    from easm.pivot.handlers import (
        PIVOT_HANDLER_REGISTRY,
        PIVOT_SOURCE_NAMES,
    )
    from easm.rate_limiter import get_default_limiters
    from easm.pivot.resolver import PivotResolver
    from easm.runners.schemas import OUTPUT_SCHEMAS
    from easm.runtime import get_runtime
    from easm.store import _compute_event_hash
    from easm.worker_context import get_config, get_pool, get_store

    pool = get_pool()
    store = get_store()
    config = get_config()

    job_id = str(context.job.id)
    run_id = None
    created_pivot_run = False
    run_start = datetime.now(UTC)
    inserted = deduped = errors = 0

    runtime = get_runtime()
    shared_http = runtime.make_http_client()
    limiters = get_default_limiters()
    resolver = PivotResolver(pool)

    try:
        handler_fn = PIVOT_HANDLER_REGISTRY.get(pivot_type)
        if not handler_fn:
            raise ValueError(f"No handler for pivot type: {pivot_type}")

        kwargs: dict[str, Any] = {}
        if "http_client" in inspect.signature(handler_fn).parameters:
            kwargs["http_client"] = shared_http
        if "limiters" in inspect.signature(handler_fn).parameters:
            kwargs["limiters"] = limiters

        job_dict = {
            "id": job_id,
            "org_id": org_id,
            "target_id": target_id,
            "entity_type": entity_type,
            "entity_value": entity_value,
            "entity_id": entity_id,
            "pivot_type": pivot_type,
            "depth": depth,
            "parent_entity_id": parent_entity_id,
            "discovery_session_id": discovery_session_id,
        }

        results = await runtime.run_pivot_handler(
            pivot_type, job_dict, handler_fn, pool, **kwargs,
        )

        source_name = PIVOT_SOURCE_NAMES.get(pivot_type, pivot_type) or pivot_type

        if not run_id:
            run_id = await store.create_run(
                target_id, f"pivot:{pivot_type}", "pivot", org_id=org_id,
            )
            created_pivot_run = True
            await store.mark_run_started(run_id, run_start)

        raw_event_ids: list = []
        for raw_result in results:
            discovery_session_id_val = discovery_session_id
            meta = {
                "_meta": {
                    "session_id": (
                        str(discovery_session_id_val) if discovery_session_id_val else None
                    ),
                    "pivot_job_id": job_id,
                },
                **raw_result,
            }
            event_hash = _compute_event_hash(org_id, target_id, source_name, meta)
            raw_json = json.dumps(meta)
            raw_event_uuid = await pool.fetchval(
                """INSERT INTO raw_events
                   (org_id, target_id, source, raw, event_hash, run_id)
                   VALUES ($1, $2, $3, $4::jsonb, $5, $6)
                   ON CONFLICT (event_hash) DO NOTHING
                   RETURNING id""",
                org_id, target_id, source_name, raw_json, event_hash, run_id,
            )
            raw_event_ids.append(raw_event_uuid)
            if raw_event_uuid:
                inserted += 1
            else:
                deduped += 1

        target_config = _resolve_target_config(config, target_id)

        schema_fn = OUTPUT_SCHEMAS.get(source_name or pivot_type)
        if schema_fn:
            for i, raw_result in enumerate(results):
                re_id = raw_event_ids[i] if i < len(raw_event_ids) else None
                try:
                    entities, rels = schema_fn(raw_result)
                    for ec in entities:
                        try:
                            eid, is_new = await store.upsert_entity(
                                org_id, target_id,
                                ec.entity_type, ec.value,
                                ec.attributes, raw_event_id=re_id,
                                discovery_session_id=discovery_session_id,
                                discovery_run_id=run_id,
                                discovery_pivot_id=None,
                                parent_entity_id=(
                                    uuid.UUID(entity_id) if entity_id else None
                                ),
                            )

                            if ec.entity_type == "ip":
                                try:
                                    import ipaddress
                                    ip_obj = ipaddress.ip_address(ec.value)
                                    rows = await store.pool.fetch(
                                        "SELECT id, entity_value FROM entities "
                                        "WHERE org_id = $1 AND target_id = $2 "
                                        "AND entity_type = 'ip_range'",
                                        org_id, target_id,
                                    )
                                    for row in rows:
                                        try:
                                            network = ipaddress.ip_network(
                                                row["entity_value"], strict=False,
                                            )
                                            if ip_obj in network:
                                                await store.upsert_relationship(
                                                    org_id, eid, row["id"],
                                                    "ip_in_range",
                                                    "auto_association",
                                                    evidence_raw_event_id=re_id,
                                                    runner=source_name or pivot_type,
                                                )
                                                break
                                        except ValueError:
                                            continue
                                except (asyncpg.PostgresError, ValueError, KeyError) as e:
                                    logger.debug(
                                        "ip range association failed",
                                        exc_info=True, extra={"error": str(e)},
                                    )

                            if ec.entity_type == "ip":
                                try:
                                    from easm.pivot.handlers import GeoIpLookup
                                    lookup = GeoIpLookup()
                                    result = lookup.lookup(ec.value)
                                    if result:
                                        existing = await store.pool.fetchrow(
                                            "SELECT attributes FROM entities WHERE id = $1",
                                            eid,
                                        )
                                        attrs = existing["attributes"] if existing else {}
                                        if isinstance(attrs, str):
                                            attrs = json.loads(attrs)
                                        if not attrs:
                                            attrs = {}
                                        attrs["geo"] = result.to_dict()
                                        await store.pool.execute(
                                            "UPDATE entities SET attributes = $1::jsonb "
                                            "WHERE id = $2",
                                            json.dumps(attrs), eid,
                                        )
                                except (asyncpg.PostgresError, ValueError, KeyError, TypeError) as e:
                                    logger.debug(
                                        "geo enrichment failed",
                                        exc_info=True, extra={"error": str(e)},
                                    )

                            try:
                                source = source_name or pivot_type or "unknown"
                                target_domains = (
                                    list(target_config.match_rules.domains)
                                    if target_config and hasattr(target_config, "match_rules")
                                    else []
                                )
                                target_asns = (
                                    list(target_config.match_rules.asns)
                                    if target_config and hasattr(target_config, "match_rules")
                                    else []
                                )
                                await store.apply_asset_profile_for_entity(
                                    org_id=org_id,
                                    target_id=target_id,
                                    entity_id=eid,
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
                            except (asyncpg.PostgresError, ValueError, KeyError) as e:
                                logger.debug(
                                    "asset profile update from pivot failed",
                                    exc_info=True, extra={"error": str(e)},
                                )

                            if is_new and target_config:
                                try:
                                    await resolver.check_and_enqueue(
                                        target_config,
                                        ec.entity_type, ec.value,
                                        eid,
                                        depth=depth + 1,
                                        parent_entity_id=entity_id,
                                        discovery_session_id=discovery_session_id,
                                    )
                                except (asyncpg.PostgresError, ValueError) as e:
                                    errors += 1
                                    logger.debug(
                                        "recursive pivot failed",
                                        exc_info=True, extra={"error": str(e)},
                                    )
                        except (asyncpg.PostgresError, ValueError, KeyError) as e:
                            errors += 1
                            logger.warning(
                                "entity upsert from pivot failed: type=%s value=%s error=%s",
                                ec.entity_type, ec.value, e,
                            )

                    for rc in rels:
                        try:
                            await store.upsert_relationship_by_value(
                                org_id, target_id,
                                rc.source_type, rc.source_value,
                                rc.target_type, rc.target_value,
                                rc.relationship_type, rc.relationship_source,
                                evidence_raw_event_id=re_id,
                            )
                        except (asyncpg.PostgresError, ValueError) as e:
                            errors += 1
                            logger.warning(
                                "relationship upsert from pivot failed: %s", e,
                            )
                except (ValueError, KeyError, TypeError) as e:
                    errors += 1
                    logger.debug(
                        "output schema failed for pivot result",
                        exc_info=True, extra={"error": str(e)},
                    )

        if errors:
            logger.warning(
                "pivot completed with %d materialization errors", errors,
            )

        # Run correlation engine to generate findings from updated entity attributes
        if not errors:
            try:
                from pathlib import Path
                from easm.correlation.engine import CorrelationEngine
                from easm.correlation.loader import load_rules_from_dir
                _corr_dir = Path(__file__).parent.parent.parent.parent / "correlations"
                if _corr_dir.exists():
                    _rules = load_rules_from_dir(_corr_dir)
                    if _rules:
                        _engine = CorrelationEngine(pool)
                        _findings = await _engine.evaluate_rules(
                            _rules, org_id, target_id,
                        )
                        for _f in _findings:
                            try:
                                await store.create_finding(_f)
                            except (asyncpg.PostgresError, ValueError) as e:
                                logger.debug(
                                    "failed to save correlation finding",
                                    exc_info=True, extra={"error": str(e)},
                                )
            except (asyncpg.PostgresError, ValueError, OSError) as e:
                logger.debug(
                    "correlation engine failed",
                    exc_info=True, extra={"error": str(e)},
                )

        if created_pivot_run and run_id:
            run_end = datetime.now(UTC)
            status = "failed" if errors else "completed"
            await store.mark_run_finished(
                run_id, status, run_end,
                int((run_end - run_start).total_seconds() * 1000),
                inserted, deduped, errors,
                error_message=(
                    f"pivot materialization: {errors} error(s)" if errors else None
                ),
                metadata={
                    "pivot_job_id": job_id,
                    "pivot_type": pivot_type,
                    "entity_value": entity_value,
                    "discovery_session_id": (
                        str(discovery_session_id) if discovery_session_id else None
                    ),
                },
            )

        return {"inserted": inserted, "deduped": deduped, "errors": errors}
    finally:
        await shared_http.aclose()
