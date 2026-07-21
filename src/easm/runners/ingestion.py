from __future__ import annotations

import json
import logging
import uuid
from typing import TYPE_CHECKING, Any

import asyncpg
import tldextract

if TYPE_CHECKING:
    from easm.store import Store

logger = logging.getLogger(__name__)


async def _ensure_seed_entities(
    store: Store,
    target: Any,
    org_id: str,
    run_id: uuid.UUID,
) -> dict[tuple[str, str], uuid.UUID]:
    seed_map: dict[tuple[str, str], uuid.UUID] = {}

    if not hasattr(target, "match_rules"):
        return seed_map

    for domain in target.match_rules.domains or []:
        try:
            eid, _ = await store.upsert_entity(
                org_id, target.id, "domain", domain, {},
                discovery_run_id=run_id,
                parent_entity_id=None,
            )
            seed_map[("domain", domain)] = eid
        except (asyncpg.PostgresError, ValueError) as e:
            logger.debug(
                "failed to create seed domain entity: %s",
                domain, exc_info=True, extra={"error": str(e)},
            )

    for asn in target.match_rules.asns or []:
        try:
            eid, _ = await store.upsert_entity(
                org_id, target.id, "asn", asn, {},
                discovery_run_id=run_id,
                parent_entity_id=None,
            )
            seed_map[("asn", asn)] = eid
        except (asyncpg.PostgresError, ValueError) as e:
            logger.debug(
                "failed to create seed ASN entity: %s",
                asn, exc_info=True, extra={"error": str(e)},
            )

    return seed_map


async def _ingest_entities(
    store: Store,
    output_schema: Any,
    raw: dict,
    run_id: uuid.UUID,
    org_id: str,
    target_id: str,
    target: Any | None = None,
    pool: Any | None = None,
    raw_event_id: uuid.UUID | None = None,
    seed_map: dict[tuple[str, str], uuid.UUID] | None = None,
) -> None:
    ingest_pool = pool or getattr(store, "pool", None)
    _effective_seed_map = seed_map or (getattr(target, "_seed_map", None) if target else None)
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            logger.warning("failed to parse raw event as JSON")
            return
    try:
        entities, relationships = output_schema(raw)
    except (ValueError, KeyError, TypeError) as e:
        logger.exception(
            "output_schema failed",
            extra={"run_id": str(run_id), "error": str(e)},
        )
        return
    discovery_session_id = None
    try:
        run_data = await store.get_run(run_id)
        discovery_session_id = run_data.get("discovery_session_id") if run_data else None
    except (asyncpg.PostgresError, KeyError) as e:
        logger.debug(
            "failed to load discovery session for run",
            exc_info=True, extra={"error": str(e)},
        )

    def _resolve_parent(ec_type: str, ec_value: str, ec_attrs: dict) -> uuid.UUID | None:
        if not _effective_seed_map:
            return None

        if ec_type == "domain":
            if ("domain", ec_value) in _effective_seed_map:
                return None
            return None

        if ec_type == "asn":
            return None

        if ec_type == "hostname":
            ext = tldextract.extract(ec_value)
            registered_domain = f"{ext.domain}.{ext.suffix}"
            parent_id = _effective_seed_map.get(("domain", registered_domain))
            if parent_id:
                return parent_id
            for (etype, eval_), eid in _effective_seed_map.items():
                if etype == "domain" and ec_value.endswith("." + eval_):
                    return eid
            return None

        if ec_type == "certificate":
            san = ec_attrs.get("san_dns_names", [])
            cn = ec_attrs.get("common_name", "")
            candidates: list[str] = []
            if cn:
                candidates.append(cn)
            if isinstance(san, list):
                candidates.extend(san)
            for d in candidates:
                ext = tldextract.extract(d)
                rd = f"{ext.domain}.{ext.suffix}"
                parent_id = _effective_seed_map.get(("domain", rd))
                if parent_id:
                    return parent_id
                for (etype, eval_), eid in _effective_seed_map.items():
                    if etype == "domain" and d.endswith("." + eval_):
                        return eid
            return None

        return None

    for ec in entities:
        try:
            _parent_id = _resolve_parent(ec.entity_type, ec.value, ec.attributes)
            entity_id, is_new = await store.upsert_entity(
                org_id, target_id, ec.entity_type, ec.value,
                ec.attributes, raw_event_id=raw_event_id,
                discovery_session_id=discovery_session_id,
                discovery_run_id=run_id,
                parent_entity_id=_parent_id,
            )
            try:
                source = ec.attributes.get("source") or "unknown"
                target_domains = (
                    list(target.match_rules.domains)
                    if target is not None and hasattr(target, "match_rules")
                    else []
                )
                target_asns = (
                    list(target.match_rules.asns)
                    if target is not None and hasattr(target, "match_rules")
                    else []
                )
                await store.apply_asset_profile_for_entity(
                    org_id=org_id,
                    target_id=target_id,
                    entity_id=entity_id,
                    entity_type=ec.entity_type,
                    entity_value=ec.value,
                    source=source,
                    raw_event_id=raw_event_id,
                    target_domains=target_domains,
                    target_asns=target_asns,
                    summary=f"{source} observed {ec.entity_type} {ec.value}",
                )
            except (asyncpg.PostgresError, ValueError, KeyError, TypeError) as e:
                logger.debug(
                    "asset profile update failed",
                    exc_info=True, extra={"error": str(e)},
                )
            if is_new and target is not None and ingest_pool is not None:
                try:
                    from easm.classify import classify_entity
                    classification = classify_entity(
                        ec.entity_type, ec.value,
                        target_domains=(
                            list(target.match_rules.domains)
                            if hasattr(target, "match_rules")
                            else None
                        ),
                        saas_rules=(
                            target.saas_providers
                            if hasattr(target, "saas_providers")
                            else None
                        ),
                    )
                    if classification.classification != "org-owned":
                        await ingest_pool.execute(
                            "UPDATE entities SET attributes "
                            "= attributes || $1::jsonb WHERE id = $2",
                            json.dumps(classification.to_dict()),
                            entity_id,
                        )
                except (ValueError, KeyError, TypeError, asyncpg.PostgresError) as e:
                    logger.debug(
                        "classification failed for %s",
                        ec.value, exc_info=True, extra={"error": str(e)},
                    )

                try:
                    from easm.pivot.resolver import PivotResolver
                    resolver = PivotResolver(ingest_pool)
                    await resolver.check_and_enqueue(
                        target, ec.entity_type, ec.value, entity_id,
                        depth=1,
                        discovery_session_id=discovery_session_id,
                    )
                except (asyncpg.PostgresError, ValueError) as e:
                    logger.debug(
                        "pivot enqueue failed for %s/%s",
                        ec.entity_type, ec.value,
                        exc_info=True, extra={"error": str(e)},
                    )
        except (asyncpg.PostgresError, ValueError, KeyError) as e:
            logger.exception(
                "entity upsert failed", extra={"error": str(e)},
            )
    for rc in relationships:
        try:
            await store.upsert_relationship_by_value(
                org_id, target_id,
                rc.source_type, rc.source_value,
                rc.target_type, rc.target_value,
                rc.relationship_type, rc.relationship_source,
                evidence_raw_event_id=raw_event_id,
            )
        except (asyncpg.PostgresError, ValueError) as e:
            logger.exception(
                "relationship upsert failed", extra={"error": str(e)},
            )
