"""Entity, relationship, and asset-profile persistence.

The ``entities``, ``entity_relationships``, and ``asset_change_events``
tables back this store. Methods cover upsert, deep-merge of attributes,
asset-profile scoring, relationship creation (by id or by value), and
entity lineage traversal.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg

from easm._compat import uuid7
from easm.assets.profile import build_asset_evidence, build_asset_profile, merge_asset_profiles
from easm.assets.scoring import score_asset_exposure
from easm.entity_store import deep_merge_attributes, normalize_entity_value
from easm.stores import BaseStore

logger = logging.getLogger(__name__)


def _asset_profile_attribute_sources(
    attributes: dict[str, Any],
    source: str,
) -> list[str]:
    sources: list[str] = []
    if source and source != "unknown":
        sources.append(source)
    attribute_source = attributes.get("source")
    if isinstance(attribute_source, str):
        if attribute_source != "unknown":
            sources.append(attribute_source)
    elif isinstance(attribute_source, list):
        sources.extend(
            item
            for item in attribute_source
            if isinstance(item, str) and item != "unknown"
        )
    return sources


def _prefer_higher_asset_risk(
    existing: dict[str, Any],
    incoming: dict[str, Any],
) -> dict[str, Any]:
    existing_score = int(existing.get("score", 0) or 0)
    incoming_score = int(incoming.get("score", 0) or 0)
    if incoming_score > existing_score:
        return incoming
    return {
        "score": existing_score,
        "level": existing.get("level", "none"),
        "reasons": list(
            dict.fromkeys(
                [
                    *existing.get("reasons", []),
                    *incoming.get("reasons", []),
                ]
            )
        ),
        **(
            {"confidence_score": incoming["confidence_score"]}
            if "confidence_score" in incoming
            else {}
        ),
    }


def _row_to_asset_change_event_dict(row: asyncpg.Record) -> dict[str, Any]:
    def _fmt(dt: datetime | None) -> str | None:
        return dt.isoformat() if dt else None

    return {
        "id": str(row["id"]),
        "org_id": row["org_id"],
        "target_id": row["target_id"],
        "entity_id": str(row["entity_id"]),
        "change_type": row["change_type"],
        "summary": row["summary"],
        "before_state": _json_field(row["before_state"], {}),
        "after_state": _json_field(row["after_state"], {}),
        "evidence": _json_field(row["evidence"], []),
        "source": row["source"],
        "observed_at": _fmt(row["observed_at"]),
        "created_at": _fmt(row["created_at"]),
    }


def _json_field(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        return json.loads(value)
    return value


class EntityStore(BaseStore):
    """Domain store for entity, relationship, and asset-profile operations."""

    async def upsert_entity(
        self,
        org_id: str,
        target_id: str,
        entity_type: str,
        entity_value: str,
        new_attributes: dict[str, Any],
        raw_event_id: uuid.UUID | None = None,
        discovery_session_id: uuid.UUID | None = None,
        discovery_run_id: uuid.UUID | None = None,
        discovery_pivot_id: uuid.UUID | None = None,
        parent_entity_id: uuid.UUID | None = None,
    ) -> tuple[uuid.UUID, bool]:
        normalized_value = normalize_entity_value(entity_type, entity_value)
        new_attributes.setdefault("triage_state", "discovered")

        # Atomic upsert avoids race condition between SELECT and INSERT.
        result = await self._pool.fetchrow(
            """
            INSERT INTO entities (org_id, target_id, entity_type, entity_value, attributes,
                                  first_seen_at, last_seen_at, is_first_discovery,
                                  discovery_session_id, discovery_run_id, discovery_pivot_id,
                                  parent_entity_id)
            VALUES ($1, $2, $3, $4, $5::jsonb, NOW(), NOW(), TRUE, $6, $7, $8, $9)
            ON CONFLICT (org_id, target_id, entity_type, entity_value) DO UPDATE
            SET last_seen_at = NOW(),
                is_first_discovery = FALSE,
                parent_entity_id = COALESCE(entities.parent_entity_id, EXCLUDED.parent_entity_id)
            RETURNING id, (xmax = 0) AS is_insert
            """,
            org_id, target_id, entity_type, normalized_value,
            json.dumps(new_attributes),
            discovery_session_id, discovery_run_id, discovery_pivot_id,
            parent_entity_id,
        )
        assert result is not None
        entity_id: uuid.UUID = result["id"]
        is_insert: bool = result["is_insert"]

        if not is_insert:
            existing = await self._pool.fetchrow(
                "SELECT attributes FROM entities WHERE id = $1",
                entity_id,
            )
            if existing is not None:
                existing_attrs = existing["attributes"]
                if isinstance(existing_attrs, str):
                    existing_attrs = json.loads(existing_attrs)
                merged = deep_merge_attributes(existing_attrs, new_attributes)
                await self._pool.execute(
                    "UPDATE entities SET attributes = $1::jsonb WHERE id = $2",
                    json.dumps(merged), entity_id,
                )

        if raw_event_id is not None:
            try:
                await self._pool.execute(
                    "INSERT INTO entity_raw_event_links (entity_id, raw_event_id) "
                    "VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    entity_id, raw_event_id,
                )
            except asyncpg.PostgresError as e:
                logger.debug(
                    "raw event link insert skipped for entity %s",
                    entity_id, extra={"error": str(e)},
                )

        return entity_id, is_insert

    async def update_entity_asset_profile(
        self,
        entity_id: uuid.UUID,
        asset_profile: dict[str, Any],
    ) -> None:
        await self._pool.execute(
            """
            UPDATE entities
            SET attributes = jsonb_set(
                COALESCE(attributes, '{}'::jsonb),
                '{asset_profile}',
                $1::jsonb,
                true
            )
            WHERE id = $2
            """,
            json.dumps(asset_profile),
            entity_id,
        )

    async def apply_asset_profile_for_entity(
        self,
        *,
        org_id: str,
        target_id: str,
        entity_id: uuid.UUID,
        entity_type: str,
        entity_value: str,
        source: str,
        raw_event_id: uuid.UUID | None,
        target_domains: list[str],
        target_asns: list[str] | None = None,
        summary: str,
        finding_lookup: Any | None = None,
    ) -> None:
        """Build and persist an asset profile for an entity.

        ``finding_lookup`` is an optional async callable
        ``(target_id, entity_id) -> list[dict]`` used to fetch findings for
        risk scoring. When omitted, findings are looked up against the
        ``findings`` table via the pool.
        """
        row = await self._pool.fetchrow(
            "SELECT attributes FROM entities WHERE id = $1",
            entity_id,
        )
        if row is None:
            return

        attributes = row["attributes"] or {}
        if isinstance(attributes, str):
            attributes = json.loads(attributes)

        observed_at = datetime.now(UTC)
        evidence = build_asset_evidence(
            source=source,
            raw_event_id=str(raw_event_id) if raw_event_id is not None else None,
            observed_at=observed_at,
            summary=summary,
        )
        existing_profile = attributes.get("asset_profile")
        existing_sources = _asset_profile_attribute_sources(attributes, source)
        incoming_profile = build_asset_profile(
            entity_type=entity_type,
            entity_value=entity_value,
            target_domains=target_domains,
            target_asns=target_asns or [],
            sources=existing_sources,
            evidence=[evidence],
            observed_at=observed_at,
        )
        profile = (
            merge_asset_profiles(existing_profile, incoming_profile)
            if isinstance(existing_profile, dict)
            else incoming_profile
        )

        scored_attributes = {**attributes, "asset_profile": profile}
        findings = await self._lookup_findings(finding_lookup, target_id, entity_id)
        risk = score_asset_exposure(
            {
                "type": entity_type,
                "value": entity_value,
                "attributes": scored_attributes,
            },
            findings,
        )
        existing_risk = (
            existing_profile.get("risk", {})
            if isinstance(existing_profile, dict)
            else {}
        )
        profile["risk"] = _prefer_higher_asset_risk(existing_risk, risk)

        await self.update_entity_asset_profile(entity_id, profile)
        await self.record_asset_change_event(
            org_id=org_id,
            target_id=target_id,
            entity_id=entity_id,
            change_type=(
                "asset_observed"
                if isinstance(existing_profile, dict)
                else "asset_discovered"
            ),
            summary=summary,
            before_state=existing_profile if isinstance(existing_profile, dict) else None,
            after_state=profile,
            evidence=[evidence],
            source=source,
            observed_at=observed_at,
        )

    async def _lookup_findings(
        self,
        finding_lookup: Any | None,
        target_id: str,
        entity_id: uuid.UUID,
    ) -> list[dict[str, Any]]:
        if finding_lookup is not None:
            return await finding_lookup(target_id, entity_id)
        try:
            rows = await self._pool.fetch(
                """SELECT * FROM findings
                   WHERE target_id = $1 AND $2 = ANY(entity_ids)
                   ORDER BY created_at DESC""",
                target_id, str(entity_id),
            )
            return [dict(r) for r in rows]
        except (asyncpg.PostgresError, KeyError) as e:
            logger.debug(
                "finding lookup skipped for asset profile",
                exc_info=True, extra={"error": str(e)},
            )
            return []

    async def _findings_for_entity(
        self,
        target_id: str,
        entity_id: uuid.UUID,
    ) -> list[dict[str, Any]]:
        """Legacy internal helper kept for the facade Store._findings_for_entity."""
        return await self._lookup_findings(None, target_id, entity_id)

    async def upsert_relationship(
        self,
        org_id: str,
        source_entity_id: uuid.UUID,
        target_entity_id: uuid.UUID,
        relationship_type: str,
        relationship_source: str,
        evidence_raw_event_id: uuid.UUID | None = None,
        runner: str | None = None,
    ) -> None:
        await self._pool.execute(
            """
            INSERT INTO entity_relationships (org_id, source_entity_id, target_entity_id,
                                             relationship_type, relationship_source,
                                             evidence_raw_event_id, runner)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (org_id, source_entity_id, target_entity_id, relationship_type)
            DO UPDATE SET last_seen_at = NOW()
            """,
            org_id, source_entity_id, target_entity_id,
            relationship_type, relationship_source,
            evidence_raw_event_id, runner,
        )

    async def upsert_relationship_by_value(
        self,
        org_id: str,
        target_id: str,
        source_type: str,
        source_value: str,
        target_type: str,
        target_value: str,
        relationship_type: str,
        relationship_source: str,
        evidence_raw_event_id: uuid.UUID | None = None,
        runner: str | None = None,
    ) -> None:
        """Like :meth:`upsert_relationship` but resolves entity UUIDs by type+value."""
        src = normalize_entity_value(source_type, source_value)
        tgt = normalize_entity_value(target_type, target_value)

        source_row = await self._pool.fetchrow(
            "SELECT id FROM entities "
            "WHERE org_id=$1 AND target_id=$2 "
            "AND entity_type=$3 AND entity_value=$4",
            org_id, target_id, source_type, src,
        )
        target_row = await self._pool.fetchrow(
            "SELECT id FROM entities "
            "WHERE org_id=$1 AND target_id=$2 "
            "AND entity_type=$3 AND entity_value=$4",
            org_id, target_id, target_type, tgt,
        )
        if source_row and target_row:
            await self.upsert_relationship(
                org_id,
                source_row["id"],
                target_row["id"],
                relationship_type,
                relationship_source,
                evidence_raw_event_id=evidence_raw_event_id,
                runner=runner,
            )
        else:
            logger.debug(
                "upsert_relationship_by_value skipped: "
                "source=%s/%s found=%s, target=%s/%s found=%s",
                source_type, src, source_row is not None,
                target_type, tgt, target_row is not None,
            )

    async def record_asset_change_event(
        self,
        target_id: str,
        entity_id: uuid.UUID,
        change_type: str,
        summary: str,
        before_state: dict[str, Any] | None = None,
        after_state: dict[str, Any] | None = None,
        evidence: list[dict[str, Any]] | None = None,
        source: str | None = None,
        observed_at: datetime | None = None,
        org_id: str = "default",
    ) -> uuid.UUID:
        from easm.assets.change import build_asset_change_event

        event = build_asset_change_event(
            change_type=change_type,
            summary=summary,
            before_state=before_state,
            after_state=after_state,
            evidence=evidence,
            source=source,
            observed_at=observed_at,
        )
        row = await self._pool.fetchrow(
            """
            INSERT INTO asset_change_events (
                org_id, target_id, entity_id, change_type, summary, before_state,
                after_state, evidence, source, observed_at
            )
            VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9, $10::timestamptz)
            RETURNING id
            """,
            org_id, target_id, entity_id,
            event["change_type"], event["summary"],
            json.dumps(event["before_state"]),
            json.dumps(event["after_state"]),
            json.dumps(event["evidence"]),
            event["source"],
            datetime.fromisoformat(event["observed_at"]),
        )
        assert row is not None
        return row["id"]

    async def list_asset_change_events(
        self,
        target_id: str | None = None,
        entity_id: uuid.UUID | None = None,
        org_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        offset = max(0, offset)
        conditions: list[str] = []
        params: list[Any] = []
        idx = 0

        if target_id:
            idx += 1
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
        if entity_id:
            idx += 1
            conditions.append(f"entity_id = ${idx}")
            params.append(entity_id)
        if org_id:
            idx += 1
            conditions.append(f"org_id = ${idx}")
            params.append(org_id)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        idx += 1
        idx += 1
        rows = await self._pool.fetch(
            f"""
            SELECT id, org_id, target_id, entity_id, change_type, summary, before_state,
                   after_state, evidence, source, observed_at, created_at
            FROM asset_change_events
            {where}
            ORDER BY observed_at DESC, id DESC
            LIMIT ${idx - 1} OFFSET ${idx}
            """,
            *params, limit, offset,
        )
        return [_row_to_asset_change_event_dict(row) for row in rows]

    async def get_active_scan_targets(
        self,
        org_id: str,
        target_id: str,
        entity_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        type_filter = ""
        if entity_types:
            placeholders = ",".join(f"'{t}'" for t in entity_types)
            type_filter = f"AND entity_type IN ({placeholders})"
        rows = await self._pool.fetch(
            f"""SELECT entity_type, entity_value, attributes
                FROM entities
                WHERE org_id = $1 AND target_id = $2
                  AND attributes->>'triage_state' = 'active'
                  {type_filter}
                ORDER BY last_seen_at DESC""",
            org_id, target_id,
        )
        return [dict(r) for r in rows]

    async def get_entity_lineage(
        self,
        entity_id: uuid.UUID,
        org_id: str,
    ) -> dict[str, Any] | None:
        """Trace discovery lineage via the ``parent_entity_id`` chain.

        Walks the chain up to a bounded depth, joining runs + relationships
        to produce an exact lineage from any asset back to its seed.
        """
        target = await self._pool.fetchrow(
            """
            SELECT e.id, e.entity_type, e.entity_value, e.first_seen_at,
                   e.parent_entity_id, e.discovery_run_id,
                   r.source AS run_source
            FROM entities e
            LEFT JOIN runs r ON r.id = e.discovery_run_id
            WHERE e.id = $1 AND e.org_id = $2
            """,
            entity_id, org_id,
        )
        if target is None:
            return None

        entity_info: dict[str, Any] = {
            "id": str(target["id"]),
            "entity_type": target["entity_type"],
            "entity_value": target["entity_value"],
            "discovered_by": target["run_source"],
            "first_seen_at": (
                target["first_seen_at"].isoformat() if target["first_seen_at"] else None
            ),
        }

        ancestors: list[dict[str, Any]] = []
        child_id: uuid.UUID | None = target["id"]
        current_parent_id = target["parent_entity_id"]
        depth = 0
        max_depth = 20

        while current_parent_id is not None and depth < max_depth:
            parent = await self._pool.fetchrow(
                """
                SELECT e.id, e.entity_type, e.entity_value, e.first_seen_at,
                       e.parent_entity_id, e.discovery_run_id,
                       r.source AS run_source,
                       rel.relationship_type,
                       rel.runner AS relationship_runner
                FROM entities e
                LEFT JOIN runs r ON r.id = e.discovery_run_id
                LEFT JOIN LATERAL (
                    SELECT relationship_type, runner
                    FROM entity_relationships
                    WHERE (source_entity_id = e.id AND target_entity_id = $2)
                       OR (target_entity_id = e.id AND source_entity_id = $2)
                    LIMIT 1
                ) rel ON TRUE
                WHERE e.id = $1
                """,
                current_parent_id, child_id,
            )
            if parent is None:
                break

            depth += 1
            ancestors.append({
                "entity": {
                    "id": str(parent["id"]),
                    "entity_type": parent["entity_type"],
                    "entity_value": parent["entity_value"],
                    "discovered_by": parent["run_source"],
                    "first_seen_at": (
                        parent["first_seen_at"].isoformat()
                        if parent["first_seen_at"] else None
                    ),
                },
                "connects_to_entity_id": str(child_id),
                "relationship": {
                    "type": parent["relationship_type"] or "discovered_by",
                    "runner": parent["relationship_runner"],
                },
                "depth": depth,
            })

            child_id = parent["id"]
            current_parent_id = parent["parent_entity_id"]

        return {"entity": entity_info, "ancestors": ancestors}

    async def count_entities(
        self,
        target_id: str | None = None,
        entity_type: str | None = None,
    ) -> int:
        conditions: list[str] = []
        params: list[Any] = []
        if target_id:
            conditions.append("target_id = $1")
            params.append(target_id)
        if entity_type:
            idx = len(params) + 1
            conditions.append(f"entity_type = ${idx}")
            params.append(entity_type)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        return await self._pool.fetchval(
            f"SELECT COUNT(*) FROM entities {where}", *params,
        ) or 0

    async def migrate_ip_associations(
        self,
        relationship_writer: Any | None = None,
    ) -> dict[str, int]:
        """One-time migration: associate existing IPs with known IP ranges and geo data.

        ``relationship_writer`` is an optional callable
        ``(org_id, ip_id, range_id, rel_type, rel_source) -> None`` used to
        upsert the IP-range relationship. When omitted, falls back to
        :meth:`upsert_relationship`.
        """
        import ipaddress

        from easm.pivot.handlers import GeoIpLookup

        results = {"ip_range_associations": 0, "geo_enrichments": 0}

        ip_ranges = await self._pool.fetch(
            "SELECT id, entity_value FROM entities WHERE entity_type = 'ip_range'"
        )
        range_map = {row["id"]: row["entity_value"] for row in ip_ranges}

        ips = await self._pool.fetch(
            "SELECT id, entity_value, attributes, org_id FROM entities WHERE entity_type = 'ip'"
        )

        for ip_row in ips:
            ip_value = ip_row["entity_value"]
            ip_id = ip_row["id"]
            attrs = ip_row["attributes"]
            if isinstance(attrs, str):
                attrs = json.loads(attrs) if attrs else {}
            elif attrs is None:
                attrs = {}

            for range_id, range_value in range_map.items():
                try:
                    network = ipaddress.ip_network(range_value, strict=False)
                    if ipaddress.ip_address(ip_value) in network:
                        if relationship_writer is not None:
                            await relationship_writer(
                                ip_row["org_id"], ip_id, range_id,
                                "ip_in_range", "retroactive_migration",
                            )
                        else:
                            await self.upsert_relationship(
                                ip_row["org_id"], ip_id, range_id,
                                "ip_in_range", "retroactive_migration",
                            )
                        results["ip_range_associations"] += 1
                        break
                except ValueError:
                    continue

            if "geo" not in attrs:
                try:
                    lookup = GeoIpLookup()
                    result = lookup.lookup(ip_value)
                    if result:
                        attrs["geo"] = result.to_dict()
                        await self._pool.execute(
                            "UPDATE entities SET attributes = $1::jsonb WHERE id = $2",
                            json.dumps(attrs), ip_id,
                        )
                        results["geo_enrichments"] += 1
                except (asyncpg.PostgresError, ValueError, TypeError, KeyError) as e:
                    logger.debug(
                        "geo enrichment skipped during migration for ip %s",
                        ip_value, extra={"error": str(e)},
                    )

        logger.info("migration complete", extra=results)
        return results


# Source-level alias retained so legacy `from easm.store import uuid7` style
# imports continue to resolve once Store delegates here.
_ = uuid7
