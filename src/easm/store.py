from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any, cast

import asyncpg

from easm.assets.change import build_asset_change_event
from easm.assets.profile import (
    build_asset_evidence,
    build_asset_profile,
    merge_asset_profiles,
)
from easm.assets.scoring import score_asset_exposure
from easm.correlation.rule import Finding
from easm.entity_store import deep_merge_attributes, normalize_entity_value

logger = logging.getLogger(__name__)


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _compute_event_hash(org_id: str, target_id: str, source: str, raw: Any) -> str:
    payload = f"{org_id}:{target_id}:{source}:{_canonical_json(raw)}"
    return hashlib.sha256(payload.encode()).hexdigest()


def _asset_profile_attribute_sources(
    attributes: dict[str, Any],
    source: str,
) -> list[str]:
    sources = []
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


class Store:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    async def create_run(
        self,
        target_id: str,
        source: str,
        trigger_type: str,
        scheduled_for: datetime | None = None,
        org_id: str = "default",
    ) -> uuid.UUID:
        discovery_session_id = uuid.uuid7()
        row = await self.pool.fetchrow(
            """
            INSERT INTO runs (org_id, target_id, source, trigger_type, status, scheduled_for, discovery_session_id)
            VALUES ($1, $2, $3, $4, 'pending', $5, $6)
            RETURNING id
            """,
            org_id,
            target_id,
            source,
            trigger_type,
            scheduled_for,
            discovery_session_id,
        )
        assert row is not None
        return cast(uuid.UUID, row["id"])

    async def mark_run_started(self, run_id: uuid.UUID, started_at: datetime) -> None:
        await self.pool.execute(
            "UPDATE runs SET status = 'running', started_at = $1 WHERE id = $2",
            started_at,
            run_id,
        )

    async def mark_run_finished(
        self,
        run_id: uuid.UUID,
        status: str,
        finished_at: datetime,
        duration_ms: int,
        inserted_count: int,
        deduped_count: int,
        error_count: int,
        error_message: str | None = None,
        metadata: dict[str, Any] | None = None,
        logs: str | None = None,
    ) -> None:
        meta = json.dumps(metadata or {})
        await self.pool.execute(
            """
            UPDATE runs
            SET status = $1,
                finished_at = $2,
                duration_ms = $3,
                inserted_count = $4,
                deduped_count = $5,
                error_count = $6,
                error_message = $7,
                metadata = $8::jsonb,
                logs = $9
            WHERE id = $10
            """,
            status,
            finished_at,
            duration_ms,
            inserted_count,
            deduped_count,
            error_count,
            error_message,
            meta,
            logs,
            run_id,
        )

    async def insert_raw_event(
        self, org_id: str, target_id: str, source: str, raw: Any, run_id: uuid.UUID
    ) -> uuid.UUID | None:
        """Insert a raw event. Returns the raw_event UUID on success, or ``None`` on dedup."""
        event_hash = _compute_event_hash(org_id, target_id, source, raw)
        raw_json = json.dumps(raw)
        row = await self.pool.fetchrow(
            """
            INSERT INTO raw_events (org_id, target_id, source, raw, event_hash, run_id)
            VALUES ($1, $2, $3, $4::jsonb, $5, $6)
            ON CONFLICT (event_hash) DO NOTHING
            RETURNING id
            """,
            org_id,
            target_id,
            source,
            raw_json,
            event_hash,
            run_id,
        )
        if row is None:
            return None
        return cast(uuid.UUID, row["id"])

    async def list_events(
        self,
        target_id: str | None = None,
        source: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        limit = max(1, min(limit, 500))
        conditions: list[str] = []
        params: list[Any] = []
        idx = 0

        if cursor:
            idx += 1
            conditions.append(f"id < ${idx}::uuid")
            params.append(cursor)
        if target_id:
            idx += 1
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
        if source:
            idx += 1
            conditions.append(f"source = ${idx}")
            params.append(source)
        if start:
            idx += 1
            conditions.append(f"collected_at >= ${idx}")
            params.append(start)
        if end:
            idx += 1
            conditions.append(f"collected_at <= ${idx}")
            params.append(end)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        idx += 1
        query = f"""
            SELECT id, org_id, target_id, source, collected_at, raw, event_hash, run_id
            FROM raw_events
            {where}
            ORDER BY id DESC
            LIMIT ${idx}
        """
        params.append(limit + 1)

        rows = await self.pool.fetch(query, *params)
        has_more = len(rows) > limit
        results = rows[:limit]

        events = [
            {
                "id": str(r["id"]),
                "org_id": r["org_id"],
                "target_id": r["target_id"],
                "source": r["source"],
                "collected_at": r["collected_at"].isoformat(),
                "raw": json.loads(r["raw"]) if isinstance(r["raw"], str) else r["raw"],
                "event_hash": r["event_hash"],
                "run_id": str(r["run_id"]),
            }
            for r in results
        ]

        next_cursor = str(results[-1]["id"]) if has_more and results else None
        return events, next_cursor

    async def get_event(self, event_id: uuid.UUID) -> dict[str, Any] | None:
        row = await self.pool.fetchrow(
            "SELECT id, org_id, target_id, source, collected_at, raw, event_hash, run_id "
            "FROM raw_events WHERE id = $1",
            event_id,
        )
        if row is None:
            return None
        return {
            "id": str(row["id"]),
            "org_id": row["org_id"],
            "target_id": row["target_id"],
            "source": row["source"],
            "collected_at": row["collected_at"].isoformat(),
            "raw": json.loads(row["raw"]) if isinstance(row["raw"], str) else row["raw"],
            "event_hash": row["event_hash"],
            "run_id": str(row["run_id"]),
        }

    async def count_active_runs(self, target_id: str, source_name: str) -> int:
        """Count runs that are still in progress for a given target and source."""
        row = await self.pool.fetchval(
            """
            SELECT COUNT(*) FROM runs
            WHERE target_id = $1 AND source = $2 AND status = 'running'
            """,
            target_id,
            source_name,
        )
        return row or 0

    async def list_runs(
        self,
        target_id: str | None = None,
        source: str | None = None,
        status: str | None = None,
        trigger_type: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        conditions: list[str] = []
        params: list[Any] = []
        idx = 0

        if target_id:
            idx += 1
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
        if source:
            idx += 1
            conditions.append(f"source = ${idx}")
            params.append(source)
        if status:
            idx += 1
            conditions.append(f"status = ${idx}")
            params.append(status)
        if trigger_type:
            idx += 1
            conditions.append(f"trigger_type = ${idx}")
            params.append(trigger_type)
        if start:
            idx += 1
            conditions.append(f"started_at >= ${idx}")
            params.append(start)
        if end:
            idx += 1
            conditions.append(f"started_at <= ${idx}")
            params.append(end)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        idx += 1
        idx += 1
        query = f"""
            SELECT id, target_id, source, trigger_type, status, scheduled_for,
                   started_at, finished_at, duration_ms, inserted_count,
                   deduped_count, error_count, error_message, metadata,
                   discovery_session_id, new_entity_count, total_entity_count, logs
            FROM runs
            {where}
            ORDER BY started_at DESC NULLS LAST
            LIMIT ${idx - 1} OFFSET ${idx}
        """
        params.extend([limit, offset])
        rows = await self.pool.fetch(query, *params)
        return [_row_to_run_dict(r) for r in rows]

    async def get_run(self, run_id: uuid.UUID) -> dict[str, Any] | None:
        row = await self.pool.fetchrow(
            """
            SELECT id, target_id, source, trigger_type, status, scheduled_for,
                   started_at, finished_at, duration_ms, inserted_count,
                   deduped_count, error_count, error_message, metadata,
                   discovery_session_id, new_entity_count, total_entity_count, logs
            FROM runs WHERE id = $1
            """,
            run_id,
        )
        if row is None:
            return None
        return _row_to_run_dict(row)

    async def save_config_snapshot(self, raw_config: dict[str, Any]) -> None:
        raw_json = _canonical_json(raw_config)
        config_hash = hashlib.sha256(raw_json.encode()).hexdigest()
        await self.pool.execute(
            """
            INSERT INTO config_snapshots (config_hash, raw_config)
            VALUES ($1, $2::jsonb)
            ON CONFLICT (config_hash) DO NOTHING
            """,
            config_hash,
            json.dumps(raw_config),
        )

    # ── Entity methods ────────────────────────────────────────────────

    async def upsert_entity(
        self,
        org_id: str,
        target_id: str,
        entity_type: str,
        entity_value: str,
        new_attributes: dict,
        raw_event_id: uuid.UUID | None = None,
        discovery_session_id: uuid.UUID | None = None,
        discovery_run_id: uuid.UUID | None = None,
        discovery_pivot_id: uuid.UUID | None = None,
    ) -> tuple[uuid.UUID, bool]:
        normalized_value = normalize_entity_value(entity_type, entity_value)
        new_attributes.setdefault("triage_state", "discovered")

        # Use atomic upsert to avoid race condition between SELECT and INSERT
        result = await self.pool.fetchrow(
            """
            INSERT INTO entities (org_id, target_id, entity_type, entity_value, attributes,
                                  first_seen_at, last_seen_at, is_first_discovery,
                                  discovery_session_id, discovery_run_id, discovery_pivot_id)
            VALUES ($1, $2, $3, $4, $5::jsonb, NOW(), NOW(), TRUE, $6, $7, $8)
            ON CONFLICT (org_id, target_id, entity_type, entity_value) DO UPDATE
            SET last_seen_at = NOW(),
                is_first_discovery = FALSE
            RETURNING id, (xmax = 0) AS is_insert
            """,
            org_id, target_id, entity_type, normalized_value,
            json.dumps(new_attributes),
            discovery_session_id, discovery_run_id, discovery_pivot_id,
        )

        entity_id = result["id"]
        is_insert = result["is_insert"]

        if not is_insert:
            # Merge attributes for existing entity
            existing = await self.pool.fetchrow(
                "SELECT attributes FROM entities WHERE id = $1",
                entity_id,
            )
            if existing:
                existing_attrs = existing["attributes"]
                if isinstance(existing_attrs, str):
                    existing_attrs = json.loads(existing_attrs)
                merged = deep_merge_attributes(existing_attrs, new_attributes)
                await self.pool.execute(
                    "UPDATE entities SET attributes = $1::jsonb WHERE id = $2",
                    json.dumps(merged), entity_id,
                )

        if raw_event_id is not None:
            try:
                await self.pool.execute(
                    "INSERT INTO entity_raw_event_links (entity_id, raw_event_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    entity_id, raw_event_id,
                )
            except Exception:
                logger.debug("raw event link insert skipped for entity %s", entity_id)

        return entity_id, is_insert

    async def update_entity_asset_profile(
        self,
        entity_id: uuid.UUID,
        asset_profile: dict[str, Any],
    ) -> None:
        await self.pool.execute(
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
    ) -> None:
        row = await self.pool.fetchrow(
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
        findings = await self._findings_for_entity(target_id, entity_id)
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

    async def _findings_for_entity(
        self,
        target_id: str,
        entity_id: uuid.UUID,
    ) -> list[dict[str, Any]]:
        try:
            findings = await self.list_findings(target_id=target_id, limit=200)
        except Exception:
            logger.debug("finding lookup skipped for asset profile", exc_info=True)
            return []

        entity_id_text = str(entity_id)
        matched: list[dict[str, Any]] = []
        for finding in findings:
            entity_ids = finding.get("entity_ids") or []
            if entity_id_text not in [str(value) for value in entity_ids]:
                continue
            if "severity" not in finding and "risk" in finding:
                finding = {**finding, "severity": finding.get("risk")}
            matched.append(finding)
        return matched

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
        await self.pool.execute(
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

        source_row = await self.pool.fetchrow(
            "SELECT id FROM entities "
            "WHERE org_id=$1 AND target_id=$2 "
            "AND entity_type=$3 AND entity_value=$4",
            org_id, target_id, source_type, src,
        )
        target_row = await self.pool.fetchrow(
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
            import logging as _logging
            _logging.getLogger(__name__).debug(
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
        event = build_asset_change_event(
            change_type=change_type,
            summary=summary,
            before_state=before_state,
            after_state=after_state,
            evidence=evidence,
            source=source,
            observed_at=observed_at,
        )
        row = await self.pool.fetchrow(
            """
            INSERT INTO asset_change_events (
                org_id, target_id, entity_id, change_type, summary, before_state,
                after_state, evidence, source, observed_at
            )
            VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9, $10::timestamptz)
            RETURNING id
            """,
            org_id,
            target_id,
            entity_id,
            event["change_type"],
            event["summary"],
            json.dumps(event["before_state"]),
            json.dumps(event["after_state"]),
            json.dumps(event["evidence"]),
            event["source"],
            datetime.fromisoformat(event["observed_at"]),
        )
        assert row is not None
        return cast(uuid.UUID, row["id"])

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
        rows = await self.pool.fetch(
            f"""
            SELECT id, org_id, target_id, entity_id, change_type, summary, before_state,
                   after_state, evidence, source, observed_at, created_at
            FROM asset_change_events
            {where}
            ORDER BY observed_at DESC, id DESC
            LIMIT ${idx - 1} OFFSET ${idx}
            """,
            *params,
            limit,
            offset,
        )
        return [_row_to_asset_change_event_dict(row) for row in rows]

    async def list_asset_inventory(
        self,
        target_id: str | None = None,
        confidence_level: str | None = None,
        risk_level: str | None = None,
        feed_eligible: bool | None = None,
        limit: int = 100,
        offset: int = 0,
        org_id: str = "default",
    ) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        offset = max(0, offset)
        conditions = ["org_id = $1", "attributes ? 'asset_profile'"]
        params: list[Any] = [org_id]
        idx = 2

        if target_id:
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
            idx += 1
        if confidence_level:
            conditions.append(f"attributes #>> '{{asset_profile,confidence,level}}' = ${idx}")
            params.append(confidence_level)
            idx += 1
        if risk_level:
            conditions.append(f"attributes #>> '{{asset_profile,risk,level}}' = ${idx}")
            params.append(risk_level)
            idx += 1
        if feed_eligible is not None:
            conditions.append(
                "COALESCE("
                "(attributes #>> '{asset_profile,source_of_truth_feed,eligible}')::boolean, "
                "(attributes #>> '{asset_profile,feed,eligible}')::boolean, "
                "false"
                ") "
                f"= ${idx}"
            )
            params.append(feed_eligible)
            idx += 1

        params.extend([limit, offset])
        rows = await self.pool.fetch(
            f"""
            SELECT
                id AS entity_id,
                org_id,
                target_id,
                entity_type,
                entity_value,
                first_seen_at,
                last_seen_at,
                (attributes #>> '{{asset_profile,confidence,score}}')::numeric AS confidence_score,
                attributes #>> '{{asset_profile,confidence,level}}' AS confidence_level,
                (attributes #>> '{{asset_profile,risk,score}}')::numeric AS risk_score,
                attributes #>> '{{asset_profile,risk,level}}' AS risk_level,
                COALESCE(
                    (attributes #>> '{{asset_profile,source_of_truth_feed,eligible}}')::boolean,
                    (attributes #>> '{{asset_profile,feed,eligible}}')::boolean,
                    false
                ) AS feed_eligible,
                attributes #> '{{asset_profile,sources}}' AS sources,
                jsonb_array_length(COALESCE(attributes #> '{{asset_profile,evidence}}', '[]'::jsonb)) AS evidence_count
            FROM entities
            WHERE {' AND '.join(conditions)}
            ORDER BY
                CASE attributes #>> '{{asset_profile,risk,level}}'
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                    ELSE 6
                END,
                (attributes #>> '{{asset_profile,confidence,score}}')::numeric DESC NULLS LAST,
                last_seen_at DESC NULLS LAST,
                id DESC
            LIMIT ${idx} OFFSET ${idx + 1}
            """,
            *params,
        )
        return [_row_to_asset_inventory_dict(row) for row in rows]

    async def get_triage_inbox(
        self,
        org_id: str,
        target_id: str | None = None,
        entity_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        where_clauses = ["e.org_id = $1", "e.attributes->>'triage_state' = 'discovered'"]
        params: list[Any] = [org_id]
        idx = 2
        if target_id:
            where_clauses.append(f"e.target_id = ${idx}")
            params.append(target_id)
            idx += 1
        if entity_type:
            where_clauses.append(f"e.entity_type = ${idx}")
            params.append(entity_type)
            idx += 1
        params.append(limit)
        params.append(offset)
        rows = await self.pool.fetch(
            f"""SELECT e.*, count(*) OVER() as total_count
                FROM entities e
                WHERE {' AND '.join(where_clauses)}
                ORDER BY e.first_seen_at DESC
                LIMIT ${idx} OFFSET ${idx + 1}""",
            *params,
        )
        return [dict(r) for r in rows]

    async def set_entity_triage_state(
        self,
        org_id: str,
        entity_id: uuid.UUID,
        triage_state: str,
    ) -> bool:
        valid_states = {"discovered", "adopted", "dismissed", "active"}
        if triage_state not in valid_states:
            return False
        result = await self.pool.execute(
            """UPDATE entities SET attributes = jsonb_set(attributes, '{triage_state}', $1::jsonb)
               WHERE org_id = $2 AND id = $3""",
            json.dumps(triage_state), org_id, entity_id,
        )
        return result.endswith("1")

    async def get_active_scan_targets(
        self,
        org_id: str,
        target_id: str,
        entity_types: list[str] | None = None,
    ) -> list[dict]:
        type_filter = ""
        if entity_types:
            placeholders = ",".join(f"'{t}'" for t in entity_types)
            type_filter = f"AND entity_type IN ({placeholders})"
        rows = await self.pool.fetch(
            f"""SELECT entity_type, entity_value, attributes
                FROM entities
                WHERE org_id = $1 AND target_id = $2
                  AND attributes->>'triage_state' = 'active'
                  {type_filter}
                ORDER BY last_seen_at DESC""",
            org_id, target_id,
        )
        return [dict(r) for r in rows]

    # ── Pivot methods ─────────────────────────────────────────────────
    # (removed — pivots now use Procrastinate tasks)

    async def count_runs(
        self,
        target_id: str | None = None,
        source: str | None = None,
        status: str | None = None,
        trigger_type: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> int:
        conditions: list[str] = []
        params: list[Any] = []
        idx = 0
        if target_id:
            idx += 1
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
        if source:
            idx += 1
            conditions.append(f"source = ${idx}")
            params.append(source)
        if status:
            idx += 1
            conditions.append(f"status = ${idx}")
            params.append(status)
        if trigger_type:
            idx += 1
            conditions.append(f"trigger_type = ${idx}")
            params.append(trigger_type)
        if start:
            idx += 1
            conditions.append(f"started_at >= ${idx}")
            params.append(start)
        if end:
            idx += 1
            conditions.append(f"started_at <= ${idx}")
            params.append(end)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        return await self.pool.fetchval(
            f"SELECT COUNT(*) FROM runs {where}", *params,
        ) or 0

    async def count_findings(
        self,
        target_id: str | None = None,
        risk: str | None = None,
        status: str | None = None,
        rule_id: str | None = None,
    ) -> int:
        conditions: list[str] = []
        params: list[Any] = []
        idx = 0
        if target_id:
            idx += 1
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
        if risk:
            idx += 1
            conditions.append(f"risk = ${idx}")
            params.append(risk)
        if status:
            idx += 1
            conditions.append(f"status = ${idx}")
            params.append(status)
        if rule_id:
            idx += 1
            conditions.append(f"rule_id = ${idx}")
            params.append(rule_id)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        return await self.pool.fetchval(
            f"SELECT COUNT(*) FROM findings {where}", *params,
        ) or 0

    async def count_events(
        self,
        target_id: str | None = None,
        source: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> int:
        conditions: list[str] = []
        params: list[Any] = []
        idx = 0
        if target_id:
            idx += 1
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
        if source:
            idx += 1
            conditions.append(f"source = ${idx}")
            params.append(source)
        if start:
            idx += 1
            conditions.append(f"collected_at >= ${idx}")
            params.append(start)
        if end:
            idx += 1
            conditions.append(f"collected_at <= ${idx}")
            params.append(end)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        return await self.pool.fetchval(
            f"SELECT COUNT(*) FROM raw_events {where}", *params,
        ) or 0

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
        return await self.pool.fetchval(
            f"SELECT COUNT(*) FROM entities {where}", *params,
        ) or 0

    # ── Finding methods ───────────────────────────────────────────────

    async def create_finding(self, finding: Finding) -> uuid.UUID:
        row = await self.pool.fetchrow(
            """
            INSERT INTO findings (org_id, target_id, rule_id, risk, headline, description,
                                  entity_ids, evidence, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7::uuid[], $8::jsonb, $9)
            RETURNING id
            """,
            finding.org_id,
            finding.target_id,
            finding.rule_id,
            finding.risk.value if hasattr(finding.risk, "value") else finding.risk,
            finding.headline,
            finding.description,
            [uuid.UUID(eid) for eid in finding.entity_ids],
            json.dumps(finding.evidence),
            finding.status,
        )
        assert row is not None
        return cast(uuid.UUID, row["id"])

    async def list_findings(
        self,
        target_id: str | None = None,
        risk: str | None = None,
        status: str | None = None,
        rule_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        conditions: list[str] = []
        params: list[Any] = []
        idx = 0

        if target_id:
            idx += 1
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
        if risk:
            idx += 1
            conditions.append(f"risk = ${idx}")
            params.append(risk)
        if status:
            idx += 1
            conditions.append(f"status = ${idx}")
            params.append(status)
        if rule_id:
            idx += 1
            conditions.append(f"rule_id = ${idx}")
            params.append(rule_id)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        idx += 1
        idx += 1
        query = f"""
            SELECT id, org_id, target_id, rule_id, risk, headline, description,
                   entity_ids, evidence, status, first_seen_at, last_seen_at, created_at
            FROM findings
            {where}
            ORDER BY risk DESC, created_at DESC
            LIMIT ${idx - 1} OFFSET ${idx}
        """
        params.extend([limit, offset])
        rows = await self.pool.fetch(query, *params)
        return [_row_to_finding_dict(r) for r in rows]

    async def get_finding(self, finding_id: uuid.UUID) -> dict[str, Any] | None:
        row = await self.pool.fetchrow(
            """SELECT id, org_id, target_id, rule_id, risk, headline, description,
                      entity_ids, evidence, status, first_seen_at, last_seen_at, created_at
               FROM findings WHERE id = $1""",
            finding_id,
        )
        if row is None:
            return None
        return _row_to_finding_dict(row)

    async def update_finding_status(self, finding_id: uuid.UUID, status: str) -> None:
        await self.pool.execute(
            "UPDATE findings SET status = $1, last_seen_at = NOW() WHERE id = $2",
            status,
            finding_id,
        )

    async def acknowledge_finding(self, finding_id: uuid.UUID) -> None:
        await self.update_finding_status(finding_id, "acknowledged")

    async def list_certificate_inventory(
        self,
        target_id: str | None = None,
        org_id: str = "default",
        deployment_state: str | None = None,
        risk: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        conditions = ["org_id = $1", "entity_type = 'certificate'"]
        params: list[Any] = [org_id]
        idx = 2

        if target_id:
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
            idx += 1
        if deployment_state:
            conditions.append(
                "COALESCE("
                "attributes #>> '{certificate_profile,analysis,deployment_state}', "
                "attributes #>> '{certificate_profile,deployment,state}'"
                f") = ${idx}"
            )
            params.append(deployment_state)
            idx += 1
        if risk:
            conditions.append(f"attributes #>> '{{certificate_profile,analysis,risk}}' = ${idx}")
            params.append(risk)
            idx += 1

        params.extend([limit, offset])
        rows = await self.pool.fetch(
            f"""
            SELECT
                id AS entity_id,
                attributes #>> '{{certificate_profile,fingerprint_sha256}}' AS fingerprint_sha256,
                COALESCE(
                    attributes #>> '{{certificate_profile,subject,common_name}}',
                    (attributes #> '{{certificate_profile,san_dns_names}}'->>0)
                ) AS subject_cn,
                attributes #> '{{certificate_profile,san_dns_names}}' AS san_dns_names,
                CASE
                    WHEN attributes #>> '{{certificate_profile,subject,common_name}}' IS NOT NULL THEN 'cn'
                    ELSE 'san'
                END AS subject_source,
                attributes #>> '{{certificate_profile,issuer,organization}}' AS issuer_organization,
                attributes #>> '{{certificate_profile,not_before}}' AS not_before,
                attributes #>> '{{certificate_profile,not_after}}' AS not_after,
                attributes #>> '{{certificate_profile,analysis,validity_state}}' AS validity_state,
                COALESCE(
                    attributes #>> '{{certificate_profile,analysis,deployment_state}}',
                    attributes #>> '{{certificate_profile,deployment,state}}'
                ) AS deployment_state,
                attributes #> '{{certificate_profile,deployment,observed_endpoints}}' AS observed_endpoints,
                attributes #>> '{{certificate_profile,analysis,risk}}' AS risk,
                attributes #> '{{certificate_profile,analysis,reasons}}' AS reasons,
                attributes #>> '{{certificate_profile,analysis,strength}}' AS strength
            FROM entities
            WHERE {' AND '.join(conditions)}
            ORDER BY
                CASE attributes #>> '{{certificate_profile,analysis,risk}}'
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                    ELSE 6
                END,
                (attributes #>> '{{certificate_profile,not_after}}') ASC NULLS LAST
            LIMIT ${idx} OFFSET ${idx + 1}
            """,
            *params,
        )
        return [_row_to_certificate_inventory_dict(row) for row in rows]

    async def summarize_certificate_inventory(
        self,
        target_id: str | None = None,
        org_id: str = "default",
    ) -> dict[str, Any]:
        conditions = ["org_id = $1", "entity_type = 'certificate'"]
        params: list[Any] = [org_id]
        if target_id:
            conditions.append("target_id = $2")
            params.append(target_id)

        rows = await self.pool.fetch(
            f"""
            SELECT
                attributes #>> '{{certificate_profile,analysis,risk}}' AS risk,
                COALESCE(
                    attributes #>> '{{certificate_profile,analysis,deployment_state}}',
                    attributes #>> '{{certificate_profile,deployment,state}}'
                ) AS deployment_state,
                attributes #>> '{{certificate_profile,issuer,organization}}' AS issuer_organization
            FROM entities
            WHERE {' AND '.join(conditions)}
            """,
            *params,
        )

        summary: dict[str, Any] = {
            "total": len(rows),
            "by_risk": {},
            "by_deployment_state": {},
            "by_issuer_organization": {},
        }
        for row in rows:
            for source_key, summary_key in (
                ("risk", "by_risk"),
                ("deployment_state", "by_deployment_state"),
                ("issuer_organization", "by_issuer_organization"),
            ):
                value = row[source_key] or "unknown"
                summary[summary_key][value] = summary[summary_key].get(value, 0) + 1
        return summary


def _row_to_finding_dict(row: asyncpg.Record) -> dict[str, Any]:
    def _fmt(dt: datetime | None) -> str | None:
        return dt.isoformat() if dt else None

    return {
        "id": str(row["id"]),
        "org_id": row["org_id"],
        "target_id": row["target_id"],
        "rule_id": row["rule_id"],
        "risk": row["risk"],
        "headline": row["headline"],
        "description": row["description"],
        "entity_ids": [str(eid) for eid in row["entity_ids"]] if row["entity_ids"] else [],
        "evidence": row["evidence"] if isinstance(row["evidence"], dict) else {},
        "status": row["status"],
        "first_seen_at": _fmt(row["first_seen_at"]),
        "last_seen_at": _fmt(row["last_seen_at"]),
        "created_at": _fmt(row["created_at"]),
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


def _row_to_asset_inventory_dict(row: asyncpg.Record) -> dict[str, Any]:
    def _fmt(dt: datetime | None) -> str | None:
        return dt.isoformat() if dt else None

    confidence_score = row["confidence_score"]
    risk_score = row["risk_score"]
    return {
        "entity_id": str(row["entity_id"]),
        "org_id": row["org_id"],
        "target_id": row["target_id"],
        "entity_type": row["entity_type"],
        "entity_value": row["entity_value"],
        "first_seen_at": _fmt(row["first_seen_at"]),
        "last_seen_at": _fmt(row["last_seen_at"]),
        "confidence_score": float(confidence_score) if confidence_score is not None else None,
        "confidence_level": row["confidence_level"],
        "risk_score": float(risk_score) if risk_score is not None else None,
        "risk_level": row["risk_level"],
        "feed_eligible": row["feed_eligible"],
        "sources": _json_field(row["sources"], []),
        "evidence_count": row["evidence_count"],
    }




def _json_field(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        return json.loads(value)
    return value


def _row_to_certificate_inventory_dict(row: asyncpg.Record) -> dict[str, Any]:
    return {
        "entity_id": str(row["entity_id"]),
        "fingerprint_sha256": row["fingerprint_sha256"],
        "subject_cn": row["subject_cn"],
        "issuer_organization": row["issuer_organization"],
        "not_before": row["not_before"],
        "not_after": row["not_after"],
        "validity_state": row["validity_state"],
        "deployment_state": row["deployment_state"],
        "observed_endpoints": _json_field(row["observed_endpoints"], []),
        "risk": row["risk"],
        "reasons": _json_field(row["reasons"], []),
        "strength": row["strength"],
        "san_dns_names": _json_field(row["san_dns_names"], []),
        "subject_source": row["subject_source"],
    }


def _row_to_run_dict(row: asyncpg.Record) -> dict[str, Any]:
    def _fmt(dt: datetime | None) -> str | None:
        return dt.isoformat() if dt else None

    return {
        "id": str(row["id"]),
        "target_id": row["target_id"],
        "source": row["source"],
        "trigger_type": row["trigger_type"],
        "status": row["status"],
        "scheduled_for": _fmt(row["scheduled_for"]),
        "started_at": _fmt(row["started_at"]),
        "finished_at": _fmt(row["finished_at"]),
        "duration_ms": row["duration_ms"],
        "inserted_count": row["inserted_count"],
        "deduped_count": row["deduped_count"],
        "error_count": row["error_count"],
        "error_message": row["error_message"],
        "discovery_session_id": str(row["discovery_session_id"]) if row["discovery_session_id"] else None,
        "new_entity_count": row["new_entity_count"],
        "total_entity_count": row["total_entity_count"],
        "metadata": (
            json.loads(row["metadata"])
            if isinstance(row["metadata"], str)
            else row["metadata"]
        ),
        "logs": row["logs"],
    }


def _findings_row_to_dict(row: asyncpg.Record) -> dict[str, Any]:
    def _fmt(dt: datetime | None) -> str | None:
        return dt.isoformat() if dt else None

    return {
        "id": str(row["id"]),
        "org_id": row["org_id"],
        "target_id": row["target_id"],
        "rule_id": row["rule_id"],
        "risk": row["risk"],
        "headline": row["headline"],
        "description": row["description"],
        "entity_ids": [str(eid) for eid in row["entity_ids"]] if row["entity_ids"] else [],
        "evidence": row["evidence"] if isinstance(row["evidence"], dict) else {},
        "status": row["status"],
        "first_seen_at": _fmt(row["first_seen_at"]),
        "last_seen_at": _fmt(row["last_seen_at"]),
        "created_at": _fmt(row["created_at"]),
    }


async def migrate_ip_associations(self) -> dict[str, int]:
        """One-time migration: associate existing IPs with known IP ranges and geo data."""
        import ipaddress
        from easm.pivot.handlers import GeoIpLookup

        results = {"ip_range_associations": 0, "geo_enrichments": 0}

        ip_ranges = await self.pool.fetch(
            "SELECT id, entity_value FROM entities WHERE entity_type = 'ip_range'"
        )
        range_map = {row["id"]: row["entity_value"] for row in ip_ranges}

        ips = await self.pool.fetch("SELECT id, entity_value, attributes, org_id FROM entities WHERE entity_type = 'ip'")

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
                        await self.upsert_relationship(
                            ip_row["org_id"],
                            ip_id,
                            range_id,
                            "ip_in_range",
                            "retroactive_migration",
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
                        await self.pool.execute(
                            "UPDATE entities SET attributes = $1::jsonb WHERE id = $2",
                            json.dumps(attrs), ip_id,
                        )
                        results["geo_enrichments"] += 1
                except Exception:
                    pass

        logger.info("migration complete", extra=results)
        return results
