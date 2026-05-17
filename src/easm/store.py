from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any, cast

import asyncpg

from easm.correlation.rule import Finding
from easm.entity_store import deep_merge_attributes, normalize_entity_value


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _compute_event_hash(org_id: str, target_id: str, source: str, raw: Any) -> str:
    payload = f"{org_id}:{target_id}:{source}:{_canonical_json(raw)}"
    return hashlib.sha256(payload.encode()).hexdigest()


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
    ) -> bool:
        event_hash = _compute_event_hash(org_id, target_id, source, raw)
        raw_json = json.dumps(raw)
        result = await self.pool.execute(
            """
            INSERT INTO raw_events (org_id, target_id, source, raw, event_hash, run_id)
            VALUES ($1, $2, $3, $4::jsonb, $5, $6)
            ON CONFLICT (event_hash) DO NOTHING
            """,
            org_id,
            target_id,
            source,
            raw_json,
            event_hash,
            run_id,
        )
        return cast(bool, result != "INSERT 0 0")

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
        raw_event_id: uuid.UUID,
        discovery_session_id: uuid.UUID | None = None,
        discovery_run_id: uuid.UUID | None = None,
        discovery_pivot_id: uuid.UUID | None = None,
    ) -> tuple[uuid.UUID, bool]:
        normalized_value = normalize_entity_value(entity_type, entity_value)

        existing = await self.pool.fetchrow(
            """
            SELECT id, attributes FROM entities
            WHERE org_id = $1 AND target_id = $2 AND entity_type = $3 AND entity_value = $4
            """,
            org_id, target_id, entity_type, normalized_value,
        )

        if existing:
            existing_attrs = existing["attributes"]
            if isinstance(existing_attrs, str):
                existing_attrs = json.loads(existing_attrs)
            merged = deep_merge_attributes(existing_attrs, new_attributes)
            await self.pool.execute(
                "UPDATE entities SET last_seen_at = NOW(), attributes = $1::jsonb WHERE id = $2",
                json.dumps(merged), existing["id"],
            )
            await self.pool.execute(
                "INSERT INTO entity_raw_event_links (entity_id, raw_event_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                existing["id"], raw_event_id,
            )
            return existing["id"], False
        else:
            entity_id = await self.pool.fetchval(
                """
                INSERT INTO entities (org_id, target_id, entity_type, entity_value, attributes,
                                      first_seen_at, last_seen_at, is_first_discovery,
                                      discovery_session_id, discovery_run_id, discovery_pivot_id)
                VALUES ($1, $2, $3, $4, $5::jsonb, NOW(), NOW(), TRUE, $6, $7, $8)
                RETURNING id
                """,
                org_id, target_id, entity_type, normalized_value,
                json.dumps(new_attributes),
                discovery_session_id, discovery_run_id, discovery_pivot_id,
            )
            await self.pool.execute(
                "INSERT INTO entity_raw_event_links (entity_id, raw_event_id) VALUES ($1, $2)",
                entity_id, raw_event_id,
            )
            return entity_id, True

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

    # ── Pivot methods ─────────────────────────────────────────────────

    async def enqueue_pivot_job(
        self,
        org_id: str,
        target_id: str,
        entity_type: str,
        entity_value: str,
        entity_id: uuid.UUID,
        pivot_type: str,
        depth: int,
        parent_entity_id: uuid.UUID | None = None,
        discovery_session_id: uuid.UUID | None = None,
        run_id: uuid.UUID | None = None,
    ) -> uuid.UUID:
        row = await self.pool.fetchrow("""
            INSERT INTO pivot_queue (org_id, target_id, entity_type, entity_value, entity_id,
                                      pivot_type, depth, parent_entity_id, discovery_session_id, run_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id
        """, org_id, target_id, entity_type, entity_value, entity_id,
            pivot_type, depth, parent_entity_id, discovery_session_id, run_id)
        return row["id"]

    async def dequeue_pivot_job(self) -> dict[str, Any] | None:
        row = await self.pool.fetchrow("""
            SELECT * FROM pivot_queue
            WHERE status = 'pending'
            ORDER BY enqueued_at
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        """)
        if not row:
            return None
        await self.pool.execute(
            "UPDATE pivot_queue SET status='running', started_at=NOW() WHERE id=$1", row["id"],
        )
        return dict(row)

    async def mark_pivot_completed(self, job_id: uuid.UUID) -> None:
        await self.pool.execute(
            "UPDATE pivot_queue SET status='completed', completed_at=NOW() WHERE id=$1", job_id,
        )

    async def mark_pivot_failed(self, job_id: uuid.UUID, error: str) -> None:
        await self.pool.execute(
            "UPDATE pivot_queue SET status='failed', completed_at=NOW(), error_message=$2 WHERE id=$1",
            job_id, error,
        )

    async def reset_orphaned_pivot_jobs(self) -> None:
        await self.pool.execute(
            "UPDATE pivot_queue SET status='pending' WHERE status='running'",
        )

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
