from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

from easm.entity_store import normalize_entity_value, upsert_entity, upsert_relationship
from easm.parse import PARSER_REGISTRY


async def backfill_worker(
    pool,
    cfg: Any,
    batch_size: int = 100,
    batch_interval_ms: int = 500,
):
    while True:
        rows = await pool.fetch("""
            SELECT id, org_id, target_id, source, raw, run_id
            FROM raw_events
            WHERE parsed_at IS NULL
            ORDER BY collected_at
            LIMIT $1
        """, batch_size)

        if not rows:
            await asyncio.sleep(batch_interval_ms / 1000)
            continue

        for row in rows:
            raw = json.loads(row["raw"]) if isinstance(row["raw"], str) else row["raw"]
            parser_cls = PARSER_REGISTRY.get(row["source"])
            if not parser_cls:
                await pool.execute(
                    "UPDATE raw_events SET parsed_at = NOW(), parsed_by = $1, parse_error = $2 WHERE id = $3",
                    "unknown:1", f"no parser for source {row['source']}", row["id"],
                )
                continue

            parser = parser_cls()
            result = await parser.parse({"raw": raw, "target_id": row["target_id"], "run_id": row["run_id"]})

            if result.unparseable:
                await pool.execute(
                    "UPDATE raw_events SET parsed_at = NOW(), parsed_by = $1, parse_error = $2 WHERE id = $3",
                    parser.parsed_by, result.parse_error, row["id"],
                )
                continue

            is_pivot_event = "_meta" in raw
            session_id = raw.get("_meta", {}).get("session_id")
            pivot_job_id_str = raw.get("_meta", {}).get("pivot_job_id")

            discovery_run_id = row["run_id"] if not is_pivot_event else None
            discovery_pivot_id = None
            if is_pivot_event and pivot_job_id_str:
                try:
                    discovery_pivot_id = uuid.UUID(pivot_job_id_str)
                except (ValueError, AttributeError):
                    discovery_pivot_id = None

            for entity_cand in result.entities:
                await upsert_entity(
                    pool,
                    org_id=row["org_id"],
                    target_id=row["target_id"],
                    entity_type=entity_cand.entity_type,
                    entity_value=entity_cand.value,
                    new_attributes=entity_cand.attributes,
                    raw_event_id=row["id"],
                    discovery_session_id=uuid.UUID(session_id) if session_id else None,
                    discovery_run_id=discovery_run_id,
                    discovery_pivot_id=discovery_pivot_id,
                )

            for rel_cand in result.relationships:
                src_norm = normalize_entity_value(rel_cand.source_type, rel_cand.source_value)
                tgt_norm = normalize_entity_value(rel_cand.target_type, rel_cand.target_value)
                src_row = await pool.fetchrow(
                    "SELECT id FROM entities WHERE org_id=$1 AND target_id=$2 AND entity_type=$3 AND entity_value=$4",
                    row["org_id"], row["target_id"], rel_cand.source_type, src_norm,
                )
                tgt_row = await pool.fetchrow(
                    "SELECT id FROM entities WHERE org_id=$1 AND target_id=$2 AND entity_type=$3 AND entity_value=$4",
                    row["org_id"], row["target_id"], rel_cand.target_type, tgt_norm,
                )
                if src_row and tgt_row:
                    await upsert_relationship(
                        pool,
                        org_id=row["org_id"],
                        source_entity_id=src_row["id"],
                        target_entity_id=tgt_row["id"],
                        relationship_type=rel_cand.relationship_type,
                        relationship_source=rel_cand.relationship_source,
                        evidence_raw_event_id=row["id"],
                        runner=rel_cand.runner,
                    )

            await pool.execute(
                "UPDATE raw_events SET parsed_at = NOW(), parsed_by = $1 WHERE id = $2",
                parser.parsed_by, row["id"],
            )

        await asyncio.sleep(batch_interval_ms / 1000)
