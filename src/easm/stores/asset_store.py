"""Asset inventory persistence.

Backed by the ``entities`` table filtered to rows that carry an
``asset_profile`` attribute. Provides the inventory list endpoint plus
NDJSON export helpers used by the reports pipeline.
"""

from __future__ import annotations

import datetime as _dt
import json
from typing import Any

import asyncpg

from easm.stores import BaseStore


def _json_field(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        return json.loads(value)
    return value


def _row_to_asset_inventory_dict(row: asyncpg.Record) -> dict[str, Any]:
    def _fmt(dt: _dt.datetime | None) -> str | None:
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


class AssetStore(BaseStore):
    """Read-side inventory over entities that have an asset profile."""

    async def list_asset_inventory(
        self,
        target_id: str | None = None,
        confidence_level: str | None = None,
        risk_level: str | None = None,
        feed_eligible: bool | None = None,
        limit: int = 100,
        offset: int = 0,
        org_id: str = "default",
    ) -> dict[str, Any]:
        limit = max(1, min(limit, 5000))
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
        rows = await self._pool.fetch(
            f"""
            SELECT
                COUNT(*) OVER() AS total_count,
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
        total_count = rows[0]["total_count"] if rows else 0
        entities = [_row_to_asset_inventory_dict(row) for row in rows]
        return {"entities": entities, "total_count": total_count}

    async def list_asset_changes(
        self,
        target_id: str | None = None,
        entity_id: str | None = None,
        org_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List asset change events via direct SQL (kept here for inventory cohesion).

        Delegates to :class:`EntityStore.list_asset_change_events` when called
        through the facade.
        """
        # Implemented by EntityStore; exposed here as an inventory helper.
        raise NotImplementedError(
            "list_asset_changes is implemented by EntityStore.list_asset_change_events"
        )

    async def export_assets_ndjson(
        self,
        org_id: str = "default",
        target_id: str | None = None,
        batch_size: int = 500,
    ) -> list[dict[str, Any]]:
        """Stream the full asset inventory as a list of NDJSON-ready dicts.

        Each dict corresponds to one inventory row. The caller is
        responsible for ``json.dumps`` + newline joining.
        """
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")
        results: list[dict[str, Any]] = []
        offset = 0
        while True:
            page = await self.list_asset_inventory(
                target_id=target_id,
                limit=batch_size,
                offset=offset,
                org_id=org_id,
            )
            page_entities = page.get("entities", [])
            if not page_entities:
                break
            results.extend(page_entities)
            if len(page_entities) < batch_size:
                break
            offset += batch_size
        return results
