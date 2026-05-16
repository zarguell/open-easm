from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from easm.api.deps import get_store
from easm.store import Store

router = APIRouter(tags=["graph"])


@router.get("/graph/{target_id}")
async def get_graph(
    target_id: str,
    depth: int = Query(3, ge=1, le=10),
    store: Store = Depends(get_store),
):
    rows = await store.pool.fetch("""
        WITH RECURSIVE graph AS (
            SELECT id, org_id, target_id, entity_type, entity_value, attributes,
                   first_seen_at, last_seen_at, is_first_discovery, 0 AS depth
            FROM entities
            WHERE target_id = $1
            UNION
            SELECT e.id, e.org_id, e.target_id, e.entity_type, e.entity_value, e.attributes,
                   e.first_seen_at, e.last_seen_at, e.is_first_discovery, g.depth + 1
            FROM graph g
            JOIN entity_relationships er ON er.source_entity_id = g.id OR er.target_entity_id = g.id
            JOIN entities e ON e.id = CASE WHEN er.source_entity_id = g.id THEN er.target_entity_id ELSE er.source_entity_id END
            WHERE g.depth < $2
        )
        SELECT DISTINCT id, org_id, target_id, entity_type, entity_value, attributes,
               first_seen_at, last_seen_at, is_first_discovery, MIN(depth) AS depth
        FROM graph
        GROUP BY id, org_id, target_id, entity_type, entity_value, attributes,
                 first_seen_at, last_seen_at, is_first_discovery
        ORDER BY MIN(depth), entity_type
    """, target_id, depth)

    nodes: list[dict[str, Any]] = []
    edge_ids: set[str] = set()
    for r in rows:
        nodes.append({
            "id": str(r["id"]),
            "org_id": r["org_id"],
            "target_id": r["target_id"],
            "entity_type": r["entity_type"],
            "entity_value": r["entity_value"],
            "attributes": r["attributes"],
            "first_seen_at": r["first_seen_at"].isoformat(),
            "last_seen_at": r["last_seen_at"].isoformat(),
            "is_first_discovery": r["is_first_discovery"],
            "depth": r["depth"],
        })
        edge_ids.add(str(r["id"]))

    edges: list[dict[str, Any]] = []
    if edge_ids:
        edge_rows = await store.pool.fetch(
            """SELECT id, source_entity_id, target_entity_id, relationship_type,
                      relationship_source, first_seen_at
               FROM entity_relationships
               WHERE source_entity_id = ANY($1::uuid[]) AND target_entity_id = ANY($1::uuid[])
               ORDER BY first_seen_at""",
            list(edge_ids),
        )
        for r in edge_rows:
            edges.append({
                "id": str(r["id"]),
                "source_entity_id": str(r["source_entity_id"]),
                "target_entity_id": str(r["target_entity_id"]),
                "relationship_type": r["relationship_type"],
                "relationship_source": r["relationship_source"],
                "first_seen_at": r["first_seen_at"].isoformat(),
            })

    return {"target_id": target_id, "max_depth": depth, "nodes": nodes, "edges": edges}
