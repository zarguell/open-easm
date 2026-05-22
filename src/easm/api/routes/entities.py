from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from easm.api.deps import get_store
from easm.assets.lifecycle import compute_lifecycle_state
from easm.store import Store

router = APIRouter(tags=["entities"])


@router.get("/entities/count")
async def count_entities(
    target_id: str | None = Query(None),
    entity_type: str | None = Query(None),
    first_seen_since: str | None = Query(None),
    last_seen_before: str | None = Query(None),
    store: Store = Depends(get_store),
):
    conditions: list[str] = []
    params: list[object] = []
    idx = 0
    if target_id:
        idx += 1
        conditions.append(f"target_id = ${idx}")
        params.append(target_id)
    if entity_type:
        idx += 1
        conditions.append(f"entity_type = ${idx}")
        params.append(entity_type)
    if first_seen_since:
        from datetime import datetime
        dt = datetime.fromisoformat(first_seen_since.replace("Z", "+00:00"))
        idx += 1
        conditions.append(f"first_seen_at >= ${idx}")
        params.append(dt)
    if last_seen_before:
        from datetime import datetime
        dt = datetime.fromisoformat(last_seen_before.replace("Z", "+00:00"))
        idx += 1
        conditions.append(f"last_seen_at <= ${idx}")
        params.append(dt)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    count = await store.pool.fetchval(
        f"SELECT COUNT(*) FROM entities {where}", *params,
    ) or 0
    return {"count": count}


@router.get("/entities/counts")
async def get_entity_counts(
    target_id: str | None = Query(None),
    store: Store = Depends(get_store),
):
    conditions: list[str] = []
    params: list[object] = []
    if target_id:
        conditions.append("target_id = $1")
        params.append(target_id)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    rows = await store.pool.fetch(
        f"SELECT entity_type, COUNT(*) AS count FROM entities {where} GROUP BY entity_type",
        *params,
    )
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["entity_type"]] = r["count"]
    return {"counts": counts}


@router.get("/entities")
async def list_entities(
    target_id: str | None = Query(None),
    entity_type: str | None = Query(None),
    first_seen_since: str | None = Query(None),
    last_seen_before: str | None = Query(None),
    new_since_run_id: str | None = Query(None),
    q: str | None = Query(None),
    limit: int = Query(50, ge=1, le=5000),
    cursor: str | None = Query(None),
    store: Store = Depends(get_store),
):
    conditions: list[str] = []
    sql_params: list[object] = []
    idx = 0

    if target_id:
        idx += 1
        conditions.append(f"target_id = ${idx}")
        sql_params.append(target_id)
    if entity_type:
        idx += 1
        conditions.append(f"entity_type = ${idx}")
        sql_params.append(entity_type)
    if first_seen_since:
        from datetime import datetime
        dt = datetime.fromisoformat(first_seen_since.replace("Z", "+00:00"))
        idx += 1
        conditions.append(f"first_seen_at >= ${idx}")
        sql_params.append(dt)
    if last_seen_before:
        from datetime import datetime
        dt = datetime.fromisoformat(last_seen_before.replace("Z", "+00:00"))
        idx += 1
        conditions.append(f"last_seen_at <= ${idx}")
        sql_params.append(dt)
    if q:
        idx += 1
        conditions.append(
            f"(entity_value ILIKE ${idx} OR entity_type ILIKE ${idx} OR attributes::text ILIKE ${idx})"
        )
        sql_params.append(f"%{q}%")
    if cursor:
        idx += 1
        conditions.append(f"id < ${idx}::uuid")
        sql_params.append(cursor)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    count_where = where
    count_params = list(sql_params)
    total_count = await store.pool.fetchval(
        f"SELECT COUNT(*) FROM entities {count_where}", *count_params,
    ) or 0

    idx += 1
    query = f"""
        SELECT id, org_id, target_id, entity_type, entity_value, attributes,
               first_seen_at, last_seen_at, is_first_discovery
        FROM entities
        {where}
        ORDER BY id DESC
        LIMIT ${idx}
    """
    sql_params.append(limit + 1)

    async with store.pool.acquire() as conn:
        rows = await conn.fetch(query, *sql_params)

    has_more = len(rows) > limit
    results = rows[:limit]

    entities_list = []
    for r in results:
        entities_list.append({
            "id": str(r["id"]),
            "org_id": r["org_id"],
            "target_id": r["target_id"],
            "entity_type": r["entity_type"],
            "entity_value": r["entity_value"],
            "attributes": r["attributes"],
            "first_seen_at": r["first_seen_at"].isoformat(),
            "last_seen_at": r["last_seen_at"].isoformat(),
            "is_first_discovery": r["is_first_discovery"],
            "lifecycle_state": compute_lifecycle_state(r["first_seen_at"]),
        })

    next_cursor = str(results[-1]["id"]) if has_more and results else None
    return {"entities": entities_list, "next_cursor": next_cursor, "total_count": total_count}


@router.get("/entities/{entity_id}")
async def get_entity(entity_id: str, store: Store = Depends(get_store)):
    row = await store.pool.fetchrow(
        "SELECT id, org_id, target_id, entity_type, entity_value, attributes, "
        "first_seen_at, last_seen_at, is_first_discovery FROM entities WHERE id = $1",
        entity_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail={"error": "not_found", "detail": "Entity not found"})

    links = await store.pool.fetch(
        "SELECT raw_event_id FROM entity_raw_event_links WHERE entity_id = $1", row["id"]
    )

    return {
        "id": str(row["id"]),
        "org_id": row["org_id"],
        "target_id": row["target_id"],
        "entity_type": row["entity_type"],
        "entity_value": row["entity_value"],
        "attributes": row["attributes"],
        "first_seen_at": row["first_seen_at"].isoformat(),
        "last_seen_at": row["last_seen_at"].isoformat(),
        "is_first_discovery": row["is_first_discovery"],
        "lifecycle_state": compute_lifecycle_state(row["first_seen_at"]),
        "raw_event_ids": [str(l["raw_event_id"]) for l in links],
    }


@router.get("/entities/{entity_id}/relationships")
async def get_entity_relationships(entity_id: str, store: Store = Depends(get_store)):
    rows = await store.pool.fetch(
        """SELECT er.id, er.source_entity_id, er.target_entity_id,
                  er.relationship_type, er.relationship_source, er.first_seen_at,
                  se.entity_value AS source_entity_value,
                  se.entity_type AS source_entity_type,
                  te.entity_value AS target_entity_value,
                  te.entity_type AS target_entity_type
           FROM entity_relationships er
           JOIN entities se ON se.id = er.source_entity_id
           JOIN entities te ON te.id = er.target_entity_id
           WHERE er.source_entity_id = $1 OR er.target_entity_id = $1
           ORDER BY er.first_seen_at DESC""",
        entity_id,
    )
    return {
        "relationships": [
            {
                "id": str(r["id"]),
                "source_entity_id": str(r["source_entity_id"]),
                "target_entity_id": str(r["target_entity_id"]),
                "relationship_type": r["relationship_type"],
                "relationship_source": r["relationship_source"],
                "first_seen_at": r["first_seen_at"].isoformat(),
                "source_entity_value": r["source_entity_value"],
                "source_entity_type": r["source_entity_type"],
                "target_entity_value": r["target_entity_value"],
                "target_entity_type": r["target_entity_type"],
            }
            for r in rows
        ]
    }


@router.get("/entities/{entity_id}/lineage")
async def get_entity_lineage(
    entity_id: UUID,
    store: Store = Depends(get_store),
):
    lineage = await store.get_entity_lineage(entity_id, org_id="default")
    if lineage is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "not_found", "detail": "Entity not found"},
        )
    return lineage
