from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

import asyncpg
from easm.models import EntityType


def normalize_entity_value(entity_type: str, value: str) -> str:

    if entity_type == EntityType.DOMAIN.value:
        return value.lower().rstrip(".").strip()
    if entity_type == EntityType.HOSTNAME.value:
        return value.lower().rstrip(".").strip()
    if entity_type == EntityType.IP.value:
        return value.strip()
    if entity_type == EntityType.IP_RANGE.value:
        return value.strip()
    if entity_type == EntityType.CERTIFICATE.value:
        return hashlib.sha256(value.encode()).hexdigest()
    if entity_type == EntityType.ASN.value:
        val = value.upper().strip()
        if not val.startswith("AS"):
            val = f"AS{val}"
        return val
    if entity_type == EntityType.ORG.value:
        return value.strip()
    return value.strip()


def deep_merge_attributes(existing: dict, incoming: dict) -> dict:
    result = dict(existing)
    for key, value in incoming.items():
        if key in result and isinstance(result[key], list) and isinstance(value, list):
            result[key] = result[key] + value
        else:
            result[key] = value
    return result


async def upsert_entity(
    pool: asyncpg.Pool,
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

    existing = await pool.fetchrow(
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
        await pool.execute(
            "UPDATE entities SET last_seen_at = NOW(), attributes = $1::jsonb WHERE id = $2",
            json.dumps(merged), existing["id"],
        )
        await pool.execute(
            "INSERT INTO entity_raw_event_links (entity_id, raw_event_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            existing["id"], raw_event_id,
        )
        return existing["id"], False
    else:
        entity_id = await pool.fetchval(
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
        await pool.execute(
            "INSERT INTO entity_raw_event_links (entity_id, raw_event_id) VALUES ($1, $2)",
            entity_id, raw_event_id,
        )
        return entity_id, True


async def upsert_relationship(
    pool: asyncpg.Pool,
    org_id: str,
    source_entity_id: uuid.UUID,
    target_entity_id: uuid.UUID,
    relationship_type: str,
    relationship_source: str,
    evidence_raw_event_id: uuid.UUID | None = None,
    runner: str | None = None,
) -> None:
    await pool.execute(
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
