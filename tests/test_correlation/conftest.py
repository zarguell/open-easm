from __future__ import annotations

import json
import uuid

import pytest_asyncio


@pytest_asyncio.fixture
async def seed_entities(db_pool):
    run_id = uuid.uuid4()
    event_id = uuid.uuid4()
    async with db_pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO runs (id, target_id, source, trigger_type, status) VALUES ($1, $2, $3, $4, $5)",
            run_id, "test-target", "test", "manual", "completed",
        )
        await conn.execute(
            "INSERT INTO raw_events (id, org_id, target_id, source, raw, event_hash, run_id) VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, $6)",
            event_id, "default", "test-target", "test", "hash-dev-test", run_id,
        )

        entities = [
            ("default", "test-target", "hostname", "dev.example.com", {"source": "subfinder"}),
            ("default", "test-target", "hostname", "test-api.example.com", {"source": "subfinder"}),
            ("default", "test-target", "hostname", "prod.example.com", {"source": "subfinder"}),
            ("default", "test-target", "ip", "192.168.1.1", {"source": "dns_resolve"}),
        ]
        inserted_ids = []
        for org, target, etype, evalue, attrs in entities:
            eid = await conn.fetchval(
                """INSERT INTO entities (org_id, target_id, entity_type, entity_value, attributes)
                   VALUES ($1, $2, $3, $4, $5::jsonb) RETURNING id""",
                org, target, etype, evalue, json.dumps(attrs),
            )
            inserted_ids.append(eid)
        return inserted_ids
