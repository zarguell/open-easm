from __future__ import annotations

import asyncio
import json
import uuid

import pytest
import pytest_asyncio

from easm.backfill import backfill_worker


@pytest_asyncio.fixture
async def sample_run(db_pool):
    run_id = uuid.uuid7()
    await db_pool.execute(
        "INSERT INTO runs (id, target_id, source, trigger_type, status) VALUES ($1, $2, $3, $4, $5)",
        run_id, "t1", "manual", "manual", "running",
    )
    return run_id


@pytest.mark.asyncio
async def test_backfill_unknown_source(db_pool, sample_run):
    await db_pool.execute(
        "INSERT INTO raw_events (org_id, target_id, source, raw, event_hash, run_id) "
        "VALUES ($1, $2, $3, $4::jsonb, $5, $6)",
        "default", "t1", "unknown-runner", "{}", "hash-unknown", sample_run,
    )

    task = asyncio.create_task(backfill_worker(db_pool, None, batch_size=10, batch_interval_ms=50))
    await asyncio.sleep(0.3)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    row = await db_pool.fetchrow("SELECT parsed_at, parse_error FROM raw_events WHERE event_hash='hash-unknown'")
    assert row["parsed_at"] is not None
    assert "no parser for source" in row["parse_error"]


@pytest.mark.asyncio
async def test_backfill_subfinder_creates_entity(db_pool, sample_run):
    await db_pool.execute(
        "INSERT INTO raw_events (org_id, target_id, source, raw, event_hash, run_id) "
        "VALUES ($1, $2, $3, $4::jsonb, $5, $6)",
        "default", "t1", "subfinder", '{"host": "foo.example.com"}', "hash-sub", sample_run,
    )

    task = asyncio.create_task(backfill_worker(db_pool, None, batch_size=10, batch_interval_ms=50))
    await asyncio.sleep(0.3)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    entity = await db_pool.fetchrow("SELECT * FROM entities WHERE entity_value='foo.example.com'")
    assert entity is not None
    assert entity["entity_type"] == "domain"


@pytest.mark.asyncio
async def test_backfill_asnmap_creates_entity_and_relationship(db_pool, sample_run):
    raw_json = json.dumps({"asn": "AS12345", "prefixes": [{"ipv4": "1.2.3.0/24"}]})
    await db_pool.execute(
        "INSERT INTO raw_events (org_id, target_id, source, raw, event_hash, run_id) "
        "VALUES ($1, $2, $3, $4::jsonb, $5, $6)",
        "default", "t1", "asnmap", raw_json, "hash-asn", sample_run,
    )

    task = asyncio.create_task(backfill_worker(db_pool, None, batch_size=10, batch_interval_ms=50))
    await asyncio.sleep(0.3)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    entities = await db_pool.fetch("SELECT * FROM entities WHERE target_id='t1'")
    assert len(entities) == 2
    rels = await db_pool.fetch("SELECT * FROM entity_relationships")
    assert len(rels) == 1
    assert rels[0]["relationship_type"] == "owns"
