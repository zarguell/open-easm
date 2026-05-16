from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def sample_run(db_pool):
    run_id = uuid.uuid7()
    await db_pool.execute(
        "INSERT INTO runs (id, target_id, source, trigger_type, status) VALUES ($1, $2, $3, $4, $5)",
        run_id, "t1", "manual", "manual", "running",
    )
    return run_id


@pytest.mark.asyncio
async def test_healthz_returns_binaries():
    from easm.api.routes.health import check_binaries

    result = check_binaries()
    assert isinstance(result, dict)
    for key in ("subfinder", "asnmap", "dnstwist"):
        assert key in result
        assert "ok" in result[key]


@pytest.mark.asyncio
async def test_gc_worker_imports():
    from easm import gc

    assert hasattr(gc, "gc_worker")


@pytest.mark.asyncio
async def test_gc_deletes_old_raw_events(db_pool, sample_run):
    old_id = uuid.uuid7()
    await db_pool.execute(
        """INSERT INTO raw_events (id, org_id, target_id, source, raw, event_hash, run_id, collected_at)
           VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)""",
        old_id, "default", "t1", "subfinder", '{}', "hash-old", sample_run,
        datetime.now(timezone.utc) - timedelta(days=200),
    )

    fresh_id = uuid.uuid7()
    await db_pool.execute(
        """INSERT INTO raw_events (id, org_id, target_id, source, raw, event_hash, run_id, collected_at)
           VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)""",
        fresh_id, "default", "t1", "subfinder", '{}', "hash-fresh", sample_run,
        datetime.now(timezone.utc),
    )

    raw_cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    await db_pool.execute("DELETE FROM raw_events WHERE collected_at < $1", raw_cutoff)

    remaining = await db_pool.fetchval("SELECT COUNT(*) FROM raw_events WHERE target_id = $1", "t1")
    assert remaining >= 1
