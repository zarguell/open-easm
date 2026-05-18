import uuid
from unittest.mock import AsyncMock

import pytest

from easm.store import Store


@pytest.mark.asyncio
async def test_enqueue_and_dequeue_pivot_job(db_pool):
    store = Store(db_pool)
    entity_id = uuid.uuid7()
    job_id = await store.enqueue_pivot_job(
        "default", "t1", "domain", "example.com",
        entity_id, "dns_resolve", 1,
    )
    assert job_id is not None

    job = await store.dequeue_pivot_job()
    assert job is not None
    assert job["pivot_type"] == "dns_resolve"
    assert job["entity_value"] == "example.com"


@pytest.mark.asyncio
@pytest.mark.db
async def test_dequeue_pivot_job_returns_running_status(db_pool):
    store = Store(db_pool)
    entity_id = uuid.uuid4()
    job_id = await store.enqueue_pivot_job(
        "default",
        "target-1",
        "hostname",
        "app.example.invalid",
        entity_id,
        "dns_resolve",
        1,
    )

    job = await store.dequeue_pivot_job()

    assert job is not None
    assert job["id"] == job_id
    assert job["status"] == "running"


@pytest.mark.asyncio
async def test_dequeue_pivot_jobs_batch_uses_atomic_update_returning_query():
    rows = [
        {"id": uuid.uuid7(), "status": "running", "entity_value": "example.com"},
        {"id": uuid.uuid7(), "status": "running", "entity_value": "example.net"},
    ]
    pool = AsyncMock()
    pool.fetch.return_value = rows
    store = Store(pool)

    jobs = await store.dequeue_pivot_jobs_batch(limit=2)

    pool.fetch.assert_awaited_once()
    query, limit = pool.fetch.await_args.args
    normalized_query = " ".join(query.split())
    assert normalized_query == (
        "WITH picked AS ( "
        "SELECT id FROM pivot_queue WHERE status = 'pending' "
        "ORDER BY enqueued_at LIMIT $1 FOR UPDATE SKIP LOCKED "
        ") "
        "UPDATE pivot_queue pq SET status = 'running', started_at = NOW() "
        "FROM picked WHERE pq.id = picked.id "
        "RETURNING pq.*"
    )
    assert limit == 2
    pool.execute.assert_not_called()
    assert jobs == [dict(row) for row in rows]
    assert all(job["status"] == "running" for job in jobs)
