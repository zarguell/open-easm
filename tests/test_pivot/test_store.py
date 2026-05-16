import uuid

import pytest

from easm.pivot_store import enqueue_pivot_job, dequeue_pivot_job


@pytest.mark.asyncio
async def test_enqueue_and_dequeue_pivot_job(db_pool):
    entity_id = uuid.uuid7()
    job_id = await enqueue_pivot_job(
        db_pool, "default", "t1", "domain", "example.com",
        entity_id, "dns_resolve", 1,
    )
    assert job_id is not None

    job = await dequeue_pivot_job(db_pool)
    assert job is not None
    assert job["pivot_type"] == "dns_resolve"
    assert job["entity_value"] == "example.com"
