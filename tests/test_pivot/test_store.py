import uuid

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
