from __future__ import annotations

import pytest

from easm.config import load_config
from easm.pivot.worker_legacy import process_pivot_job_batch
from easm.runtime import configure_runtime
from easm.store import Store

pytestmark = pytest.mark.skip(
    reason="Legacy worker tests disabled: Store pivot methods (enqueue_pivot_job, "
    "dequeue_pivot_jobs_batch, mark_pivot_completed/failed) were removed in "
    "the Procrastinate migration"
)


@pytest.mark.asyncio
@pytest.mark.db
@pytest.mark.simulation
async def test_simulated_dns_pivot_batch_writes_raw_event_and_ip_entity(db_pool) -> None:
    config = load_config("config.offline.yaml")
    configure_runtime(config.runtime)
    store = Store(db_pool)

    entity_id, _ = await store.upsert_entity(
        "default",
        "offline-local",
        "hostname",
        "app.example.invalid",
        {"source": "test"},
    )
    await store.enqueue_pivot_job(
        org_id="default",
        target_id="offline-local",
        entity_type="hostname",
        entity_value="app.example.invalid",
        entity_id=entity_id,
        pivot_type="dns_resolve",
        depth=1,
    )

    processed = await process_pivot_job_batch(db_pool, config, limit=20)

    assert processed == 1
    status = await db_pool.fetchval("SELECT status FROM pivot_queue")
    assert status == "completed"
    raw_count = await db_pool.fetchval(
        "SELECT COUNT(*) FROM raw_events WHERE source = 'dns'"
    )
    assert raw_count == 1
    ip_count = await db_pool.fetchval(
        """
        SELECT COUNT(*)
        FROM entities
        WHERE entity_type = 'ip'
          AND entity_value = '198.51.100.10'
        """
    )
    assert ip_count == 1
