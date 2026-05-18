from __future__ import annotations

import pytest

from easm.pivot.worker import process_pivot_job_batch
from easm.store import Store


class _NoopAsyncClient:
    async def aclose(self) -> None:
        pass


class _PivotRuntime:
    def make_http_client(self) -> _NoopAsyncClient:
        return _NoopAsyncClient()

    async def run_pivot_handler(self, _pivot_type, _job, _handler_fn, _pool, **_kwargs):
        return [{"hostname": "app.example.invalid", "ip": "198.51.100.10"}]


@pytest.mark.asyncio
@pytest.mark.db
async def test_pivot_batch_marks_unknown_handler_failed(db_pool, monkeypatch) -> None:
    monkeypatch.setattr("easm.pivot.worker.get_runtime", lambda: _PivotRuntime())
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
        pivot_type="missing_handler",
        depth=1,
    )

    processed = await process_pivot_job_batch(db_pool, None, limit=20)

    assert processed == 1
    row = await db_pool.fetchrow("SELECT status, error_message FROM pivot_queue")
    assert row["status"] == "failed"
    assert "no handler" in row["error_message"]


@pytest.mark.asyncio
@pytest.mark.db
async def test_pivot_batch_marks_schema_materialization_error_failed(
    db_pool, monkeypatch
) -> None:
    monkeypatch.setattr("easm.pivot.worker.get_runtime", lambda: _PivotRuntime())
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

    async def fail_upsert_entity(self, *args, **kwargs):
        raise RuntimeError("entity upsert boom")

    monkeypatch.setattr(Store, "upsert_entity", fail_upsert_entity)

    processed = await process_pivot_job_batch(db_pool, None, limit=20)

    assert processed == 1
    row = await db_pool.fetchrow("SELECT status, error_message FROM pivot_queue")
    assert row["status"] == "failed"
    assert "pivot materialization failed" in row["error_message"]
    run_row = await db_pool.fetchrow("SELECT status, error_message FROM runs")
    assert run_row["status"] == "failed"
    assert run_row["error_message"] == row["error_message"]
