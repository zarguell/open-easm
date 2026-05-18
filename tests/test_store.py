import uuid
from datetime import UTC, datetime

import pytest

from easm.store import Store


@pytest.fixture
async def store(db_pool):
    return Store(db_pool)


@pytest.mark.asyncio
async def test_create_run_returns_uuid(store):
    run_id = await store.create_run("test-target", "subfinder", "scheduled")
    assert isinstance(run_id, uuid.UUID)

    row = await store.get_run(run_id)
    assert row is not None
    assert row["target_id"] == "test-target"
    assert row["source"] == "subfinder"
    assert row["trigger_type"] == "scheduled"
    assert row["status"] == "pending"


@pytest.mark.asyncio
async def test_run_lifecycle_pending_to_running(store):
    run_id = await store.create_run("t", "subfinder", "manual")
    now = datetime.now(UTC)
    await store.mark_run_started(run_id, now)
    row = await store.get_run(run_id)
    assert row["started_at"] is not None
    assert row["status"] == "running"


@pytest.mark.asyncio
async def test_mark_run_finished_with_counters(store):
    run_id = await store.create_run("t", "subfinder", "manual")
    now = datetime.now(UTC)
    await store.mark_run_started(run_id, now)
    await store.mark_run_finished(
        run_id, "completed", now, 1000, 5, 2, 0, metadata={"extra": "info"}
    )
    row = await store.get_run(run_id)
    assert row["status"] == "completed"
    assert row["inserted_count"] == 5
    assert row["deduped_count"] == 2
    assert row["duration_ms"] == 1000
    assert row["metadata"] == {"extra": "info"}


@pytest.mark.asyncio
async def test_list_runs_filtered(store):
    await store.create_run("a", "subfinder", "scheduled")
    await store.create_run("b", "asnmap", "manual")
    await store.create_run("a", "certstream", "stream")

    a_runs = await store.list_runs(target_id="a")
    assert len(a_runs) == 2

    sub_runs = await store.list_runs(source="subfinder")
    assert len(sub_runs) == 1


@pytest.mark.asyncio
async def test_insert_and_list_event(store):
    run_id = await store.create_run("t", "subfinder", "scheduled")
    now = datetime.now(UTC)
    await store.mark_run_started(run_id, now)
    await store.insert_raw_event("default", "t", "subfinder", {"host": "test.example.com"}, run_id)

    events, next_cursor = await store.list_events(limit=10)
    assert len(events) == 1
    assert events[0]["raw"]["host"] == "test.example.com"


@pytest.mark.asyncio
async def test_get_event_returns_full_raw(store):
    run_id = await store.create_run("t", "subfinder", "scheduled")
    now = datetime.now(UTC)
    await store.mark_run_started(run_id, now)
    await store.insert_raw_event("default", "t", "subfinder", {"deep": {"nested": True}}, run_id)

    events, _ = await store.list_events(limit=1)
    event_id = events[0]["id"]
    event = await store.get_event(uuid.UUID(event_id))
    assert event is not None
    assert event["raw"] == {"deep": {"nested": True}}


@pytest.mark.asyncio
async def test_list_events_pagination(store):
    run_id = await store.create_run("t", "subfinder", "scheduled")
    now = datetime.now(UTC)
    await store.mark_run_started(run_id, now)

    for i in range(3):
        await store.insert_raw_event("default", "t", "subfinder", {"n": i}, run_id)

    page1, cursor = await store.list_events(limit=2)
    assert len(page1) == 2
    assert cursor is not None

    page2, cursor2 = await store.list_events(limit=2, cursor=cursor)
    assert len(page2) >= 0
    assert cursor2 is None


@pytest.mark.asyncio
async def test_save_config_snapshot_does_not_error(store):
    raw = {"targets": []}
    await store.save_config_snapshot(raw)


@pytest.mark.asyncio
async def test_insert_raw_event_with_org_id(store):
    run_id = await store.create_run("test-target", "subfinder", "scheduled")
    inserted = await store.insert_raw_event(
        org_id="default",
        target_id="test-target",
        source="subfinder",
        raw={"domain": "example.com"},
        run_id=run_id,
    )
    assert isinstance(inserted, uuid.UUID)
    events, _ = await store.list_events(target_id="test-target")
    assert len(events) == 1
    assert events[0]["raw"] == {"domain": "example.com"}
    assert events[0]["org_id"] == "default"


@pytest.mark.asyncio
async def test_dequeue_pivot_jobs_batch_returns_multiple(store):
    org_id = "test-org"
    target_id = "test-target"
    ids = []
    for i in range(5):
        jid = await store.enqueue_pivot_job(
            org_id=org_id, target_id=target_id,
            entity_type="domain", entity_value=f"sub{i}.example.com",
            entity_id=uuid.uuid4(), pivot_type="crtsh_search", depth=1,
        )
        ids.append(jid)

    batch = await store.dequeue_pivot_jobs_batch(limit=3)
    assert len(batch) == 3
    assert all(j["pivot_type"] == "crtsh_search" for j in batch)
    assert all(j["status"] == "running" for j in batch)

    batch2 = await store.dequeue_pivot_jobs_batch(limit=3)
    assert len(batch2) == 2


@pytest.mark.asyncio
async def test_dequeue_pivot_jobs_batch_empty(store):
    batch = await store.dequeue_pivot_jobs_batch(limit=50)
    assert batch == []
