from datetime import UTC, datetime

import pytest

from easm.store import Store


@pytest.fixture
async def store(db_pool):
    return Store(db_pool)


@pytest.mark.asyncio
async def test_duplicate_event_returns_false(store):
    run_id = await store.create_run("t", "subfinder", "scheduled")
    await store.mark_run_started(run_id, datetime.now(UTC))

    raw = {"host": "test.example.com", "source": "subfinder"}
    first = await store.insert_raw_event("default", "t", "subfinder", raw, run_id)
    assert first is True

    second = await store.insert_raw_event("default", "t", "subfinder", raw, run_id)
    assert second is False


@pytest.mark.asyncio
async def test_different_key_order_same_hash(store):
    run_id = await store.create_run("t", "subfinder", "scheduled")
    await store.mark_run_started(run_id, datetime.now(UTC))

    raw_a = {"a": 1, "b": 2}
    raw_b = {"b": 2, "a": 1}

    first = await store.insert_raw_event("default", "t", "subfinder", raw_a, run_id)
    assert first is True

    second = await store.insert_raw_event("default", "t", "subfinder", raw_b, run_id)
    assert second is False


@pytest.mark.asyncio
async def test_different_targets_same_raw_different_events(store):
    run_id_a = await store.create_run("target-a", "subfinder", "scheduled")
    run_id_b = await store.create_run("target-b", "subfinder", "scheduled")
    await store.mark_run_started(run_id_a, datetime.now(UTC))
    await store.mark_run_started(run_id_b, datetime.now(UTC))

    raw = {"host": "shared.example.com"}

    first = await store.insert_raw_event("default", "target-a", "subfinder", raw, run_id_a)
    assert first is True

    second = await store.insert_raw_event("default", "target-b", "subfinder", raw, run_id_b)
    assert second is True


@pytest.mark.asyncio
async def test_same_target_different_source_different_events(store):
    run_id_a = await store.create_run("t", "subfinder", "scheduled")
    run_id_b = await store.create_run("t", "certstream", "stream")
    await store.mark_run_started(run_id_a, datetime.now(UTC))
    await store.mark_run_started(run_id_b, datetime.now(UTC))

    raw = {"host": "same.example.com"}

    first = await store.insert_raw_event("default", "t", "subfinder", raw, run_id_a)
    assert first is True

    second = await store.insert_raw_event("default", "t", "certstream", raw, run_id_b)
    assert second is True
