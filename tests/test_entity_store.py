import uuid

import pytest

from easm.entity_store import (
    deep_merge_attributes,
    normalize_entity_value,
    upsert_entity,
)


def test_normalize_entity_value():
    assert normalize_entity_value("domain", "Example.COM.") == "example.com"
    assert normalize_entity_value("asn", "12345") == "AS12345"
    assert normalize_entity_value("asn", "as12345") == "AS12345"
    assert normalize_entity_value("hostname", "App.Prod.Example.COM.") == "app.prod.example.com"
    assert normalize_entity_value("ip", "  1.2.3.4  ") == "1.2.3.4"
    assert normalize_entity_value("org", "  Example Corp  ") == "Example Corp"


def test_deep_merge_attributes():
    existing = {"shodan": [{"observed_at": "2026-05-14", "ports": [80, 443]}]}
    incoming = {"shodan": [{"observed_at": "2026-05-16", "ports": [443]}]}
    result = deep_merge_attributes(existing, incoming)
    assert result["shodan"][0]["observed_at"] == "2026-05-14"
    assert result["shodan"][1]["observed_at"] == "2026-05-16"


@pytest.mark.asyncio
async def test_upsert_entity_is_first_discovery(db_pool):
    pool = db_pool
    run_id = uuid.uuid7()
    event_id = uuid.uuid7()
    await pool.execute(
        "INSERT INTO runs (id, target_id, source, trigger_type, status) VALUES ($1, $2, $3, $4, $5)",
        run_id, "test-target", "subfinder", "manual", "running",
    )
    await pool.execute(
        "INSERT INTO raw_events (id, org_id, target_id, source, raw, event_hash, run_id) VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, $6)",
        event_id, "default", "test-target", "subfinder", "hash1", run_id,
    )

    id1, is_new1 = await upsert_entity(pool, "default", "test-target", "domain", "example.com", {}, event_id, discovery_run_id=run_id)
    assert is_new1 is True

    id2, is_new2 = await upsert_entity(pool, "default", "test-target", "domain", "example.com", {}, event_id, discovery_run_id=run_id)
    assert is_new2 is False
    assert id1 == id2
