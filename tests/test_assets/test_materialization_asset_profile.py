import json
import uuid

import pytest

from easm.store import Store


@pytest.fixture
async def store(db_pool):
    return Store(db_pool)


async def _entity_attributes(store: Store, entity_id: uuid.UUID) -> dict:
    row = await store.pool.fetchrow(
        "SELECT attributes FROM entities WHERE id = $1",
        entity_id,
    )
    attributes = row["attributes"]
    if isinstance(attributes, str):
        attributes = json.loads(attributes)
    return attributes


@pytest.mark.asyncio
async def test_apply_asset_profile_for_entity_records_discovery_profile(store):
    target_id = "materialization-profile-target"
    raw_event_id = uuid.uuid4()
    entity_id, _ = await store.upsert_entity(
        org_id="default",
        target_id=target_id,
        entity_type="hostname",
        entity_value="app.example.invalid",
        new_attributes={"source": "dns"},
    )

    await store.apply_asset_profile_for_entity(
        org_id="default",
        target_id=target_id,
        entity_id=entity_id,
        entity_type="hostname",
        entity_value="app.example.invalid",
        source="subfinder",
        raw_event_id=raw_event_id,
        target_domains=["example.invalid"],
        summary="subfinder observed hostname app.example.invalid",
    )

    attributes = await _entity_attributes(store, entity_id)
    profile = attributes["asset_profile"]
    assert profile["confidence"]["level"] == "high"
    assert profile["confidence"]["score"] >= 80
    assert profile["source_of_truth_feed"]["eligible"] is True
    assert profile["sources"] == ["dns", "subfinder"]
    assert profile["evidence"] == [
        {
            "source": "subfinder",
            "raw_event_id": str(raw_event_id),
            "observed_at": profile["evidence"][0]["observed_at"],
            "summary": "subfinder observed hostname app.example.invalid",
        }
    ]

    events = await store.list_asset_change_events(
        target_id=target_id,
        entity_id=entity_id,
    )
    assert [event["change_type"] for event in events] == ["asset_discovered"]
    assert events[0]["before_state"] == {}
    assert events[0]["after_state"] == profile
    assert events[0]["evidence"] == profile["evidence"]
    assert events[0]["source"] == "subfinder"


@pytest.mark.asyncio
async def test_apply_asset_profile_for_entity_merges_observations(store):
    target_id = "materialization-profile-merge-target"
    entity_id, _ = await store.upsert_entity(
        org_id="default",
        target_id=target_id,
        entity_type="hostname",
        entity_value="api.example.invalid",
        new_attributes={"source": "dns"},
    )

    await store.apply_asset_profile_for_entity(
        org_id="default",
        target_id=target_id,
        entity_id=entity_id,
        entity_type="hostname",
        entity_value="api.example.invalid",
        source="subfinder",
        raw_event_id=uuid.uuid4(),
        target_domains=["example.invalid"],
        summary="subfinder observed hostname api.example.invalid",
    )
    first_profile = (await _entity_attributes(store, entity_id))["asset_profile"]

    await store.apply_asset_profile_for_entity(
        org_id="default",
        target_id=target_id,
        entity_id=entity_id,
        entity_type="hostname",
        entity_value="api.example.invalid",
        source="dns",
        raw_event_id=uuid.uuid4(),
        target_domains=["example.invalid"],
        summary="dns observed hostname api.example.invalid",
    )

    profile = (await _entity_attributes(store, entity_id))["asset_profile"]
    assert profile["sources"] == ["dns", "subfinder"]
    assert [item["source"] for item in profile["evidence"]] == ["subfinder", "dns"]
    assert [item["summary"] for item in profile["evidence"]] == [
        "subfinder observed hostname api.example.invalid",
        "dns observed hostname api.example.invalid",
    ]

    events = await store.list_asset_change_events(
        target_id=target_id,
        entity_id=entity_id,
    )
    assert [event["change_type"] for event in events] == [
        "asset_observed",
        "asset_discovered",
    ]
    assert events[0]["before_state"] == first_profile
    assert events[0]["after_state"] == profile


@pytest.mark.asyncio
async def test_apply_asset_profile_for_entity_ignores_unknown_source(store):
    target_id = "materialization-profile-unknown-source-target"
    entity_id, _ = await store.upsert_entity(
        org_id="default",
        target_id=target_id,
        entity_type="hostname",
        entity_value="solo.example.invalid",
        new_attributes={"source": "unknown"},
    )

    await store.apply_asset_profile_for_entity(
        org_id="default",
        target_id=target_id,
        entity_id=entity_id,
        entity_type="hostname",
        entity_value="solo.example.invalid",
        source="unknown",
        raw_event_id=None,
        target_domains=[],
        summary="unknown observed hostname solo.example.invalid",
    )

    profile = (await _entity_attributes(store, entity_id))["asset_profile"]
    assert profile["sources"] == []
    assert "multi_source_seen" not in profile["confidence"]["reasons"]
