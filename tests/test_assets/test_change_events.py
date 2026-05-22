import uuid
from datetime import UTC, datetime

import pytest

from easm.assets.change import build_asset_change_event
from easm.store import Store


OBSERVED_AT = datetime(2026, 5, 18, 12, 0, tzinfo=UTC)


@pytest.fixture
async def store(db_pool):
    return Store(db_pool)


def test_build_asset_change_event_normalizes_defaults_and_timestamp():
    event = build_asset_change_event(
        change_type="asset_added",
        summary="hostname appeared in inventory",
        source="subfinder",
        observed_at=OBSERVED_AT,
    )

    assert event == {
        "change_type": "asset_added",
        "summary": "hostname appeared in inventory",
        "before_state": {},
        "after_state": {},
        "evidence": [],
        "source": "subfinder",
        "observed_at": "2026-05-18T12:00:00+00:00",
    }


@pytest.mark.asyncio
async def test_record_and_list_asset_change_events_round_trip(store):
    target_id = "asset-change-target"
    entity_id, _ = await store.upsert_entity(
        org_id="default",
        target_id=target_id,
        entity_type="hostname",
        entity_value="app.example.invalid",
        new_attributes={"source": "subfinder"},
    )

    event_id = await store.record_asset_change_event(
        org_id="default",
        target_id=target_id,
        entity_id=entity_id,
        change_type="asset_added",
        summary="hostname appeared in inventory",
        before_state={"state": "missing"},
        after_state={"state": "active", "hostname": "app.example.invalid"},
        evidence=[{"source": "subfinder", "value": "app.example.invalid"}],
        source="subfinder",
        observed_at=OBSERVED_AT,
    )

    assert isinstance(event_id, uuid.UUID)

    by_target = await store.list_asset_change_events(target_id=target_id)
    by_entity = await store.list_asset_change_events(entity_id=entity_id)

    assert by_target == by_entity
    assert len(by_target) == 1
    event = by_target[0]
    assert event["id"] == str(event_id)
    assert event["org_id"] == "default"
    assert event["target_id"] == target_id
    assert event["entity_id"] == str(entity_id)
    assert event["change_type"] == "asset_added"
    assert event["summary"] == "hostname appeared in inventory"
    assert event["before_state"] == {"state": "missing"}
    assert event["after_state"] == {"state": "active", "hostname": "app.example.invalid"}
    assert event["evidence"] == [{"source": "subfinder", "value": "app.example.invalid"}]
    assert event["source"] == "subfinder"
    assert event["observed_at"] == "2026-05-18T12:00:00+00:00"
    assert event["created_at"] is not None


@pytest.mark.asyncio
async def test_list_asset_change_events_filters_by_org_id(store):
    target_id = "asset-change-target"
    await store.pool.execute(
        """
        INSERT INTO organizations (id, name)
        VALUES ('other', 'Other Organization')
        ON CONFLICT (id) DO NOTHING
        """
    )
    default_entity_id, _ = await store.upsert_entity(
        org_id="default",
        target_id=target_id,
        entity_type="hostname",
        entity_value="app.example.invalid",
        new_attributes={"source": "subfinder"},
    )
    other_entity_id, _ = await store.upsert_entity(
        org_id="other",
        target_id=target_id,
        entity_type="hostname",
        entity_value="app.example.invalid",
        new_attributes={"source": "subfinder"},
    )

    default_event_id = await store.record_asset_change_event(
        target_id=target_id,
        entity_id=default_entity_id,
        change_type="asset_added",
        summary="default org hostname appeared",
        source="subfinder",
        observed_at=OBSERVED_AT,
    )
    other_event_id = await store.record_asset_change_event(
        org_id="other",
        target_id=target_id,
        entity_id=other_entity_id,
        change_type="asset_added",
        summary="other org hostname appeared",
        source="subfinder",
        observed_at=OBSERVED_AT,
    )

    default_events = await store.list_asset_change_events(
        target_id=target_id,
        org_id="default",
    )
    other_events = await store.list_asset_change_events(
        target_id=target_id,
        org_id="other",
    )
    all_events = await store.list_asset_change_events(target_id=target_id)

    assert [event["id"] for event in default_events] == [str(default_event_id)]
    assert [event["org_id"] for event in default_events] == ["default"]
    assert [event["id"] for event in other_events] == [str(other_event_id)]
    assert [event["org_id"] for event in other_events] == ["other"]
    assert {event["id"] for event in all_events} == {
        str(default_event_id),
        str(other_event_id),
    }
