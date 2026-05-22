import json

import pytest

from easm.store import Store


@pytest.fixture
async def store(db_pool):
    return Store(db_pool)


@pytest.mark.asyncio
async def test_update_entity_asset_profile_preserves_existing_attributes(store):
    entity_id, _ = await store.upsert_entity(
        org_id="default",
        target_id="target-1",
        entity_type="hostname",
        entity_value="app.example.invalid",
        new_attributes={"source": "subfinder"},
    )

    await store.update_entity_asset_profile(
        entity_id,
        {
            "confidence": {
                "score": 85,
                "level": "high",
                "reasons": ["direct_target_match"],
            },
            "sources": ["subfinder"],
            "evidence": [{"source": "subfinder", "summary": "observed"}],
        },
    )

    row = await store.pool.fetchrow(
        "SELECT attributes FROM entities WHERE id = $1",
        entity_id,
    )
    attributes = row["attributes"]
    if isinstance(attributes, str):
        attributes = json.loads(attributes)

    assert attributes["asset_profile"]["confidence"]["score"] == 85
    assert attributes["asset_profile"]["sources"] == ["subfinder"]
    assert attributes["source"] == "subfinder"
