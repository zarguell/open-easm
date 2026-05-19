import json
import uuid

import pytest

from easm.correlation.rule import Finding, RiskLevel
from easm.store import Store


@pytest.fixture
async def store(db_pool):
    return Store(db_pool)


@pytest.fixture
async def run_id(store):
    return await store.create_run("int-target", "subfinder", "manual")


@pytest.fixture
async def raw_event_id(store, run_id):
    eid = await store.insert_raw_event(
        org_id="default",
        target_id="int-target",
        source="subfinder",
        raw={"host": "test.example.com"},
        run_id=run_id,
    )
    assert eid is not None
    return eid


@pytest.mark.asyncio
async def test_insert_raw_event_returns_uuid(store, run_id):
    result = await store.insert_raw_event(
        org_id="default",
        target_id="int-target",
        source="subfinder",
        raw={"data": "value"},
        run_id=run_id,
    )
    assert isinstance(result, uuid.UUID)

    row = await store.pool.fetchrow(
        "SELECT id, org_id, target_id, source FROM raw_events WHERE id = $1",
        result,
    )
    assert row is not None
    assert row["org_id"] == "default"
    assert row["target_id"] == "int-target"
    assert row["source"] == "subfinder"


@pytest.mark.asyncio
async def test_insert_raw_event_dedup_returns_none(store, run_id):
    first = await store.insert_raw_event(
        org_id="default",
        target_id="int-target",
        source="subfinder",
        raw={"unique_key": "dedup_test"},
        run_id=run_id,
    )
    assert isinstance(first, uuid.UUID)

    second = await store.insert_raw_event(
        org_id="default",
        target_id="int-target",
        source="subfinder",
        raw={"unique_key": "dedup_test"},
        run_id=run_id,
    )
    assert second is None


@pytest.mark.asyncio
async def test_upsert_entity_first_discovery(store, run_id):
    entity_id, is_first = await store.upsert_entity(
        org_id="default",
        target_id="int-target",
        entity_type="domain",
        entity_value="example.com",
        new_attributes={"source": "subfinder"},
        discovery_run_id=run_id,
    )
    assert isinstance(entity_id, uuid.UUID)
    assert is_first is True

    row = await store.pool.fetchrow(
        "SELECT entity_type, entity_value, is_first_discovery FROM entities WHERE id = $1",
        entity_id,
    )
    assert row is not None
    assert row["entity_type"] == "domain"
    assert row["entity_value"] == "example.com"
    assert row["is_first_discovery"] is True


@pytest.mark.asyncio
async def test_upsert_entity_dedup_merges_attributes(store, run_id):
    await store.upsert_entity(
        org_id="default",
        target_id="int-target",
        entity_type="domain",
        entity_value="merge.example.com",
        new_attributes={"source": "subfinder", "ports": [80]},
        discovery_run_id=run_id,
    )

    entity_id, is_first = await store.upsert_entity(
        org_id="default",
        target_id="int-target",
        entity_type="domain",
        entity_value="merge.example.com",
        new_attributes={"source": "crtsh", "ports": [443]},
        discovery_run_id=run_id,
    )
    assert is_first is False

    row = await store.pool.fetchrow(
        "SELECT attributes FROM entities WHERE id = $1",
        entity_id,
    )
    attrs = row["attributes"]
    if isinstance(attrs, str):
        attrs = json.loads(attrs)
    assert attrs["ports"] == [80, 443]

    count = await store.pool.fetchval(
        "SELECT COUNT(*) FROM entities WHERE entity_value = 'merge.example.com'"
    )
    assert count == 1


@pytest.mark.asyncio
async def test_upsert_entity_with_valid_raw_event_id_creates_link(store, raw_event_id):
    entity_id, _ = await store.upsert_entity(
        org_id="default",
        target_id="int-target",
        entity_type="domain",
        entity_value="linked.example.com",
        new_attributes={"source": "subfinder"},
        raw_event_id=raw_event_id,
    )

    link = await store.pool.fetchrow(
        "SELECT entity_id, raw_event_id "
        "FROM entity_raw_event_links "
        "WHERE entity_id = $1 AND raw_event_id = $2",
        entity_id,
        raw_event_id,
    )
    assert link is not None
    assert link["entity_id"] == entity_id
    assert link["raw_event_id"] == raw_event_id


@pytest.mark.asyncio
async def test_upsert_entity_with_none_raw_event_id_no_link(store, run_id):
    entity_id, _ = await store.upsert_entity(
        org_id="default",
        target_id="int-target",
        entity_type="domain",
        entity_value="unlinked.example.com",
        new_attributes={"source": "manual"},
        raw_event_id=None,
        discovery_run_id=run_id,
    )

    link_count = await store.pool.fetchval(
        "SELECT COUNT(*) FROM entity_raw_event_links WHERE entity_id = $1",
        entity_id,
    )
    assert link_count == 0


@pytest.mark.asyncio
async def test_upsert_entity_with_invalid_raw_event_id_no_link(store, run_id):
    fake_raw_event_id = uuid.uuid4()

    entity_id, _ = await store.upsert_entity(
        org_id="default",
        target_id="int-target",
        entity_type="domain",
        entity_value="badlink.example.com",
        new_attributes={"source": "test"},
        raw_event_id=fake_raw_event_id,
        discovery_run_id=run_id,
    )
    assert isinstance(entity_id, uuid.UUID)

    link_count = await store.pool.fetchval(
        "SELECT COUNT(*) FROM entity_raw_event_links WHERE entity_id = $1",
        entity_id,
    )
    assert link_count == 0


@pytest.mark.asyncio
async def test_entity_triage_state_defaults_to_discovered(store, run_id):
    entity_id, _ = await store.upsert_entity(
        org_id="default",
        target_id="int-target",
        entity_type="domain",
        entity_value="triage.example.com",
        new_attributes={},
        discovery_run_id=run_id,
    )

    row = await store.pool.fetchrow(
        "SELECT attributes FROM entities WHERE id = $1",
        entity_id,
    )
    attrs = row["attributes"]
    if isinstance(attrs, str):
        attrs = json.loads(attrs)
    assert attrs.get("triage_state") == "discovered"


@pytest.mark.asyncio
async def test_set_entity_triage_state(store, run_id):
    entity_id, _ = await store.upsert_entity(
        org_id="default",
        target_id="int-target",
        entity_type="domain",
        entity_value="state-change.example.com",
        new_attributes={},
        discovery_run_id=run_id,
    )

    result = await store.set_entity_triage_state("default", entity_id, "active")
    assert result is True

    row = await store.pool.fetchrow(
        "SELECT attributes FROM entities WHERE id = $1",
        entity_id,
    )
    attrs = row["attributes"]
    if isinstance(attrs, str):
        attrs = json.loads(attrs)
    assert attrs["triage_state"] == "active"


@pytest.mark.asyncio
async def test_set_entity_triage_state_rejects_invalid(store, run_id):
    entity_id, _ = await store.upsert_entity(
        org_id="default",
        target_id="int-target",
        entity_type="domain",
        entity_value="invalid-state.example.com",
        new_attributes={},
        discovery_run_id=run_id,
    )

    result = await store.set_entity_triage_state("default", entity_id, "bogus")
    assert result is False


@pytest.mark.asyncio
async def test_upsert_relationship_by_value(store, run_id):
    src_id, _ = await store.upsert_entity(
        org_id="default",
        target_id="int-target",
        entity_type="domain",
        entity_value="parent.example.com",
        new_attributes={},
        discovery_run_id=run_id,
    )
    tgt_id, _ = await store.upsert_entity(
        org_id="default",
        target_id="int-target",
        entity_type="hostname",
        entity_value="sub.parent.example.com",
        new_attributes={},
        discovery_run_id=run_id,
    )

    await store.upsert_relationship_by_value(
        org_id="default",
        target_id="int-target",
        source_type="domain",
        source_value="parent.example.com",
        target_type="hostname",
        target_value="sub.parent.example.com",
        relationship_type="has_subdomain",
        relationship_source="test",
    )

    row = await store.pool.fetchrow(
        "SELECT source_entity_id, target_entity_id, relationship_type "
        "FROM entity_relationships WHERE source_entity_id = $1 AND target_entity_id = $2",
        src_id,
        tgt_id,
    )
    assert row is not None
    assert row["relationship_type"] == "has_subdomain"


@pytest.mark.asyncio
async def test_upsert_relationship_with_evidence_raw_event_id(store, raw_event_id, run_id):
    src_id, _ = await store.upsert_entity(
        org_id="default",
        target_id="int-target",
        entity_type="domain",
        entity_value="evidence-parent.example.com",
        new_attributes={},
        raw_event_id=raw_event_id,
        discovery_run_id=run_id,
    )
    tgt_id, _ = await store.upsert_entity(
        org_id="default",
        target_id="int-target",
        entity_type="ip",
        entity_value="1.2.3.4",
        new_attributes={},
        raw_event_id=raw_event_id,
        discovery_run_id=run_id,
    )

    await store.upsert_relationship(
        org_id="default",
        source_entity_id=src_id,
        target_entity_id=tgt_id,
        relationship_type="resolves_to",
        relationship_source="dns_resolve",
        evidence_raw_event_id=raw_event_id,
    )

    row = await store.pool.fetchrow(
        "SELECT evidence_raw_event_id FROM entity_relationships "
        "WHERE source_entity_id = $1 AND target_entity_id = $2",
        src_id,
        tgt_id,
    )
    assert row is not None
    assert row["evidence_raw_event_id"] == raw_event_id


@pytest.mark.asyncio
async def test_count_runs_with_filters(store):
    await store.create_run("target-a", "subfinder", "manual")
    await store.create_run("target-a", "asnmap", "scheduled")
    await store.create_run("target-b", "subfinder", "manual")

    total = await store.count_runs()
    assert total == 3

    a_runs = await store.count_runs(target_id="target-a")
    assert a_runs == 2

    sub_runs = await store.count_runs(source="subfinder")
    assert sub_runs == 2

    manual = await store.count_runs(trigger_type="manual")
    assert manual == 2


@pytest.mark.asyncio
async def test_count_events_with_filters(store, run_id):
    await store.insert_raw_event(
        "default", "int-target", "subfinder", {"a": 1}, run_id,
    )
    await store.insert_raw_event(
        "default", "int-target", "subfinder", {"a": 2}, run_id,
    )
    await store.insert_raw_event(
        "default", "int-target", "certstream", {"a": 3}, run_id,
    )

    total = await store.count_events()
    assert total == 3

    by_source = await store.count_events(source="subfinder")
    assert by_source == 2

    by_target = await store.count_events(target_id="int-target")
    assert by_target == 3

    nonexistent = await store.count_events(source="nonexistent")
    assert nonexistent == 0


@pytest.mark.asyncio
async def test_count_entities_with_type_filter(store, run_id):
    await store.upsert_entity(
        "default", "int-target", "domain", "a.example.com",
        new_attributes={}, discovery_run_id=run_id,
    )
    await store.upsert_entity(
        "default", "int-target", "domain", "b.example.com",
        new_attributes={}, discovery_run_id=run_id,
    )
    await store.upsert_entity(
        "default", "int-target", "ip", "1.2.3.4",
        new_attributes={}, discovery_run_id=run_id,
    )

    total = await store.count_entities()
    assert total == 3

    domains = await store.count_entities(entity_type="domain")
    assert domains == 2

    ips = await store.count_entities(entity_type="ip")
    assert ips == 1


@pytest.mark.asyncio
async def test_count_findings_with_filters(store):
    f1 = Finding(
        org_id="default",
        target_id="int-target",
        rule_id="test_rule_1",
        risk=RiskLevel.HIGH,
        headline="Test finding 1",
        entity_ids=[str(uuid.uuid4())],
        evidence={"key": "val"},
    )
    f2 = Finding(
        org_id="default",
        target_id="int-target",
        rule_id="test_rule_2",
        risk=RiskLevel.LOW,
        headline="Test finding 2",
    )
    await store.create_finding(f1)
    await store.create_finding(f2)

    total = await store.count_findings()
    assert total == 2

    high = await store.count_findings(risk="high")
    assert high == 1

    low = await store.count_findings(risk="low")
    assert low == 1

    by_rule = await store.count_findings(rule_id="test_rule_1")
    assert by_rule == 1


@pytest.mark.asyncio
async def test_get_triage_inbox_returns_total_count(store, run_id):
    for i in range(5):
        await store.upsert_entity(
            "default", "int-target", "domain", f"inbox{i}.example.com",
            new_attributes={}, discovery_run_id=run_id,
        )

    await store.upsert_entity(
        "default", "int-target", "domain", "adopted.example.com",
        new_attributes={}, discovery_run_id=run_id,
    )
    last = await store.pool.fetchrow(
        "SELECT id FROM entities WHERE entity_value = 'adopted.example.com'"
    )
    await store.set_entity_triage_state("default", last["id"], "adopted")

    inbox = await store.get_triage_inbox("default")
    assert len(inbox) == 5
    assert inbox[0]["total_count"] == 5


@pytest.mark.asyncio
async def test_entity_raw_event_links_cascade_on_raw_event_delete(store, run_id):
    eid = await store.insert_raw_event(
        "default", "int-target", "subfinder", {"cascade": True}, run_id,
    )
    assert eid is not None

    entity_id, _ = await store.upsert_entity(
        "default", "int-target", "domain", "cascade.example.com",
        new_attributes={}, raw_event_id=eid, discovery_run_id=run_id,
    )

    link_count = await store.pool.fetchval(
        "SELECT COUNT(*) FROM entity_raw_event_links WHERE entity_id = $1",
        entity_id,
    )
    assert link_count == 1

    await store.pool.execute("DELETE FROM raw_events WHERE id = $1", eid)

    link_count_after = await store.pool.fetchval(
        "SELECT COUNT(*) FROM entity_raw_event_links WHERE entity_id = $1",
        entity_id,
    )
    assert link_count_after == 0


@pytest.mark.asyncio
async def test_create_finding_round_trip(store):
    entity_id, _ = await store.upsert_entity(
        "default", "int-target", "domain", "finding-entity.example.com",
        new_attributes={},
    )
    finding = Finding(
        org_id="default",
        target_id="int-target",
        rule_id="test_rule_roundtrip",
        risk=RiskLevel.CRITICAL,
        headline="Critical finding",
        description="Something bad",
        entity_ids=[str(entity_id)],
        evidence={"key": "value"},
    )
    finding_id = await store.create_finding(finding)
    assert isinstance(finding_id, uuid.UUID)

    row = await store.get_finding(finding_id)
    assert row is not None
    assert row["headline"] == "Critical finding"
    assert row["risk"] == "critical"
    assert str(entity_id) in row["entity_ids"]
