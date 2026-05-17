from __future__ import annotations

import uuid

import pytest

from easm.correlation.findings_store import FindingsStore
from easm.correlation.rule import Finding


@pytest.fixture
def store(db_pool):
    return FindingsStore(db_pool)


@pytest.mark.asyncio
async def test_create_finding(store: FindingsStore):
    f = Finding(
        org_id="default",
        target_id="test-target",
        rule_id="test_rule",
        risk="high",
        headline="Test finding",
        description="A detailed description",
        entity_ids=[str(uuid.uuid7())],
        evidence={"key": "value"},
    )
    finding_id = await store.create_finding(f)
    assert finding_id is not None
    assert isinstance(finding_id, uuid.UUID)


@pytest.mark.asyncio
async def test_create_finding_minimal(store: FindingsStore):
    f = Finding(
        org_id="default",
        target_id="test-target",
        rule_id="minimal_rule",
        risk="low",
        headline="Minimal finding",
        entity_ids=[],
    )
    finding_id = await store.create_finding(f)
    assert finding_id is not None


@pytest.mark.asyncio
async def test_list_findings_empty(store: FindingsStore):
    results = await store.list_findings(target_id="test-target")
    assert results == []


@pytest.mark.asyncio
async def test_list_findings_with_data(store: FindingsStore):
    f1 = Finding(org_id="default", target_id="test-target", rule_id="rule_a", risk="high", headline="Finding A", entity_ids=[])
    f2 = Finding(org_id="default", target_id="test-target", rule_id="rule_b", risk="low", headline="Finding B", entity_ids=[])
    await store.create_finding(f1)
    await store.create_finding(f2)

    results = await store.list_findings(target_id="test-target")
    assert len(results) == 2


@pytest.mark.asyncio
async def test_list_findings_filter_by_risk(store: FindingsStore):
    f1 = Finding(org_id="default", target_id="test-target", rule_id="rule_a", risk="high", headline="High", entity_ids=[])
    f2 = Finding(org_id="default", target_id="test-target", rule_id="rule_b", risk="low", headline="Low", entity_ids=[])
    await store.create_finding(f1)
    await store.create_finding(f2)

    results = await store.list_findings(target_id="test-target", risk="high")
    assert len(results) == 1
    assert results[0]["headline"] == "High"


@pytest.mark.asyncio
async def test_list_findings_filter_by_status(store: FindingsStore):
    f1 = Finding(org_id="default", target_id="test-target", rule_id="rule_a", risk="high", headline="Open", entity_ids=[])
    f2 = Finding(org_id="default", target_id="test-target", rule_id="rule_b", risk="low", headline="Resolved", entity_ids=[], status="resolved")
    await store.create_finding(f1)
    await store.create_finding(f2)

    results = await store.list_findings(target_id="test-target", status="open")
    assert len(results) == 1
    assert results[0]["headline"] == "Open"


@pytest.mark.asyncio
async def test_list_findings_filter_by_rule_id(store: FindingsStore):
    f1 = Finding(org_id="default", target_id="test-target", rule_id="rule_a", risk="high", headline="A", entity_ids=[])
    f2 = Finding(org_id="default", target_id="test-target", rule_id="rule_b", risk="low", headline="B", entity_ids=[])
    await store.create_finding(f1)
    await store.create_finding(f2)

    results = await store.list_findings(target_id="test-target", rule_id="rule_a")
    assert len(results) == 1
    assert results[0]["rule_id"] == "rule_a"


@pytest.mark.asyncio
async def test_get_finding(store: FindingsStore):
    f = Finding(org_id="default", target_id="test-target", rule_id="test_rule", risk="medium", headline="Get me", entity_ids=[])
    finding_id = await store.create_finding(f)

    result = await store.get_finding(finding_id)
    assert result is not None
    assert result["headline"] == "Get me"
    assert result["rule_id"] == "test_rule"
    assert result["risk"] == "medium"


@pytest.mark.asyncio
async def test_get_finding_not_found(store: FindingsStore):
    result = await store.get_finding(uuid.UUID("00000000-0000-0000-0000-000000000000"))
    assert result is None


@pytest.mark.asyncio
async def test_update_finding_status(store: FindingsStore):
    f = Finding(org_id="default", target_id="test-target", rule_id="test_rule", risk="high", headline="Update me", entity_ids=[])
    finding_id = await store.create_finding(f)

    await store.update_finding_status(finding_id, "acknowledged")
    result = await store.get_finding(finding_id)
    assert result is not None
    assert result["status"] == "acknowledged"


@pytest.mark.asyncio
async def test_update_finding_status_resolved(store: FindingsStore):
    f = Finding(org_id="default", target_id="test-target", rule_id="test_rule", risk="high", headline="Resolve me", entity_ids=[])
    finding_id = await store.create_finding(f)

    await store.update_finding_status(finding_id, "resolved")
    result = await store.get_finding(finding_id)
    assert result["status"] == "resolved"


@pytest.mark.asyncio
async def test_finding_has_timestamps(store: FindingsStore):
    f = Finding(org_id="default", target_id="test-target", rule_id="test_rule", risk="info", headline="Timestamp test", entity_ids=[])
    finding_id = await store.create_finding(f)

    result = await store.get_finding(finding_id)
    assert result["first_seen_at"] is not None
    assert result["last_seen_at"] is not None
    assert result["created_at"] is not None
