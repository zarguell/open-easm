from __future__ import annotations

import json
import uuid

import pytest

from easm.correlation.engine import CorrelationEngine
from easm.correlation.rule import (
    AnalysisMethod,
    AnalysisStep,
    CollectCondition,
    CollectMethod,
    CorrelationRule,
    RuleMeta,
)


@pytest.fixture
def engine(db_pool) -> CorrelationEngine:
    return CorrelationEngine(pool=db_pool)


@pytest.fixture
def sample_rule() -> CorrelationRule:
    return CorrelationRule(
        id="dev_or_test_system",
        meta=RuleMeta(name="Dev/Test System", description="Hostname with dev/test in name", risk="medium"),
        collect=[
            CollectCondition(method=CollectMethod.EXACT, field="entity_type", value="hostname"),
            CollectCondition(method=CollectMethod.REGEX, field="entity_value", patterns=[".*dev.*", ".*test.*"]),
        ],
        aggregation={"field": "entity_value"},
        headline="Development system exposed: {entity_value}",
    )


@pytest.mark.asyncio
async def test_collect_exact_match(engine: CorrelationEngine, seed_entities):
    rule = CorrelationRule(
        id="test_exact",
        meta=RuleMeta(name="Test", description="x", risk="info"),
        collect=[CollectCondition(method=CollectMethod.EXACT, field="entity_type", value="ip")],
        aggregation={"field": "entity_value"},
        headline="Found IP: {entity_value}",
    )
    results = await engine._collect(rule, "default", "test-target")
    assert len(results) == 1
    assert results[0]["entity_type"] == "ip"
    assert results[0]["entity_value"] == "192.168.1.1"


@pytest.mark.asyncio
async def test_collect_regex_match(engine: CorrelationEngine, seed_entities):
    rule = CorrelationRule(
        id="test_regex",
        meta=RuleMeta(name="Test", description="x", risk="info"),
        collect=[CollectCondition(method=CollectMethod.REGEX, field="entity_value", patterns=[".*dev.*", ".*test.*"])],
        aggregation={"field": "entity_value"},
        headline="Dev/test: {entity_value}",
    )
    results = await engine._collect(rule, "default", "test-target")
    assert len(results) == 2
    values = {r["entity_value"] for r in results}
    assert values == {"dev.example.com", "test-api.example.com"}


@pytest.mark.asyncio
async def test_collect_exact_and_regex(engine: CorrelationEngine, seed_entities):
    rule = CorrelationRule(
        id="dev_or_test_system",
        meta=RuleMeta(name="Dev/Test", description="x", risk="medium"),
        collect=[
            CollectCondition(method=CollectMethod.EXACT, field="entity_type", value="hostname"),
            CollectCondition(method=CollectMethod.REGEX, field="entity_value", patterns=[".*dev.*", ".*test.*"]),
        ],
        aggregation={"field": "entity_value"},
        headline="Dev/test system: {entity_value}",
    )
    results = await engine._collect(rule, "default", "test-target")
    assert len(results) == 2
    for r in results:
        assert r["entity_type"] == "hostname"


@pytest.mark.asyncio
async def test_collect_attributes_exact(engine: CorrelationEngine, seed_entities):
    rule = CorrelationRule(
        id="test_attrs",
        meta=RuleMeta(name="Test", description="x", risk="info"),
        collect=[CollectCondition(method=CollectMethod.EXACT, field="attributes.source", value="subfinder")],
        aggregation={"field": "entity_value"},
        headline="Subfinder: {entity_value}",
    )
    results = await engine._collect(rule, "default", "test-target")
    assert len(results) == 3


@pytest.mark.asyncio
async def test_collect_no_match(engine: CorrelationEngine, seed_entities):
    rule = CorrelationRule(
        id="no_match",
        meta=RuleMeta(name="No match", description="x", risk="info"),
        collect=[CollectCondition(method=CollectMethod.EXACT, field="entity_type", value="certificate")],
        aggregation={"field": "entity_value"},
        headline="No match",
    )
    results = await engine._collect(rule, "default", "test-target")
    assert results == []


@pytest.mark.asyncio
async def test_aggregate_by_entity_value(engine: CorrelationEngine, seed_entities):
    matched = [
        {"entity_value": "dev.example.com", "entity_type": "hostname", "id": str(uuid.uuid7())},
        {"entity_value": "dev.example.com", "entity_type": "hostname", "id": str(uuid.uuid7())},
        {"entity_value": "test.example.com", "entity_type": "hostname", "id": str(uuid.uuid7())},
    ]
    rule = CorrelationRule(
        id="test_agg",
        meta=RuleMeta(name="Test", description="x", risk="info"),
        collect=[CollectCondition(method=CollectMethod.EXACT, field="entity_type", value="hostname")],
        aggregation={"field": "entity_value"},
        headline="Agg: {entity_value}",
    )
    groups = engine._aggregate(matched, rule)
    assert "dev.example.com" in groups
    assert "test.example.com" in groups
    assert len(groups["dev.example.com"]) == 2
    assert len(groups["test.example.com"]) == 1


@pytest.mark.asyncio
async def test_analyze_threshold_passes(engine: CorrelationEngine):
    rule = CorrelationRule(
        id="test_threshold",
        meta=RuleMeta(name="Test", description="x", risk="high"),
        collect=[CollectCondition(method=CollectMethod.EXACT, field="entity_type", value="hostname")],
        aggregation={"field": "entity_value"},
        headline="Threshold: {entity_value}",
        analysis=[AnalysisStep(method=AnalysisMethod.THRESHOLD, field="entity_value", minimum=2)],
    )
    groups = {
        "group_a": [{"entity_value": "group_a"}, {"entity_value": "group_a"}],
        "group_b": [{"entity_value": "group_b"}],
    }
    passing = {key: entities for key, entities in groups.items() if engine._analyze(entities, rule)}
    assert "group_a" in passing
    assert "group_b" not in passing


@pytest.mark.asyncio
async def test_analyze_no_analysis_all_pass(engine: CorrelationEngine):
    rule = CorrelationRule(
        id="test_no_analysis",
        meta=RuleMeta(name="Test", description="x", risk="low"),
        collect=[CollectCondition(method=CollectMethod.EXACT, field="entity_type", value="hostname")],
        aggregation={"field": "entity_value"},
        headline="All pass: {entity_value}",
    )
    groups = {
        "a": [{"entity_value": "a"}],
        "b": [{"entity_value": "b"}, {"entity_value": "b"}],
    }
    for entities in groups.values():
        assert engine._analyze(entities, rule) is True


@pytest.mark.asyncio
async def test_evaluate_full_pipeline(engine: CorrelationEngine, seed_entities, sample_rule):
    results = await engine.evaluate(sample_rule, "default", "test-target")
    assert len(results) == 2
    headlines = {r.headline for r in results}
    assert "Development system exposed: dev.example.com" in headlines
    assert "Development system exposed: test-api.example.com" in headlines
    for f in results:
        assert f.rule_id == "dev_or_test_system"
        assert f.risk.value == "medium"
        assert f.target_id == "test-target"
        assert f.org_id == "default"
        assert len(f.entity_ids) == 1


@pytest.mark.asyncio
async def test_evaluate_no_matches(engine: CorrelationEngine, db_pool):
    rule = CorrelationRule(
        id="no_match",
        meta=RuleMeta(name="No match", description="x", risk="info"),
        collect=[CollectCondition(method=CollectMethod.EXACT, field="entity_type", value="certificate")],
        aggregation={"field": "entity_value"},
        headline="No match: {entity_value}",
    )
    results = await engine.evaluate(rule, "default", "test-target")
    assert results == []


@pytest.mark.asyncio
async def test_evaluate_with_threshold(engine: CorrelationEngine, db_pool):
    rule = CorrelationRule(
        id="multi_occurrence",
        meta=RuleMeta(name="Multi", description="Entities appearing multiple times", risk="high"),
        collect=[CollectCondition(method=CollectMethod.EXACT, field="entity_type", value="hostname")],
        aggregation={"field": "entity_value"},
        headline="Multi: {entity_value}",
        analysis=[AnalysisStep(method=AnalysisMethod.THRESHOLD, field="entity_value", minimum=2)],
    )
    run_id = uuid.uuid7()
    event_id = uuid.uuid7()
    async with db_pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO runs (id, target_id, source, trigger_type, status) VALUES ($1, $2, $3, $4, $5)",
            run_id, "test-target", "test", "manual", "completed",
        )
        await conn.execute(
            "INSERT INTO raw_events (id, org_id, target_id, source, raw, event_hash, run_id) VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, $6)",
            event_id, "default", "test-target", "test", "hash-threshold", run_id,
        )
        for i in range(4):
            await conn.execute(
                """INSERT INTO entities (org_id, target_id, entity_type, entity_value, attributes)
                   VALUES ($1, $2, $3, $4, $5::jsonb)""",
                "default", "test-target", "hostname", f"host-{i}.example.com", json.dumps({}),
            )

    results = await engine.evaluate(rule, "default", "test-target")
    # Unique constraint means each entity_value appears once, so no group has 2+ entities
    assert len(results) == 0


@pytest.mark.asyncio
async def test_evaluate_rules(engine: CorrelationEngine, seed_entities):
    rules = [
        CorrelationRule(
            id="rule_one",
            meta=RuleMeta(name="Rule 1", description="x", risk="high"),
            collect=[CollectCondition(method=CollectMethod.EXACT, field="entity_type", value="hostname")],
            aggregation={"field": "entity_value"},
            headline="Hostname: {entity_value}",
        ),
        CorrelationRule(
            id="rule_two",
            meta=RuleMeta(name="Rule 2", description="x", risk="low"),
            collect=[CollectCondition(method=CollectMethod.EXACT, field="entity_type", value="ip")],
            aggregation={"field": "entity_value"},
            headline="IP: {entity_value}",
        ),
    ]
    results = await engine.evaluate_rules(rules, "default", "test-target")
    assert len(results) == 4
    rule_ids = {f.rule_id for f in results}
    assert rule_ids == {"rule_one", "rule_two"}
