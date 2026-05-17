from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from easm.correlation.engine import CorrelationEngine
from easm.correlation.findings_store import FindingsStore
from easm.correlation.loader import load_rules_from_dir
from easm.correlation.rule import RiskLevel

CORRELATIONS_DIR = Path(__file__).parent.parent.parent / "correlations"


@pytest.fixture
def engine(db_pool) -> CorrelationEngine:
    return CorrelationEngine(pool=db_pool)


@pytest.fixture
def findings_store(db_pool) -> FindingsStore:
    return FindingsStore(db_pool)


@pytest.fixture
def loaded_rules():
    return load_rules_from_dir(CORRELATIONS_DIR)


@pytest.mark.asyncio
async def test_rules_load_and_validate(loaded_rules):
    assert len(loaded_rules) >= 1
    for rule in loaded_rules:
        assert rule.id is not None
        assert rule.meta.risk in RiskLevel._value2member_map_
        assert len(rule.collect) >= 1


@pytest.mark.asyncio
async def test_full_pipeline_integration(engine: CorrelationEngine, findings_store: FindingsStore, db_pool):
    run_id = uuid.uuid7()
    event_id = uuid.uuid7()
    async with db_pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO runs (id, target_id, source, trigger_type, status) VALUES ($1, $2, $3, $4, $5)",
            run_id, "test-target", "test", "manual", "completed",
        )
        await conn.execute(
            """INSERT INTO raw_events (id, org_id, target_id, source, raw, event_hash, run_id)
               VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, $6)""",
            event_id, "default", "test-target", "test", "hash-integration", run_id,
        )
        for evalue in ["dev.example.com", "test-api.example.com", "prod.example.com"]:
            await conn.execute(
                """INSERT INTO entities (org_id, target_id, entity_type, entity_value, attributes)
                   VALUES ($1, $2, $3, $4, '{}'::jsonb)""",
                "default", "test-target", "hostname", evalue,
            )

    rules = load_rules_from_dir(CORRELATIONS_DIR)
    findings = await engine.evaluate_rules(rules, "default", "test-target")

    assert len(findings) > 0

    for f in findings:
        finding_id = await findings_store.create_finding(f)
        assert finding_id is not None

    saved = await findings_store.list_findings(target_id="test-target")
    assert len(saved) == len(findings)


@pytest.mark.asyncio
async def test_engine_dedupes_rule_ids(engine: CorrelationEngine, seed_entities):
    rules = load_rules_from_dir(CORRELATIONS_DIR)
    findings = await engine.evaluate_rules(rules, "default", "test-target")
    rule_ids = [f.rule_id for f in findings]
    headline_ids = {(f.rule_id, f.headline) for f in findings}
    assert len(headline_ids) == len(rule_ids)
