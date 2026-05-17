from __future__ import annotations

import pytest
from pydantic import ValidationError

from easm.correlation.rule import (
    AnalysisMethod,
    AnalysisStep,
    CollectCondition,
    CollectMethod,
    CorrelationRule,
    Finding,
    RiskLevel,
    RuleMeta,
)


def test_collect_condition_exact():
    c = CollectCondition(method=CollectMethod.EXACT, field="entity_type", value="domain")
    assert c.method == CollectMethod.EXACT
    assert c.field == "entity_type"
    assert c.value == "domain"
    assert c.patterns is None


def test_collect_condition_regex():
    c = CollectCondition(
        method=CollectMethod.REGEX,
        field="entity_value",
        patterns=[".*dev.*", ".*test.*"],
    )
    assert c.method == CollectMethod.REGEX
    assert c.patterns == [".*dev.*", ".*test.*"]
    assert c.value is None


def test_collect_condition_attributes_path():
    c = CollectCondition(method=CollectMethod.EXACT, field="attributes.source", value="breach_monitor")
    assert c.field == "attributes.source"


def test_collect_condition_exact_requires_value():
    with pytest.raises(ValidationError):
        CollectCondition(method=CollectMethod.EXACT, field="entity_type")


def test_collect_condition_regex_requires_patterns():
    with pytest.raises(ValidationError):
        CollectCondition(method=CollectMethod.REGEX, field="entity_value")


def test_rule_meta_default_risk():
    m = RuleMeta(name="Test Rule", description="A test")
    assert m.risk == RiskLevel.MEDIUM
    assert m.name == "Test Rule"


def test_rule_meta_invalid_risk():
    with pytest.raises(ValidationError):
        RuleMeta(name="Bad", description="x", risk="extreme")  # type: ignore[arg-type]


def test_analysis_step_threshold():
    step = AnalysisStep(method=AnalysisMethod.THRESHOLD, field="attributes.keyword_matched", minimum=2)
    assert step.minimum == 2
    assert step.maximum is None


def test_correlation_rule_minimal():
    rule = CorrelationRule(
        id="test_rule",
        meta=RuleMeta(name="Test Rule", description="A test rule"),
        collect=[
            CollectCondition(method=CollectMethod.EXACT, field="entity_type", value="hostname"),
        ],
        aggregation={"field": "entity_value"},
        headline="Found: {entity_value}",
    )
    assert rule.id == "test_rule"
    assert rule.meta.risk == RiskLevel.MEDIUM
    assert len(rule.collect) == 1
    assert rule.analysis is None


def test_correlation_rule_full():
    rule = CorrelationRule(
        id="email_breach",
        meta=RuleMeta(name="Email Breach", description="Email in breach", risk="high"),
        collect=[
            CollectCondition(method=CollectMethod.EXACT, field="entity_type", value="finding"),
            CollectCondition(method=CollectMethod.EXACT, field="attributes.source", value="breach_monitor"),
        ],
        aggregation={"field": "attributes.keyword_matched"},
        headline="{attributes.keyword_matched} found in breach data",
        analysis=[AnalysisStep(method=AnalysisMethod.THRESHOLD, field="attributes.keyword_matched", minimum=1)],
    )
    assert rule.meta.risk == RiskLevel.HIGH


def test_finding_creation():
    f = Finding(
        org_id="default",
        target_id="test-target",
        rule_id="test_rule",
        risk="high",
        headline="Development system exposed: dev.example.com",
        entity_ids=["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"],
        evidence={"matched_entities": [{"entity_value": "dev.example.com"}]},
    )
    assert f.status == "open"
    assert f.risk == RiskLevel.HIGH
    assert f.description is None


def test_finding_with_description():
    f = Finding(
        org_id="default",
        target_id="test-target",
        rule_id="test_rule",
        risk="medium",
        headline="Found something",
        description="Detailed description here",
        entity_ids=[],
    )
    assert f.description == "Detailed description here"


def test_finding_invalid_risk():
    with pytest.raises(ValidationError):
        Finding(
            org_id="default",
            target_id="test-target",
            rule_id="test_rule",
            risk="invalid_risk",
            headline="test",
            entity_ids=[],
        )


def test_finding_invalid_status():
    with pytest.raises(ValidationError):
        Finding(
            org_id="default",
            target_id="test-target",
            rule_id="test_rule",
            risk="high",
            headline="test",
            entity_ids=[],
            status="unknown",
        )
