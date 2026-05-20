from pathlib import Path

from easm.correlation.loader import load_rules_from_dir


def test_saas_hosted_infrastructure_rule_loads():
    rules_path = Path(__file__).parents[2] / "correlations"
    rules = load_rules_from_dir(rules_path)
    names = [r.meta.name for r in rules]
    assert "saas_hosted_infrastructure" in [r.id for r in rules]


def test_saas_hosted_infrastructure_rule_severity():
    rules_path = Path(__file__).parents[2] / "correlations"
    rules = load_rules_from_dir(rules_path)
    rule = next(r for r in rules if r.id == "saas_hosted_infrastructure")
    assert rule.meta.risk.value == "low"


def test_saas_hosted_infrastructure_rule_collects_hostnames():
    rules_path = Path(__file__).parents[2] / "correlations"
    rules = load_rules_from_dir(rules_path)
    rule = next(r for r in rules if r.id == "saas_hosted_infrastructure")
    assert len(rule.collect) >= 1
    assert rule.collect[0].value == "hostname"
