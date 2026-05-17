from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from easm.correlation.loader import load_rule_from_file, load_rules_from_dir
from easm.correlation.rule import CorrelationRule


def test_load_rule_from_file(tmp_path: Path):
    rule_yaml = """
id: dev_or_test_system
meta:
  name: "Development or test system on public internet"
  risk: medium
  description: "A host containing dev/test/staging/uat was found exposed."
collect:
  - method: exact
    field: entity_type
    value: hostname
  - method: regex
    field: entity_value
    patterns: [".*dev.*", ".*test.*", ".*staging.*", ".*uat.*"]
aggregation:
  field: entity_value
headline: "Development system exposed: {entity_value}"
"""
    rule_file = tmp_path / "dev_or_test_system.yaml"
    rule_file.write_text(rule_yaml)

    rule = load_rule_from_file(rule_file)
    assert isinstance(rule, CorrelationRule)
    assert rule.id == "dev_or_test_system"
    assert rule.meta.risk.value == "medium"
    assert len(rule.collect) == 2
    assert rule.aggregation.field == "entity_value"


def test_load_rule_from_file_with_analysis(tmp_path: Path):
    rule_yaml = """
id: email_in_breach
meta:
  name: "Email found in breach data"
  risk: high
  description: "An email pattern was found in breach monitoring data."
collect:
  - method: exact
    field: entity_type
    value: hostname
aggregation:
  field: entity_value
headline: "Email pattern in breach: {entity_value}"
analysis:
  - method: threshold
    field: entity_value
    minimum: 1
"""
    rule_file = tmp_path / "email_in_breach.yaml"
    rule_file.write_text(rule_yaml)

    rule = load_rule_from_file(rule_file)
    assert rule.analysis is not None
    assert len(rule.analysis) == 1
    assert rule.analysis[0].method.value == "threshold"
    assert rule.analysis[0].minimum == 1


def test_load_rule_from_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_rule_from_file(Path("/nonexistent/path.yaml"))


def test_load_rule_from_file_invalid_yaml(tmp_path: Path):
    rule_file = tmp_path / "bad.yaml"
    rule_file.write_text("id: broken\nthis is not valid yaml: \n  - [")

    with pytest.raises(ValueError, match="Failed to parse YAML"):
        load_rule_from_file(rule_file)


def test_load_rule_from_file_invalid_structure(tmp_path: Path):
    rule_file = tmp_path / "bad.yaml"
    rule_file.write_text("random_key: value\n")

    with pytest.raises(ValueError, match="Failed to validate rule"):
        load_rule_from_file(rule_file)


def test_load_rules_from_dir(tmp_path: Path):
    rules_dir = tmp_path / "correlations"
    rules_dir.mkdir()

    (rules_dir / "rule_one.yaml").write_text("""
id: rule_one
meta:
  name: "Rule One"
  risk: low
  description: "First rule"
collect:
  - method: exact
    field: entity_type
    value: domain
aggregation:
  field: entity_value
headline: "Rule one: {entity_value}"
""")
    (rules_dir / "rule_two.yaml").write_text("""
id: rule_two
meta:
  name: "Rule Two"
  risk: high
  description: "Second rule"
collect:
  - method: exact
    field: entity_type
    value: ip
aggregation:
  field: entity_value
headline: "Rule two: {entity_value}"
""")
    (rules_dir / "not_a_rule.txt").write_text("this is ignored")

    rules = load_rules_from_dir(rules_dir)
    assert len(rules) == 2
    rule_ids = {r.id for r in rules}
    assert rule_ids == {"rule_one", "rule_two"}


def test_load_rules_from_dir_empty(tmp_path: Path):
    rules_dir = tmp_path / "empty"
    rules_dir.mkdir()

    rules = load_rules_from_dir(rules_dir)
    assert rules == []


def test_load_rules_from_dir_not_found():
    with pytest.raises(FileNotFoundError):
        load_rules_from_dir(Path("/nonexistent"))
