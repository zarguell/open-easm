from pathlib import Path

from easm.correlation.loader import load_rules_from_dir


def test_known_exploited_rule_loads():
    rules_dir = Path(__file__).parent.parent / "correlations"
    rules = load_rules_from_dir(rules_dir)
    rule_ids = {r.id for r in rules}
    assert "known_exploited_vulnerability" in rule_ids
