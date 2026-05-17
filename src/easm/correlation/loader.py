from __future__ import annotations

from pathlib import Path

import yaml

from easm.correlation.rule import CorrelationRule


def load_rule_from_file(path: Path) -> CorrelationRule:
    if not path.exists():
        raise FileNotFoundError(f"Rule file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        raise ValueError(f"Failed to parse YAML in {path}: {e}") from e

    if raw is None:
        raise ValueError(f"Empty rule file: {path}")

    try:
        return CorrelationRule.model_validate(raw)
    except Exception as e:
        raise ValueError(f"Failed to validate rule in {path}: {e}") from e


def load_rules_from_dir(directory: Path) -> list[CorrelationRule]:
    if not directory.exists():
        raise FileNotFoundError(f"Correlations directory not found: {directory}")

    rules: list[CorrelationRule] = []
    for fpath in sorted(directory.iterdir()):
        if fpath.suffix.lower() in (".yaml", ".yml"):
            try:
                rule = load_rule_from_file(fpath)
                rules.append(rule)
            except ValueError:
                continue
    return rules
