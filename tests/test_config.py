import pytest
import yaml
from pathlib import Path
from easm.config import Config, load_config


def make_yaml(tmp_path: Path, content: dict) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump(content))
    return path


def test_loads_valid_minimal_config(tmp_path: Path):
    cfg = make_yaml(tmp_path, {
        "targets": [{
            "id": "test-target",
            "name": "Test Target",
            "type": "organization",
            "enabled": True,
            "match_rules": {"domains": ["example.com"]},
            "runners": {},
        }]
    })
    config = load_config(cfg)
    assert len(config.targets) == 1
    assert config.targets[0].id == "test-target"


def test_rejects_duplicate_target_ids(tmp_path: Path):
    cfg = make_yaml(tmp_path, {
        "targets": [
            {"id": "dup", "name": "A", "type": "organization", "enabled": True, "match_rules": {}, "runners": {}},
            {"id": "dup", "name": "B", "type": "organization", "enabled": True, "match_rules": {}, "runners": {}},
        ]
    })
    with pytest.raises(ValueError, match="Duplicate target ID"):
        load_config(cfg)


def test_rejects_unknown_runner(tmp_path: Path):
    cfg = make_yaml(tmp_path, {
        "targets": [{
            "id": "t",
            "name": "T",
            "type": "organization",
            "enabled": True,
            "match_rules": {},
            "runners": {"nonexistent_runner": {"enabled": True}},
        }]
    })
    with pytest.raises(ValueError, match="Unknown runner"):
        load_config(cfg)


def test_rejects_invalid_cron(tmp_path: Path):
    cfg = make_yaml(tmp_path, {
        "targets": [{
            "id": "t",
            "name": "T",
            "type": "organization",
            "enabled": True,
            "match_rules": {},
            "runners": {"subfinder": {"enabled": True, "schedule": "not-a-cron"}},
        }]
    })
    with pytest.raises(ValueError, match="Invalid cron"):
        load_config(cfg)


def test_labels_are_optional(tmp_path: Path):
    cfg = make_yaml(tmp_path, {
        "targets": [{
            "id": "t", "name": "T", "type": "organization", "enabled": True, "match_rules": {}, "runners": {}
        }]
    })
    config = load_config(cfg)
    assert config.targets[0].labels == {}


def test_disabled_target_valid(tmp_path: Path):
    cfg = make_yaml(tmp_path, {
        "targets": [{
            "id": "t",
            "name": "T",
            "type": "organization",
            "enabled": False,
            "match_rules": {},
            "runners": {"subfinder": {"enabled": True, "schedule": "0 */6 * * *", "args": {"timeout_seconds": 300}}},
        }]
    })
    config = load_config(cfg)
    assert config.targets[0].enabled is False


def test_optional_match_rules_fields(tmp_path: Path):
    cfg = make_yaml(tmp_path, {
        "targets": [{
            "id": "t", "name": "T", "type": "organization", "enabled": True,
            "match_rules": {"domains": ["x.com"]}, "runners": {}
        }]
    })
    config = load_config(cfg)
    assert config.targets[0].match_rules.keywords == []
    assert config.targets[0].match_rules.asns == []
