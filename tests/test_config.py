from pathlib import Path

import pytest
import yaml

from easm.config import load_config


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


def test_runtime_config_defaults_to_live(tmp_path):
    path = make_yaml(tmp_path, {
        "targets": [{
            "id": "t",
            "name": "T",
            "type": "organization",
            "enabled": False,
            "match_rules": {},
            "runners": {},
        }],
    })
    config = load_config(path)
    assert config.runtime.mode == "live"
    assert config.runtime.allow_external_network is True
    assert config.runtime.allow_subprocess is True
    assert config.runtime.allow_active_scanning is False
    assert config.runtime.refresh_kev_on_startup is True


def test_runtime_config_parses_simulation_mode(tmp_path):
    path = make_yaml(tmp_path, {
        "runtime": {
            "mode": "simulate",
            "fixtures_path": "fixtures/simulation",
            "allow_external_network": False,
            "allow_subprocess": False,
            "allow_active_scanning": False,
            "refresh_kev_on_startup": False,
        },
        "targets": [{
            "id": "offline",
            "name": "Offline",
            "type": "organization",
            "enabled": True,
            "match_rules": {"domains": ["example.invalid"]},
            "runners": {},
        }],
    })
    config = load_config(path)
    assert config.runtime.mode == "simulate"
    assert str(config.runtime.fixtures_path).endswith("fixtures/simulation")
    assert config.runtime.allow_external_network is False
    assert config.runtime.refresh_kev_on_startup is False


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


from easm.config import SaasProviderRule, SaasProviderConfig


def test_saas_provider_rule_valid():
    rule = SaasProviderRule(
        pattern="*.amazonaws.com",
        provider="aws",
        classification="saas-hosted",
    )
    assert rule.pattern == "*.amazonaws.com"
    assert rule.provider == "aws"
    assert rule.classification == "saas-hosted"


def test_saas_provider_rule_rejects_invalid_classification():
    import pytest
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        SaasProviderRule(
            pattern="*.foo.com",
            provider="unknown",
            classification="invalid_value",
        )


def test_saas_provider_config_default_empty():
    cfg = SaasProviderConfig()
    assert cfg.rules == []


def test_saas_provider_config_from_list():
    cfg = SaasProviderConfig(
        rules=[
            {"pattern": "*.amazonaws.com", "provider": "aws", "classification": "saas-hosted"},
        ]
    )
    assert len(cfg.rules) == 1


def test_saas_providers_parsed_from_yaml(tmp_path):
    from easm.config import load_config
    import yaml
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump({
        "targets": [{
            "id": "t", "name": "T", "type": "org", "enabled": True,
            "match_rules": {"domains": ["example.com"]},
            "runners": {},
        }],
        "saas_providers": {
            "rules": [
                {"pattern": "*.amazonaws.com", "provider": "aws", "classification": "saas-hosted"},
                {"pattern": "*.cloudfront.net", "provider": "aws", "classification": "saas-hosted"},
            ],
        },
    }))
    config = load_config(path)
    assert len(config.saas_providers.rules) == 2
    assert config.saas_providers.rules[0].provider == "aws"


def test_saas_providers_optional(tmp_path):
    from easm.config import load_config
    import yaml
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump({
        "targets": [{
            "id": "t", "name": "T", "type": "org", "enabled": True,
            "match_rules": {"domains": ["example.com"]},
            "runners": {},
        }],
    }))
    config = load_config(path)
    assert len(config.saas_providers.rules) == 0


from easm.config import KeywordPattern


def test_keyword_pattern_valid():
    kp = KeywordPattern(type="email", pattern="@example\\.com", severity="high")
    assert kp.type == "email"
    assert kp.pattern == "@example\\.com"
    assert kp.severity == "high"


def test_keyword_pattern_severity_default():
    kp = KeywordPattern(type="custom", pattern="AKIA[A-Z0-9]{16}")
    assert kp.severity == "medium"


def test_keyword_pattern_rejects_invalid_severity():
    from pydantic import ValidationError
    import pytest
    with pytest.raises(ValidationError):
        KeywordPattern(type="custom", pattern="test", severity="critical")


def test_match_rules_can_include_keyword_patterns():
    from easm.config import MatchRules
    rules = MatchRules(
        domains=["example.com"],
        keyword_patterns=[
            {"type": "api_key", "pattern": "AKIA[0-9A-Z]{16}", "severity": "high"},
            {"type": "hostname", "pattern": "internal\\.example\\.com", "severity": "high"},
        ],
    )
    assert len(rules.keyword_patterns) == 2
    assert rules.keyword_patterns[0].type == "api_key"


def test_keyword_patterns_parsed_from_yaml(tmp_path):
    from easm.config import load_config
    import yaml
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump({
        "targets": [{
            "id": "t", "name": "T", "type": "org", "enabled": True,
            "match_rules": {
                "domains": ["example.com"],
                "keyword_patterns": [
                    {"type": "api_key", "pattern": "AKIA[0-9A-Z]{16}", "severity": "high"},
                ],
            },
            "runners": {},
        }],
    }))
    config = load_config(path)
    assert len(config.targets[0].match_rules.keyword_patterns) == 1
    assert config.targets[0].match_rules.keyword_patterns[0].pattern == "AKIA[0-9A-Z]{16}"


def test_keyword_patterns_optional(tmp_path):
    from easm.config import load_config
    import yaml
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump({
        "targets": [{
            "id": "t", "name": "T", "type": "org", "enabled": True,
            "match_rules": {"domains": ["example.com"]},
            "runners": {},
        }],
    }))
    config = load_config(path)
    assert config.targets[0].match_rules.keyword_patterns == []


def test_valid_paste_monitor_config(tmp_path: Path):
    cfg = make_yaml(tmp_path, {
        "targets": [{
            "id": "t",
            "name": "T",
            "type": "organization",
            "enabled": True,
            "match_rules": {},
            "runners": {"paste_monitor": {"enabled": True, "schedule": "*/5 * * * *"}},
        }]
    })
    config = load_config(cfg)
    assert config.targets[0].runners["paste_monitor"].enabled is True


def test_valid_github_scan_config(tmp_path: Path):
    cfg = make_yaml(tmp_path, {
        "targets": [{
            "id": "t",
            "name": "T",
            "type": "organization",
            "enabled": True,
            "match_rules": {},
            "runners": {"github_scan": {"enabled": True, "schedule": "0 */4 * * *"}},
        }]
    })
    config = load_config(cfg)
    assert config.targets[0].runners["github_scan"].enabled is True


def test_valid_breach_monitor_config(tmp_path: Path):
    cfg = make_yaml(tmp_path, {
        "targets": [{
            "id": "t",
            "name": "T",
            "type": "organization",
            "enabled": True,
            "match_rules": {},
            "runners": {"breach_monitor": {"enabled": True, "schedule": "0 6 * * *"}},
        }]
    })
    config = load_config(cfg)
    assert config.targets[0].runners["breach_monitor"].enabled is True


def test_rejects_unknown_cron_new_runners(tmp_path: Path):
    cfg = make_yaml(tmp_path, {
        "targets": [{
            "id": "t",
            "name": "T",
            "type": "organization",
            "enabled": True,
            "match_rules": {},
            "runners": {"paste_monitor": {"enabled": True, "schedule": "invalid-cron"}},
        }]
    })
    with pytest.raises(ValueError, match="Invalid cron"):
        load_config(cfg)
