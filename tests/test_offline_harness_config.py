from __future__ import annotations

from pathlib import Path

import pytest

from easm.config import load_config

REPO_ROOT = Path(__file__).parents[1]


@pytest.mark.simulation
def test_offline_config_is_safe_and_fixture_backed() -> None:
    config = load_config(REPO_ROOT / "config.offline.yaml")

    assert config.runtime.mode == "simulate"
    assert config.runtime.allow_external_network is False
    assert config.runtime.allow_subprocess is False
    assert config.runtime.allow_active_scanning is False
    assert config.runtime.refresh_kev_on_startup is False

    target = next(t for t in config.targets if t.id == "offline-local")
    assert target.match_rules.domains == ["example.invalid"]
    assert target.runners["subfinder"].enabled is True
    assert target.runners["crtsh"].enabled is True

    fixtures = REPO_ROOT / Path(config.runtime.fixtures_path)
    assert (fixtures / "runners" / "subfinder.jsonl").is_file()
    assert (fixtures / "http" / "crtsh.json").is_file()
    assert (fixtures / "pivots" / "dns_resolve.json").is_file()
