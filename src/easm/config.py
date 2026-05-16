from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

VALID_RUNNER_NAMES = {"certstream", "subfinder", "asnmap"}
SCHEDULABLE_RUNNERS = {"subfinder", "asnmap"}


class CertStreamFilters(BaseModel):
    include_common_name: bool = True
    include_san_dns_names: bool = True
    match_mode: str = "suffix"


class CertStreamRunnerConfig(BaseModel):
    enabled: bool = False
    mode: str = "realtime"
    filters: CertStreamFilters = Field(default_factory=CertStreamFilters)


class ScheduledRunnerArgs(BaseModel):
    timeout_seconds: int = 300

    @field_validator("timeout_seconds")
    @classmethod
    def timeout_must_be_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("timeout_seconds must be positive")
        return v


class SubfinderRunnerArgs(ScheduledRunnerArgs):
    passive_only: bool = True
    recursive: bool = False


class AsnmapRunnerArgs(ScheduledRunnerArgs):
    expand_org_names: bool = False


class SubfinderRunnerConfig(BaseModel):
    enabled: bool = False
    schedule: str = "0 */6 * * *"
    args: SubfinderRunnerArgs = Field(default_factory=SubfinderRunnerArgs)


class AsnmapRunnerConfig(BaseModel):
    enabled: bool = False
    schedule: str = "0 2 * * *"
    args: AsnmapRunnerArgs = Field(default_factory=AsnmapRunnerArgs)


class MatchRules(BaseModel):
    domains: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    asns: list[str] = Field(default_factory=list)


class TargetConfig(BaseModel):
    id: str
    name: str
    type: str
    org_id: str = "default"
    enabled: bool = True
    labels: dict[str, str] = Field(default_factory=dict)
    match_rules: MatchRules = Field(default_factory=MatchRules)
    runners: dict[str, Any] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def id_must_be_api_safe(cls, v: str) -> str:
        if not v or not all(c.isalnum() or c == "-" for c in v):
            raise ValueError(f"Target id '{v}' must be alphanumeric with hyphens only")
        return v


class Config(BaseModel):
    targets: list[TargetConfig]

    @model_validator(mode="after")
    def validate_targets(self) -> Config:
        ids = [t.id for t in self.targets]
        if len(ids) != len(set(ids)):
            dupes = [i for i in ids if ids.count(i) > 1]
            raise ValueError(f"Duplicate target IDs found: {dupes}")
        return self

    @model_validator(mode="after")
    def validate_runners(self) -> Config:
        import re

        _cron_field = r"(\*(\/\d+)?|[0-5]?\d)"
        _cron_hour = r"(\*(\/\d+)?|1?\d|2[0-3])"
        _cron_day = r"(\*(\/\d+)?|[1-3]?\d)"
        _cron_month = r"(\*(\/\d+)?|1?\d|1[0-2])"
        _cron_dow = r"(\*(\/\d+)?|[0-7])"
        cron_re = re.compile(
            rf"^{_cron_field}\s+{_cron_hour}\s+{_cron_day}\s+{_cron_month}\s+{_cron_dow}$"
        )
        for target in self.targets:
            for runner_name, runner_cfg in target.runners.items():
                if runner_name not in VALID_RUNNER_NAMES:
                    raise ValueError(
                        f"Unknown runner '{runner_name}' in target '{target.id}'. "
                        f"Valid runners: {', '.join(sorted(VALID_RUNNER_NAMES))}"
                    )
                cfg_dict = runner_cfg if isinstance(runner_cfg, dict) else runner_cfg.model_dump()
                if runner_name in SCHEDULABLE_RUNNERS:
                    schedule = cfg_dict.get("schedule")
                    if schedule and not cron_re.match(schedule):
                        raise ValueError(
                            f"Invalid cron expression '{schedule}' "
                            f"for {runner_name} in target '{target.id}'"
                        )
        return self


def load_config(path: str | Path) -> Config:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    raw = yaml.safe_load(path.read_text())
    if raw is None:
        raise ValueError("Config file is empty")
    return Config.model_validate(raw)
