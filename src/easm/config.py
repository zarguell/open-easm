from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

VALID_RUNNER_NAMES = {
    "certstream", "subfinder", "asnmap", "crtsh", "dnstwist",
    "cloud_enum", "paste_monitor", "github_scan", "breach_monitor",
    "commoncrawl", "searchengine",
}
SCHEDULABLE_RUNNERS = {
    "subfinder", "asnmap", "crtsh", "dnstwist", "cloud_enum",
    "paste_monitor", "github_scan", "breach_monitor",
    "commoncrawl", "searchengine",
}


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


class CrtShRunnerConfig(BaseModel):
    enabled: bool = False
    schedule: str = "0 4 * * *"
    args: ScheduledRunnerArgs = Field(default_factory=ScheduledRunnerArgs)


class DnstwistRunnerConfig(BaseModel):
    enabled: bool = False
    schedule: str = "0 6 * * 1"
    args: ScheduledRunnerArgs = Field(default_factory=ScheduledRunnerArgs)


class PasteMonitorRunnerConfig(BaseModel):
    enabled: bool = False
    schedule: str = "*/5 * * * *"
    sources: list[str] = Field(default_factory=lambda: ["pastebin"])
    pastebin_api_key: str | None = None
    max_pastes_per_run: int = 100


class GithubScanRunnerConfig(BaseModel):
    enabled: bool = False
    schedule: str = "0 */4 * * *"
    github_token: str | None = None
    gitleaks_path: str = "gitleaks"
    search_queries: list[str] = Field(
        default_factory=lambda: ["credential_patterns", "domain_matches"],
    )


class BreachMonitorRunnerConfig(BaseModel):
    enabled: bool = False
    schedule: str = "0 6 * * *"
    sources: list[str] = Field(default_factory=lambda: ["hibp"])
    hibp_api_key: str | None = None
    dehashed_api_key: str | None = None
    dehashed_email: str | None = None


class CoverageConfig(BaseModel):
    apex_covers_subdomains: bool = False


class AllowedPivot(BaseModel):
    from_: str = Field(alias="from")
    to: str
    via: str
    cooldown_hours: int = 0
    coverage: CoverageConfig | None = None


class PivotConfig(BaseModel):
    enabled: bool = False
    max_depth: int = 3
    max_concurrent: int = 3
    batch_interval_ms: int = 200
    scope_mode: str = "strict"
    allowed_pivots: list[AllowedPivot] = Field(default_factory=list)


VALID_PIVOT_TYPES = {
    "dns_mail_records",
    "dns_resolve", "rdap_lookup", "crtsh_search",
    "shodan_enrich", "reverse_dns", "domain_rdap", "subdomain_enum",
    "tls_cert_grab", "geoip_enrich",
    "greynoise_enrich",
    "abuseipdb_enrich",
    "urlscan_enrich",
    "censys_enrich", "reverse_whois", "passive_dns", "subdomain_takeover",
}


class KeywordPattern(BaseModel):
    type: str
    pattern: str
    severity: str = "medium"

    @field_validator("severity")
    @classmethod
    def severity_must_be_valid(cls, v: str) -> str:
        if v not in ("high", "medium", "low"):
            raise ValueError(f"severity must be one of: high, medium, low, got: {v}")
        return v


class MatchRules(BaseModel):
    domains: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    asns: list[str] = Field(default_factory=list)
    ip_ranges: list[str] = Field(default_factory=list)
    keyword_patterns: list[KeywordPattern] = Field(default_factory=list)


class TargetConfig(BaseModel):
    id: str
    name: str
    type: str
    org_id: str = "default"
    enabled: bool = True
    labels: dict[str, str] = Field(default_factory=dict)
    match_rules: MatchRules = Field(default_factory=MatchRules)
    runners: dict[str, Any] = Field(default_factory=dict)
    pivot: PivotConfig = Field(default_factory=PivotConfig)

    @field_validator("id")
    @classmethod
    def id_must_be_api_safe(cls, v: str) -> str:
        if not v or not all(c.isalnum() or c == "-" for c in v):
            raise ValueError(f"Target id '{v}' must be alphanumeric with hyphens only")
        return v


ClassificationType = Literal["saas-hosted", "org-owned", "third-party-integrated"]


class SaasProviderRule(BaseModel):
    pattern: str
    provider: str
    classification: ClassificationType


class SaasProviderConfig(BaseModel):
    rules: list[SaasProviderRule] = Field(default_factory=list)


class AlertRule(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    condition: str
    severity: str = "medium"

    @field_validator("severity")
    @classmethod
    def severity_valid(cls, v: str) -> str:
        if v not in ("high", "medium", "low"):
            raise ValueError("severity must be high, medium, or low")
        return v


class AlertsConfig(BaseModel):
    rules: list[AlertRule] = Field(default_factory=list)


class Config(BaseModel):
    targets: list[TargetConfig]
    saas_providers: SaasProviderConfig = Field(default_factory=SaasProviderConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)

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
