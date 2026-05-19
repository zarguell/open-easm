from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

VALID_RUNNER_NAMES = {
    "certstream", "subfinder", "asnmap", "crtsh", "dnstwist", "certspotter",
    "cloud_enum", "paste_monitor", "gist_monitor", "stackoverflow_monitor", "discord_monitor",
    "github_scan", "breach_monitor",
    "commoncrawl", "searchengine",
    "wappalyzer", "screenshot", "portscan", "nuclei",
}
SCHEDULABLE_RUNNERS = {
    "subfinder", "asnmap", "crtsh", "dnstwist", "certspotter", "cloud_enum",
    "paste_monitor", "gist_monitor", "stackoverflow_monitor", "discord_monitor",
    "github_scan", "breach_monitor",
    "commoncrawl", "searchengine",
    "wappalyzer", "screenshot", "portscan", "nuclei",
}


class CertStreamFilters(BaseModel):
    include_common_name: bool = True
    include_san_dns_names: bool = True
    match_mode: str = "suffix"


class RunnerConfig(BaseModel):
    """Generic per-runner configuration. All fields optional, validated at load time."""
    enabled: bool = False
    schedule: str | None = None
    mode: str | None = None
    filters: CertStreamFilters | None = None
    args: dict[str, Any] = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)
    pastebin_api_key: str | None = None
    max_pastes_per_run: int = 100
    github_token: str | None = None
    gitleaks_path: str = "gitleaks"
    search_queries: list[str] = Field(
        default_factory=lambda: ["credential_patterns", "domain_matches"],
    )
    hibp_api_key: str | None = None
    dehashed_api_key: str | None = None
    dehashed_email: str | None = None

    @field_validator("schedule")
    @classmethod
    def must_be_valid_cron(cls, v: str | None) -> str | None:
        if v is None:
            return None
        import re
        field = r"(\*(\/\d+)?|[0-5]?\d)"
        hour = r"(\*(\/\d+)?|1?\d|2[0-3])"
        day = r"(\*(\/\d+)?|[1-3]?\d)"
        month = r"(\*(\/\d+)?|1?\d|1[0-2])"
        dow = r"(\*(\/\d+)?|[0-7])"
        cr = re.compile(rf"^{field}\s+{hour}\s+{day}\s+{month}\s+{dow}$")
        if not cr.match(v):
            raise ValueError(f"Invalid cron expression: {v}")
        return v


class CoverageConfig(BaseModel):
    apex_covers_subdomains: bool = False


class AllowedPivot(BaseModel):
    from_: str = Field(alias="from")
    to: str
    via: str
    cooldown_hours: int = 0
    coverage: CoverageConfig | None = None
    skip_on_source: list[str] = Field(default_factory=list)


class PivotConfig(BaseModel):
    enabled: bool = False
    max_depth: int = 3
    max_concurrent: int = 3
    batch_interval_ms: int = 200
    scope_mode: str = "strict"
    max_queue_depth: int = 10000
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
    "cpe_vuln_enrich", "ip_to_asn",
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
    runners: dict[str, RunnerConfig] = Field(default_factory=dict)
    pivot: PivotConfig = Field(default_factory=PivotConfig)

    @field_validator("id")
    @classmethod
    def id_must_be_api_safe(cls, v: str) -> str:
        if not v or not all(c.isalnum() or c == "-" for c in v):
            raise ValueError(f"Target id '{v}' must be alphanumeric with hyphens only")
        return v

    @model_validator(mode="before")
    @classmethod
    def normalize_runners(cls, data: Any) -> Any:
        """Coerce raw dict runner configs to RunnerConfig instances."""
        if isinstance(data, dict) and "runners" in data:
            runners = data["runners"]
            if isinstance(runners, dict):
                normalized = {}
                for name, cfg in runners.items():
                    if isinstance(cfg, dict):
                        normalized[name] = RunnerConfig.model_validate(cfg)
                    elif isinstance(cfg, RunnerConfig):
                        normalized[name] = cfg
                    else:
                        raise ValueError(
                            f"Unknown runner config type for '{name}': {type(cfg)}"
                        )
                data["runners"] = normalized
        return data


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


class RuntimeConfig(BaseModel):
    mode: Literal["live", "simulate"] = "live"
    fixtures_path: str = "fixtures/simulation"
    allow_external_network: bool = True
    allow_subprocess: bool = True
    allow_active_scanning: bool = False
    refresh_kev_on_startup: bool = True


class Config(BaseModel):
    targets: list[TargetConfig]
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
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
        for target in self.targets:
            for runner_name in target.runners:
                if runner_name not in VALID_RUNNER_NAMES:
                    raise ValueError(
                        f"Unknown runner '{runner_name}' in target '{target.id}'. "
                        f"Valid runners: {', '.join(sorted(VALID_RUNNER_NAMES))}"
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
