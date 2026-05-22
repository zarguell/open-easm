from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class CollectMethod(str, enum.Enum):
    EXACT = "exact"
    REGEX = "regex"
    NOT_REGEX = "not_regex"


class AnalysisMethod(str, enum.Enum):
    THRESHOLD = "threshold"
    UNIQUE = "unique"


class RiskLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


VALID_RISK_LEVELS = {"critical", "high", "medium", "low", "info"}
VALID_FINDING_STATUSES = {"open", "acknowledged", "resolved", "false_positive"}


class CollectCondition(BaseModel):
    method: CollectMethod
    field: str
    value: str | None = None
    patterns: list[str] | None = None

    @field_validator("value")
    @classmethod
    def value_required_for_exact(cls, v: str | None, info: Any) -> str | None:
        if info.data.get("method") == CollectMethod.EXACT and not v:
            raise ValueError("value is required for exact match")
        return v

    @field_validator("patterns")
    @classmethod
    def patterns_required_for_regex(cls, v: list[str] | None, info: Any) -> list[str] | None:
        if info.data.get("method") == CollectMethod.REGEX and (not v or len(v) == 0):
            raise ValueError("patterns are required for regex match")
        return v

    def model_post_init(self, __context: Any) -> None:
        if self.method == CollectMethod.EXACT and not self.value:
            raise ValueError("value is required for exact match")
        if self.method == CollectMethod.REGEX and (not self.patterns or len(self.patterns) == 0):
            raise ValueError("patterns are required for regex match")


class RuleMeta(BaseModel):
    name: str
    description: str
    risk: RiskLevel = RiskLevel.MEDIUM


class AnalysisStep(BaseModel):
    method: AnalysisMethod
    field: str
    minimum: int | None = None
    maximum: int | None = None


class AggregationConfig(BaseModel):
    field: str


class CorrelationRule(BaseModel):
    id: str
    meta: RuleMeta
    collect: list[CollectCondition]
    aggregation: AggregationConfig
    headline: str
    analysis: list[AnalysisStep] | None = None


class Finding(BaseModel):
    org_id: str
    target_id: str
    rule_id: str
    risk: RiskLevel
    headline: str
    description: str | None = None
    entity_ids: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    confidence_score: float | None = None
    confidence_level: str | None = None
    status: str = "open"

    @field_validator("risk")
    @classmethod
    def risk_must_be_valid(cls, v: str | RiskLevel) -> str | RiskLevel:
        if isinstance(v, str) and v not in VALID_RISK_LEVELS:
            raise ValueError(f"Invalid risk level: {v}")
        return v

    @field_validator("status")
    @classmethod
    def status_must_be_valid(cls, v: str) -> str:
        if v not in VALID_FINDING_STATUSES:
            raise ValueError(f"Invalid status: {v}")
        return v
