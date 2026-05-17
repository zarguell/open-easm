from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    database: str
    scheduler: str
    config_loaded: bool


class TargetSummary(BaseModel):
    id: str
    name: str
    type: str
    enabled: bool
    labels: dict[str, str]
    runners: dict[str, Any]


class TargetDetail(TargetSummary):
    match_rules: dict[str, Any]


class EventSummary(BaseModel):
    id: str
    target_id: str
    source: str
    collected_at: str
    event_hash: str
    run_id: str


class EventDetail(EventSummary):
    raw: dict[str, Any]


class RunSummary(BaseModel):
    id: str
    target_id: str
    source: str
    trigger_type: str
    status: str
    scheduled_for: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    duration_ms: int | None = None
    inserted_count: int
    deduped_count: int
    error_count: int


class RunDetail(RunSummary):
    error_message: str | None = None
    logs: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RunTriggerResponse(BaseModel):
    run_id: str
    status: str
    message: str


class EntitySummary(BaseModel):
    id: str
    org_id: str
    target_id: str
    entity_type: str
    entity_value: str
    attributes: dict[str, Any]
    first_seen_at: str
    last_seen_at: str
    is_first_discovery: bool


class EntityDetail(EntitySummary):
    raw_event_ids: list[str]


class RelationshipSummary(BaseModel):
    id: str
    source_entity_id: str
    target_entity_id: str
    relationship_type: str
    relationship_source: str
    first_seen_at: str
    source_entity_value: str
    source_entity_type: str
    target_entity_value: str
    target_entity_type: str


class GraphResponse(BaseModel):
    target_id: str
    max_depth: int
    nodes: list[EntitySummary]
    edges: list[RelationshipSummary]


class ErrorResponse(BaseModel):
    error: str
    detail: str


class ConfigSnapshot(BaseModel):
    id: str
    target_count: int
    created_at: str


class ConfigUpdateRequest(BaseModel):
    """Partial config update. Only the sections provided are updated."""
    targets: list[dict[str, Any]] | None = None
    saas_providers: dict[str, Any] | None = None
    alerts: dict[str, Any] | None = None


class ConfigResponse(BaseModel):
    targets: list[dict[str, Any]]
    saas_providers: dict[str, Any] | None = None
    alerts: dict[str, Any] | None = None


class AlertRuleSchema(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    condition: str
    severity: str = "medium"


class AlertFeedEntry(BaseModel):
    id: str
    rule_name: str
    severity: str
    title: str
    detail: str
    entity_id: str | None = None
    created_at: str
    acknowledged: bool = False
