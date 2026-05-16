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
    metadata: dict[str, Any] = Field(default_factory=dict)


class RunTriggerResponse(BaseModel):
    run_id: str
    status: str
    message: str


class ErrorResponse(BaseModel):
    error: str
    detail: str
