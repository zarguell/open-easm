from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class NotificationPayload:
    finding_id: str
    rule_id: str
    headline: str
    risk: str
    severity: str
    target_id: str
    entity_ids: list[str]
    evidence: dict[str, Any] = field(default_factory=dict)
    dashboard_url: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
