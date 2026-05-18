from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def build_asset_change_event(
    change_type: str,
    summary: str,
    before_state: dict[str, Any] | None = None,
    after_state: dict[str, Any] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    source: str | None = None,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    observed = observed_at or datetime.now(UTC)
    return {
        "change_type": change_type,
        "summary": summary,
        "before_state": dict(before_state or {}),
        "after_state": dict(after_state or {}),
        "evidence": list(evidence or []),
        "source": source,
        "observed_at": observed.isoformat(),
    }
