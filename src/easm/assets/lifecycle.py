from __future__ import annotations

from datetime import UTC, datetime, timedelta


def compute_lifecycle_state(first_seen_at: datetime | None, now: datetime | None = None) -> str:
    """Classify entity lifecycle state based on first_seen_at.

    Returns: 'new' (< 24h), 'recent' (1-7d), 'stable' (> 7d), 'unknown' (no first_seen_at)
    """
    if first_seen_at is None:
        return "unknown"
    now = now or datetime.now(UTC)
    age = now - first_seen_at
    if age < timedelta(hours=24):
        return "new"
    if age < timedelta(days=7):
        return "recent"
    return "stable"
