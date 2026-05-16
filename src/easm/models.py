from __future__ import annotations

import enum


class TriggerType(str, enum.Enum):
    SCHEDULED = "scheduled"
    MANUAL = "manual"
    STREAM = "stream"


class RunStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
