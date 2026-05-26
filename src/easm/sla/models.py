"""Patching SLA models and policy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any


# SLA deadlines for internet-facing findings.
# Based on common remediation guidance for externally exposed assets:
#   critical — actively exploited or trivially exploitable (NIST 800-40: < 72h)
#   high     — significant exposure, exploit likely within 2 weeks
#   medium   — actionable weakness, fix within one patch cycle
#   low      — hardening improvement, next maintenance window
SLA_DAYS: dict[str, int | None] = {
    "critical": 3,
    "high": 14,
    "medium": 30,
    "low": 60,
    "info": None,
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class SLAStatus:
    severity: str
    sla_days: int | None
    due_at: str | None
    status: str  # within_sla, overdue, resolved, informational

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "sla_days": self.sla_days,
            "due_at": self.due_at,
            "status": self.status,
        }


def compute_sla_status(
    severity: str,
    first_seen_at: str | None,
    finding_status: str = "open",
) -> SLAStatus:
    """Compute SLA status for a single finding.

    SLA is computed dynamically from first_seen_at + SLA_DAYS[severity].
    """
    days = SLA_DAYS.get(severity)

    if days is None:
        return SLAStatus(
            severity=severity,
            sla_days=None,
            due_at=None,
            status="informational",
        )

    if finding_status in ("resolved", "false_positive"):
        return SLAStatus(
            severity=severity,
            sla_days=days,
            due_at=None,
            status="resolved",
        )

    if not first_seen_at:
        return SLAStatus(
            severity=severity,
            sla_days=days,
            due_at=None,
            status="unknown",
        )

    try:
        seen = datetime.fromisoformat(first_seen_at.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        seen = datetime.now(timezone.utc)

    due = seen + timedelta(days=days)
    now = datetime.now(timezone.utc)

    return SLAStatus(
        severity=severity,
        sla_days=days,
        due_at=due.isoformat(),
        status="overdue" if now > due else "within_sla",
    )


def compute_sla_summary(findings: list[dict]) -> dict[str, Any]:
    """Compute an SLA summary across a list of finding dicts.

    Each finding dict should have: severity, first_seen_at, status.
    """
    counts = {"within_sla": 0, "overdue": 0, "resolved": 0, "informational": 0, "unknown": 0}
    overdue_items: list[dict] = []
    next_deadline: str | None = None

    for f in findings:
        sla = compute_sla_status(
            severity=f.get("risk", f.get("severity", "info")),
            first_seen_at=f.get("first_seen_at"),
            finding_status=f.get("status", "open"),
        )
        counts[sla.status] += 1

        if sla.status == "overdue":
            overdue_items.append({
                "id": f.get("id"),
                "headline": f.get("headline"),
                "severity": sla.severity,
                "due_at": sla.due_at,
                "days_overdue": (
                    (datetime.now(timezone.utc) - datetime.fromisoformat(sla.due_at)).days
                    if sla.due_at else None
                ),
            })

        if sla.status == "within_sla" and sla.due_at:
            if next_deadline is None or sla.due_at < next_deadline:
                next_deadline = sla.due_at

    return {
        "total": len(findings),
        "by_status": counts,
        "overdue_count": counts["overdue"],
        "next_deadline": next_deadline,
        "overdue_items": sorted(
            overdue_items,
            key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 9),
        )[:20],
        "sla_policy": {
            "critical": "< 3 days",
            "high": "< 14 days",
            "medium": "< 30 days",
            "low": "< 60 days",
            "info": "informational",
        },
    }
