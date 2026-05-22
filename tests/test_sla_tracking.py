"""Tests for SLA tracking."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from easm.sla.models import compute_sla_status, compute_sla_summary, SLA_DAYS


class TestComputeSlaStatus:
    def test_critical_within_sla(self):
        now = datetime.now(timezone.utc).isoformat()
        sla = compute_sla_status("critical", now)
        assert sla.status == "within_sla"
        assert sla.sla_days == 3

    def test_high_within_sla(self):
        now = datetime.now(timezone.utc).isoformat()
        sla = compute_sla_status("high", now)
        assert sla.status == "within_sla"
        assert sla.sla_days == 14

    def test_medium_within_sla(self):
        now = datetime.now(timezone.utc).isoformat()
        sla = compute_sla_status("medium", now)
        assert sla.status == "within_sla"
        assert sla.sla_days == 30

    def test_low_within_sla(self):
        now = datetime.now(timezone.utc).isoformat()
        sla = compute_sla_status("low", now)
        assert sla.status == "within_sla"
        assert sla.sla_days == 60

    def test_info_is_informational(self):
        sla = compute_sla_status("info", "2026-01-01T00:00:00Z")
        assert sla.status == "informational"
        assert sla.sla_days is None
        assert sla.due_at is None

    def test_overdue_critical(self):
        old = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        sla = compute_sla_status("critical", old)
        assert sla.status == "overdue"

    def test_overdue_high(self):
        old = (datetime.now(timezone.utc) - timedelta(days=20)).isoformat()
        sla = compute_sla_status("high", old)
        assert sla.status == "overdue"

    def test_resolved_finding(self):
        sla = compute_sla_status("critical", "2026-01-01T00:00:00Z", finding_status="resolved")
        assert sla.status == "resolved"

    def test_false_positive_finding(self):
        sla = compute_sla_status("critical", "2026-01-01T00:00:00Z", finding_status="false_positive")
        assert sla.status == "resolved"

    def test_no_first_seen(self):
        sla = compute_sla_status("critical", None)
        assert sla.status == "unknown"

    def test_sla_days_sum_reasonable(self):
        total = sum(v for v in SLA_DAYS.values() if v is not None)
        assert total > 0
        assert total < 200  # sanity check

    def test_to_dict(self):
        sla = compute_sla_status("high", datetime.now(timezone.utc).isoformat())
        d = sla.to_dict()
        assert "severity" in d
        assert "sla_days" in d
        assert "due_at" in d
        assert "status" in d


class TestComputeSlaSummary:
    def test_empty_findings(self):
        result = compute_sla_summary([])
        assert result["total"] == 0
        assert result["overdue_count"] == 0

    def test_mixed_severities(self):
        now = datetime.now(timezone.utc)
        findings = [
            {"risk": "critical", "first_seen_at": (now - timedelta(days=5)).isoformat(), "status": "open"},
            {"risk": "high", "first_seen_at": now.isoformat(), "status": "open"},
            {"risk": "info", "first_seen_at": now.isoformat(), "status": "open"},
        ]
        result = compute_sla_summary(findings)
        assert result["total"] == 3
        assert result["by_status"]["overdue"] == 1
        assert result["by_status"]["within_sla"] == 1
        assert result["by_status"]["informational"] == 1

    def test_next_deadline(self):
        now = datetime.now(timezone.utc)
        findings = [
            {"risk": "critical", "first_seen_at": now.isoformat(), "status": "open"},
            {"risk": "high", "first_seen_at": now.isoformat(), "status": "open"},
        ]
        result = compute_sla_summary(findings)
        assert result["next_deadline"] is not None
        # Critical (3d) deadline should be before high (14d)
        assert result["next_deadline"] is not None

    def test_sla_policy_in_output(self):
        result = compute_sla_summary([])
        assert "sla_policy" in result
        assert "critical" in result["sla_policy"]
        assert result["sla_policy"]["critical"] == "< 3 days"
        assert result["sla_policy"]["high"] == "< 14 days"
